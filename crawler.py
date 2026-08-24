import json
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from utils import normalize_url
from rate_limiter import TokenBucket


class Crawler:
    def __init__(self, http_client, rate_limiter, depth=2, max_urls=500, allow_external=False, js_render=False, logger=None):
        self.client = http_client
        self.rate_limiter = rate_limiter
        self.depth = depth
        self.max_urls = max_urls
        self.allow_external = allow_external
        self.js_render = js_render
        self.logger = logger or logging.getLogger(__name__)
        self.visited = set()
        self.found_targets = []
        self._seen_target_keys = set()
        # 锁：保护 visited、found_targets、_seen_target_keys
        # 多线程爬取时这些共享数据结构必须串行访问，否则会丢失 target
        self._lock = threading.Lock()
        self.start_domain = None
        self.crawl_threads = 5
        # 复用 Playwright 浏览器实例，避免每个 URL 重启浏览器
        self._playwright = None
        self._browser = None

    def crawl(self, start_url):
        self.start_domain = urlparse(start_url).netloc
        to_visit = [(start_url, 0)]

        # 解析 robots.txt：把 Disallow/Allow 路径作为额外种子，扩大覆盖
        # 实际挖 src 时 robots.txt 经常暴露 admin/api 等隐藏路径
        robots_paths = self._fetch_robots_paths(start_url)
        for path in robots_paths:
            full = urljoin(start_url, path)
            if self._is_valid_url(full):
                to_visit.append((full, 0))

        with ThreadPoolExecutor(max_workers=self.crawl_threads) as executor:
            while to_visit and len(self.visited) < self.max_urls:
                batch = []
                while to_visit and len(batch) < self.crawl_threads * 2:
                    url, depth = to_visit.pop(0)
                    # 加锁检查 visited，避免重复提交
                    with self._lock:
                        if url in self.visited or depth > self.depth:
                            continue
                        self.visited.add(url)
                    batch.append((url, depth))
                if not batch:
                    break

                # 每批次提交后，仅收集本批次的 future，避免 futures 字典无限增长
                batch_futures = {}
                for url, depth in batch:
                    future = executor.submit(self._process_url, url, depth)
                    batch_futures[future] = (url, depth)

                for future in as_completed(batch_futures):
                    url, depth = batch_futures[future]
                    try:
                        new_links = future.result()
                        if new_links:
                            for link in new_links:
                                # 加锁检查 visited
                                with self._lock:
                                    if link in self.visited or len(self.visited) >= self.max_urls:
                                        continue
                                to_visit.append((link, depth + 1))
                    except Exception as e:
                        self.logger.error(f"爬取 {url} 失败: {e}")
        self._close_browser()
        return self.found_targets

    def _fetch_robots_paths(self, start_url):
        """解析 robots.txt，返回 Disallow/Allow 路径列表（用于扩大爬取覆盖）

        即使 User-agent 不匹配我们也收集，目的是发现隐藏路径。
        """
        paths = []
        try:
            robots_url = urljoin(start_url, "/robots.txt")
            self.rate_limiter.acquire()
            resp = self.client.get(robots_url)
            if resp.status_code != 200:
                return paths
            for line in resp.text.splitlines():
                line = line.strip()
                # 跳过注释和 User-agent 行
                if not line or line.startswith("#") or line.lower().startswith("user-agent:"):
                    continue
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    parts = line.split(":", 1)
                    if len(parts) != 2:
                        continue
                    val = parts[1].strip()
                    if not val or val == "/":
                        continue
                    # Sitemap 指向完整 URL，直接加入
                    if line.lower().startswith("sitemap:") and val.startswith("http"):
                        paths.append(val)
                    else:
                        paths.append(val)
            if paths:
                self.logger.info(f"从 robots.txt 解析到 {len(paths)} 个路径")
        except Exception as e:
            self.logger.debug(f"获取 robots.txt 失败: {e}")
        return paths

    def _process_url(self, url, depth):
        try:
            self.rate_limiter.acquire()
            if self.js_render:
                html = self._render_js(url)
            else:
                resp = self.client.get(url)
                # 200 才是有效爬取；3xx 已被 requests 自动跟随，到这里仍是 3xx 说明重定向到 login
                # 401/403/5xx 同样跳过，但记录到日志便于排查
                if resp.status_code != 200:
                    if resp.status_code in (401, 403):
                        self.logger.debug(f"访问 {url} 返回 {resp.status_code}，可能需要登录")
                    return []
                html = resp.text
        except Exception as e:
            self.logger.error(f"请求 {url} 失败: {e}")
            return []
        self._add_target(url, "GET", None)
        soup = BeautifulSoup(html, "lxml")
        new_links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(url, href)
            if self._is_valid_url(full_url):
                new_links.add(normalize_url(full_url))
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            if method not in ("get", "post"):
                method = "get"
            full_action = urljoin(url, action) if action else url
            inputs = form.find_all(["input", "textarea", "select"])
            params = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    params[name] = inp.get("value", "")
            if method == "get":
                # GET 表单：把带参数的 URL 作为 target 提交，让参数级插件能测到这些参数
                # 注意：原来只放入 new_links，参数会被 _add_target 丢弃；这里显式提交
                if params:
                    full_url_with_params = full_action + "?" + urlencode(params)
                    if self._is_valid_url(full_url_with_params):
                        # 作为 GET target 提交（含参数）
                        self._add_target(full_url_with_params, "GET", None)
                        new_links.add(normalize_url(full_url_with_params))
                else:
                    if self._is_valid_url(full_action):
                        new_links.add(normalize_url(full_action))
            else:
                self._add_target(full_action, "POST", params)
                if self._is_valid_url(full_action):
                    new_links.add(normalize_url(full_action))
        for iframe in soup.find_all("iframe", src=True):
            full_url = urljoin(url, iframe["src"])
            if self._is_valid_url(full_url):
                new_links.add(normalize_url(full_url))
        return list(new_links)

    def _add_target(self, url, method, params):
        # 加锁：多线程下 _seen_target_keys 检查+添加必须是原子的
        # 否则两个线程可能同时通过检查，导致 target 重复或丢失
        params_str = json.dumps(params, sort_keys=True) if params else ""
        key = (method, url, params_str)
        with self._lock:
            if key not in self._seen_target_keys:
                self._seen_target_keys.add(key)
                self.found_targets.append({"url": url, "method": method, "params": params})

    def _render_js(self, url):
        """使用复用的浏览器实例渲染页面，避免每个 URL 重启浏览器"""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.logger.warning("未安装playwright，回退到普通请求")
            resp = self.client.get(url)
            return resp.text

        try:
            if self._playwright is None:
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(headless=True)
            page = self._browser.new_page()
            try:
                page.goto(url, timeout=15000)
                page.wait_for_load_state("networkidle")
                return page.content()
            finally:
                page.close()
        except Exception as e:
            self.logger.error(f"JS渲染失败 {url}: {e}")
            return ""

    def _close_browser(self):
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

    def _is_valid_url(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not self.allow_external and parsed.netloc != self.start_domain:
            return False
        static_extensions = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3')
        if parsed.path.lower().endswith(static_extensions):
            return False
        return True
