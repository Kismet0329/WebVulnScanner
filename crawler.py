import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from utils import normalize_url, target_dedup_key, target_param_richness
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
                    url = normalize_url(url)
                    # 跳过注销类 URL，避免销毁会话
                    if self._is_logout_url(url):
                        self.logger.info(f"跳过注销类 URL: {url}")
                        continue
                    if self._is_skip_path(url):
                        self.logger.info(f"跳过易挂起/低价值路径: {url}")
                        continue
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

    # 注销/退出类 URL 模式：爬虫绝对不能访问，否则会销毁当前会话
    # 导致后续所有受保护页面返回 302 到登录页 → param 级插件全部漏报
    # 真实挖 src 时同理：误访问 /logout /signout /exit 会断开会话
    LOGOUT_PATTERNS = (
        "/logout", "/signout", "/sign-out", "/sign_off", "/signoff",
        "/exit", "/deauth", "/logoff", "/log-off", "/quit",
        "/account/logout", "/user/logout", "/auth/logout",
        "/session/destroy", "/session/end",
    )

    # 已知易挂起/无注入价值的路径（DVWA captcha 会请求外部 reCAPTCHA 导致 read timeout）
    SKIP_PATH_PATTERNS = (
        "/vulnerabilities/captcha",
        "/captcha",
        "/recaptcha",
    )

    def _is_logout_url(self, url):
        path = urlparse(url).path.lower()
        return any(pat in path for pat in self.LOGOUT_PATTERNS)

    def _is_skip_path(self, url):
        path = urlparse(url).path.lower().rstrip("/")
        return any(
            path == pat.rstrip("/") or path.startswith(pat.rstrip("/") + "/")
            for pat in self.SKIP_PATH_PATTERNS
        )

    LOGIN_PATH_KEYWORDS = ("login", "signin", "sign-in", "sign_in", "auth/login")
    LOGIN_BODY_MARKERS = (
        'name="username"', 'name="password"', "user_token",
        "please enter your credentials", "用户登录", "login.php",
    )

    def _is_login_url(self, url):
        path = urlparse(url).path.lower()
        return any(k in path for k in self.LOGIN_PATH_KEYWORDS)

    def _response_is_login_page(self, resp, requested_url):
        """判断响应是否为登录页（会话失效时的典型表现）。

        根因：未登录访问受保护页会被 302 到 login.php；requests 默认跟随重定向后
        返回 200 + 登录表单 HTML。若把该 HTML 当业务页解析，会把登录表单当成
        漏洞目标，参数插件全部空转，最终只剩 robots.txt 等站点级发现。
        """
        if resp is None:
            return True
        final_url = getattr(resp, "url", "") or ""
        requested_is_login = self._is_login_url(requested_url)
        final_is_login = self._is_login_url(final_url)
        # 请求业务页却落到登录页
        if final_is_login and not requested_is_login:
            return True
        if requested_is_login:
            return False
        body = (resp.text or "")[:3000].lower()
        has_password_field = 'name="password"' in body or "name='password'" in body
        has_user_field = 'name="username"' in body or "name='username'" in body or "user_token" in body
        return has_password_field and has_user_field

    def _process_url(self, url, depth):
        url = normalize_url(url)
        if self._is_logout_url(url):
            self.logger.info(f"跳过注销类 URL: {url}")
            return []
        if self._is_skip_path(url):
            self.logger.info(f"跳过易挂起/低价值路径: {url}")
            return []
        try:
            self.rate_limiter.acquire()
            if self.js_render:
                html = self._render_js(url)
                class _Fake:
                    pass
                fake = _Fake()
                fake.url = url
                fake.text = html or ""
                fake.status_code = 200 if html else 0
                if not html or self._response_is_login_page(fake, url):
                    if html and self._response_is_login_page(fake, url):
                        self.logger.warning(
                            f"爬取 {url} 得到登录页内容，会话可能失效，跳过表单提取"
                        )
                    return []
            else:
                resp = self.client.get(url)
                if resp.status_code != 200:
                    if resp.status_code in (401, 403):
                        self.logger.debug(f"访问 {url} 返回 {resp.status_code}，可能需要登录")
                    return []
                if self._response_is_login_page(resp, url):
                    self.logger.warning(
                        f"爬取 {url} 被导向登录页（最终 URL: {resp.url}），"
                        "会话失效或未登录，跳过以免把登录表单当成扫描目标"
                    )
                    return []
                html = resp.text
        except Exception as e:
            self.logger.error(f"请求 {url} 失败: {e}")
            return []
        self._add_target(url, "GET", None)
        soup = BeautifulSoup(html, "lxml")
        new_links = set()
        for a in soup.find_all("a", href=True):
            href = (a.get("href") or "").strip()
            if not href or href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            full_url = normalize_url(urljoin(url, href))
            if (
                self._is_valid_url(full_url)
                and not self._is_logout_url(full_url)
                and not self._is_skip_path(full_url)
            ):
                new_links.add(full_url)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            if method not in ("get", "post"):
                method = "get"
            full_action = normalize_url(urljoin(url, action) if action else url)
            if (
                self._is_login_url(full_action)
                or self._is_logout_url(full_action)
                or self._is_skip_path(full_action)
            ):
                if (
                    self._is_valid_url(full_action)
                    and not self._is_logout_url(full_action)
                    and not self._is_skip_path(full_action)
                ):
                    new_links.add(full_action)
                continue
            inputs = form.find_all(["input", "textarea", "select"])
            params = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    params[name] = inp.get("value", "")
            if method == "get":
                if params:
                    full_url_with_params = normalize_url(full_action + "?" + urlencode(params))
                    if self._is_valid_url(full_url_with_params):
                        self._add_target(full_url_with_params, "GET", None)
                        new_links.add(full_url_with_params)
                else:
                    if self._is_valid_url(full_action):
                        new_links.add(full_action)
            else:
                self._add_target(full_action, "POST", params)
                if self._is_valid_url(full_action):
                    new_links.add(full_action)
        for iframe in soup.find_all("iframe", src=True):
            src = (iframe.get("src") or "").strip()
            if not src or src.startswith("#"):
                continue
            full_url = normalize_url(urljoin(url, src))
            if (
                self._is_valid_url(full_url)
                and not self._is_logout_url(full_url)
                and not self._is_skip_path(full_url)
            ):
                new_links.add(full_url)
        return list(new_links)

    def _add_target(self, url, method, params):
        url = normalize_url(url)
        if self._is_skip_path(url) or self._is_logout_url(url):
            return
        key = target_dedup_key(method, url, params)
        new_score = target_param_richness(method, url, params)
        with self._lock:
            if key not in self._seen_target_keys:
                self._seen_target_keys.add(key)
                self.found_targets.append({"url": url, "method": method, "params": params})
                return
            # 已有同路径目标：若新目标参数更丰富，则升级替换（保留可测 query/POST 字段）
            for i, existing in enumerate(self.found_targets):
                if target_dedup_key(existing["method"], existing["url"], existing.get("params")) != key:
                    continue
                old_score = target_param_richness(
                    existing["method"], existing["url"], existing.get("params")
                )
                if new_score > old_score:
                    self.found_targets[i] = {"url": url, "method": method, "params": params}
                break

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
