import json
import requests
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
        self.start_domain = None
        self.crawl_threads = 5

    def crawl(self, start_url):
        self.start_domain = urlparse(start_url).netloc
        to_visit = [(start_url, 0)]
        with ThreadPoolExecutor(max_workers=self.crawl_threads) as executor:
            futures = {}
            while to_visit and len(self.visited) < self.max_urls:
                batch = []
                while to_visit and len(batch) < self.crawl_threads * 2:
                    url, depth = to_visit.pop(0)
                    if url not in self.visited and depth <= self.depth:
                        batch.append((url, depth))
                        self.visited.add(url)
                if not batch:
                    break
                for url, depth in batch:
                    future = executor.submit(self._process_url, url, depth)
                    futures[future] = (url, depth)
                for future in as_completed(futures):
                    url, depth = futures[future]
                    try:
                        new_links = future.result()
                        if new_links:
                            for link in new_links:
                                if link not in self.visited and len(self.visited) < self.max_urls:
                                    to_visit.append((link, depth + 1))
                    except Exception as e:
                        self.logger.error(f"爬取 {url} 失败: {e}")
        return self.found_targets

    def _process_url(self, url, depth):
        try:
            self.rate_limiter.acquire()
            if self.js_render:
                html = self._render_js(url)
            else:
                resp = self.client.get(url)
                if resp.status_code != 200:
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
                full_url_with_params = full_action + "?" + urlencode(params)
                if self._is_valid_url(full_url_with_params):
                    new_links.add(normalize_url(full_url_with_params))
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
        params_str = json.dumps(params, sort_keys=True) if params else ""
        key = (method, url, params_str)
        if key not in self._seen_target_keys:
            self._seen_target_keys.add(key)
            self.found_targets.append({"url": url, "method": method, "params": params})

    def _render_js(self, url):
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=15000)
                page.wait_for_load_state("networkidle")
                html = page.content()
                browser.close()
                return html
        except ImportError:
            self.logger.warning("未安装playwright，回退到普通请求")
            resp = self.client.get(url)
            return resp.text
        except Exception as e:
            self.logger.error(f"JS渲染失败 {url}: {e}")
            return ""

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