# http_client.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HttpClient:
    def __init__(self, proxy=None, timeout=10, verify_ssl=False, user_agent=None, headers=None, cookies=None):
        self.session = requests.Session()
        self.timeout = timeout
        # 设置请求头
        self.session.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        if headers:
            for h in headers:
                if ":" in h:
                    key, value = h.split(":", 1)
                    self.session.headers[key.strip()] = value.strip()
        if cookies:
            for c in cookies:
                if "=" in c:
                    key, value = c.split("=", 1)
                    self.session.cookies.set(key.strip(), value.strip())
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = verify_ssl
        # 重试机制
        retry = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def login(self, login_url, username, password, username_field="username", password_field="password"):
        """简单表单登录，保留会话"""
        try:
            resp = self.session.get(login_url, timeout=self.timeout)
            # 可以解析CSRF token等，这里简化
            data = {
                username_field: username,
                password_field: password,
            }
            resp = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)
            logging.info(f"登录状态码: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            logging.error(f"登录失败: {e}")
            return False

    def request(self, method, url, **kwargs):
        """发送请求，统一超时和异常处理"""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.session.verify)
        return self.session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        self.session.close()