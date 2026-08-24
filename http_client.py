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
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500,502,503,504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def login(self, login_url, username, password, username_field="username", password_field="password"):
        try:
            self.session.get(login_url, timeout=self.timeout)
            data = {username_field: username, password_field: password}
            resp = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)
            # 仅凭 200 不能判定登录成功：DVWA 等应用登录失败也返回 200
            # 通过响应内容里的失败标志 + cookie 变化综合判断
            if resp.status_code != 200:
                return False
            text_lower = resp.text.lower()
            failure_indicators = [
                "login failed", "username and/or password incorrect",
                "incorrect username or password", "登录失败", "用户名或密码错误",
                "invalid credentials", "wrong password",
            ]
            if any(ind in text_lower for ind in failure_indicators):
                return False
            # 检查是否设置了登录态 Cookie（如 PHPSESSID 之外的 session/uid/token 等）
            cookies_keys = {c.name.lower() for c in self.session.cookies}
            auth_cookie_hints = ("session", "uid", "user", "token", "auth", "login", "uid", "userid")
            if any(hint in key for key in cookies_keys for hint in auth_cookie_hints):
                return True
            # 未发现明确登录态 Cookie，回退到内容判断：响应中含登出/账户信息视为成功
            success_indicators = ["logout", "welcome", "my account", "logout.php", "退出登录", "欢迎"]
            return any(ind in text_lower for ind in success_indicators)
        except Exception as e:
            logging.error(f"登录失败: {e}")
            return False

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.session.verify)
        return self.session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        self.session.close()