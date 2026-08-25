import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import logging
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

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
            # 用户可能传入两种格式：
            #   1) 多次 --cookie "k1=v1" --cookie "k2=v2"    （append 成 list，每项一个 cookie）
            #   2) 一次 --cookie "k1=v1; k2=v2; k3=v3"     （append 成 list，单项含分号）
            # 需要同时支持：先按分号再按等号切分。
            # 对 localhost / IP 场景，不设置 domain（保持 Host-only cookie），
            # 避免显式 domain 导致 CookieJar 匹配失败（ExperienceRecall 609349）。
            for raw in cookies:
                for part in raw.split(";"):
                    part = part.strip()
                    if not part or "=" not in part:
                        continue
                    key, value = part.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    if not key:
                        continue
                    self.session.cookies.set(key, value)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = verify_ssl
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500,502,503,504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    # 常见 CSRF token 字段名（覆盖 DVWA/OWASP/主流框架）
    CSRF_FIELD_NAMES = (
        "user_token", "csrf_token", "csrf", "_token", "authenticity_token",
        "__requestverificationtoken", "csrfmiddlewaretoken", "anticsrf",
        "csrf_token_", "token",
    )

    def _extract_csrf_token(self, html):
        """从登录页 HTML 中提取 CSRF token

        优先策略：
        1. <input type="hidden" name="{field}" value="{token}">  （DVWA/WordPress/Laravel）
        2. <meta name="csrf-token" content="{token}">            （Laravel Blade）
        3. <meta name="{field}" content="{token}">              （部分框架）

        返回 {field_name: token_value} 字典
        """
        tokens = {}
        if not html:
            return tokens

        # 优先用 BeautifulSoup 精确解析 hidden input
        if BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(html, "lxml")
                # hidden input
                for inp in soup.find_all("input", {"type": "hidden"}):
                    name = inp.get("name", "")
                    value = inp.get("value", "")
                    if name and value and name in self.CSRF_FIELD_NAMES:
                        tokens[name] = value
                # meta 标签（Laravel: <meta name="csrf-token">）
                for meta in soup.find_all("meta"):
                    name = meta.get("name", "").lower()
                    content = meta.get("content", "")
                    if content and name in self.CSRF_FIELD_NAMES:
                        tokens[name] = content
                if tokens:
                    return tokens
            except Exception:
                pass  # 解析失败回退到正则

        # 正则回退：name="xxx" value="yyy" 或 value="yyy" name="xxx"
        for field in self.CSRF_FIELD_NAMES:
            patterns = [
                rf'name=["\']?{re.escape(field)}["\']?\s+value=["\']?([^"\'>\s]+)',
                rf'value=["\']?([^"\'>\s]+)["\']?\s+name=["\']?{re.escape(field)}["\']?',
            ]
            for pat in patterns:
                m = re.search(pat, html, re.IGNORECASE)
                if m:
                    tokens[field] = m.group(1)
                    break
        return tokens

    def login(self, login_url, username, password, username_field="username", password_field="password"):
        try:
            # 1. GET 登录页：建立 cookie + 提取 CSRF token
            get_resp = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
            csrf_tokens = self._extract_csrf_token(get_resp.text)
            if csrf_tokens:
                logging.info(f"提取到 CSRF token 字段: {list(csrf_tokens.keys())}")

            # 2. 构造 POST 数据：用户名密码 + 所有发现的 CSRF token
            data = {username_field: username, password_field: password}
            data.update(csrf_tokens)
            # 部分登录表单需要提交按钮 name=value 才识别
            data.setdefault("Login", "Login")

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
                "csrf token is incorrect", "csrf token is missing",  # DVWA 显式 CSRF 失败
            ]
            if any(ind in text_lower for ind in failure_indicators):
                return False
            # 检查是否设置了登录态 Cookie（如 PHPSESSID 之外的 session/uid/token 等）
            cookies_keys = {c.name.lower() for c in self.session.cookies}
            auth_cookie_hints = ("session", "uid", "user", "token", "auth", "login", "userid")
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