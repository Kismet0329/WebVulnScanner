import logging
import re
import threading

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# DVWA 等 PHP 应用的 Cookie 名大小写敏感；统一规范已知名称
COOKIE_NAME_ALIASES = {
    "security": "security",  # DVWA 安全等级，必须小写
    "phpsessid": "PHPSESSID",
}


class HttpClient:
    def __init__(self, proxy=None, timeout=10, verify_ssl=False, user_agent=None,
                 headers=None, cookies=None):
        self.session = requests.Session()
        self.timeout = timeout
        # requests.Session / CookieJar 非线程安全；多线程扫描必须串行化会话访问
        self._lock = threading.RLock()
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
            self._apply_cookies(cookies)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = verify_ssl
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _normalize_cookie_name(self, name):
        alias = COOKIE_NAME_ALIASES.get(name.lower())
        return alias if alias else name

    def _apply_cookies(self, cookies):
        """解析 --cookie 参数。

        支持：
          1) 多次 --cookie "k1=v1" --cookie "k2=v2"
          2) 一次 --cookie "k1=v1; k2=v2; k3=v3"
        对 localhost / IP 不设置 domain（Host-only），避免 CookieJar 匹配失败。
        """
        for raw in cookies:
            for part in raw.split(";"):
                part = part.strip()
                if not part or "=" not in part:
                    continue
                key, value = part.split("=", 1)
                key = self._normalize_cookie_name(key.strip())
                value = value.strip()
                if not key:
                    continue
                self.session.cookies.set(key, value)

    def ensure_dvwa_security(self, level="low"):
        """确保 DVWA security Cookie 为指定等级（默认 low）。

        真实 DVWA 读取 $_COOKIE['security']（全小写）。若用户写成 Security=low，
        会话仍有效但漏洞页面全部走高/impossible 过滤 → 参数插件全部漏报，
        最终往往只剩下 robots.txt 等站点级发现。
        """
        with self._lock:
            others = [
                (c.name, c.value)
                for c in list(self.session.cookies)
                if c.name.lower() != "security"
            ]
            had_wrong_case = any(
                c.name.lower() == "security" and c.name != "security"
                for c in list(self.session.cookies)
            )
            current = next(
                (c.value for c in self.session.cookies if c.name == "security"),
                None,
            )
            if current == level and not had_wrong_case:
                return
            # 重建 cookie，去掉错误大小写的 Security
            self.session.cookies.clear()
            for name, value in others:
                self.session.cookies.set(name, value)
            self.session.cookies.set("security", level)
            logging.info(f"已设置 DVWA security={level}（检测低强度漏洞所需）")

    # 常见 CSRF token 字段名（覆盖 DVWA/OWASP/主流框架）
    CSRF_FIELD_NAMES = (
        "user_token", "csrf_token", "csrf", "_token", "authenticity_token",
        "__requestverificationtoken", "csrfmiddlewaretoken", "anticsrf",
        "csrf_token_", "token",
    )

    def _extract_csrf_token(self, html):
        """从登录页 HTML 中提取 CSRF token。"""
        tokens = {}
        if not html:
            return tokens

        if BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(html, "lxml")
                for inp in soup.find_all("input", {"type": "hidden"}):
                    name = inp.get("name", "")
                    value = inp.get("value", "")
                    if name and value and name.lower() in {n.lower() for n in self.CSRF_FIELD_NAMES}:
                        tokens[name] = value
                for meta in soup.find_all("meta"):
                    name = meta.get("name", "").lower()
                    content = meta.get("content", "")
                    if content and name in {n.lower() for n in self.CSRF_FIELD_NAMES}:
                        tokens[name] = content
                if tokens:
                    return tokens
            except Exception:
                pass

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
            with self._lock:
                get_resp = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
                csrf_tokens = self._extract_csrf_token(get_resp.text)
                if csrf_tokens:
                    logging.info(f"提取到 CSRF token 字段: {list(csrf_tokens.keys())}")

                data = {username_field: username, password_field: password}
                data.update(csrf_tokens)
                data.setdefault("Login", "Login")

                resp = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)

                if resp.status_code != 200:
                    return False
                text_lower = resp.text.lower()
                failure_indicators = [
                    "login failed", "username and/or password incorrect",
                    "incorrect username or password", "登录失败", "用户名或密码错误",
                    "invalid credentials", "wrong password",
                    "csrf token is incorrect", "csrf token is missing",
                ]
                if any(ind in text_lower for ind in failure_indicators):
                    return False
                cookies_keys = {c.name.lower() for c in self.session.cookies}
                auth_cookie_hints = ("session", "uid", "user", "token", "auth", "login", "userid")
                if any(hint in key for key in cookies_keys for hint in auth_cookie_hints):
                    self.ensure_dvwa_security("low")
                    return True
                success_indicators = ["logout", "welcome", "my account", "logout.php", "退出登录", "欢迎"]
                ok = any(ind in text_lower for ind in success_indicators)
                if ok:
                    self.ensure_dvwa_security("low")
                return ok
        except Exception as e:
            logging.error(f"登录失败: {e}")
            return False

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.session.verify)
        with self._lock:
            return self.session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        with self._lock:
            self.session.close()
