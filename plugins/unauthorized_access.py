# plugins/unauthorized_access.py
from .base import ScannerPlugin
from urllib.parse import urljoin

class UnauthorizedAccessPlugin(ScannerPlugin):
    name = "unauthorized_access"
    description = "检测常见未授权访问路径"
    severity = "high"

    SENSITIVE_PATHS = {
        "/admin": ["admin", "login", "dashboard", "后台"],
        "/actuator": ["status", "health", "info"],
        "/swagger-ui.html": ["swagger", "api"],
        "/druid": ["Druid Stat Index", "dataSourceList"],
        "/console": ["console", "login"],
        "/manager/html": ["Tomcat Web Application Manager"],
        "/phpmyadmin": ["phpMyAdmin"],
        "/.git/config": ["[core]"],
    }

    def check_get(self, url):
        base = url.rstrip('/')
        for path, keywords in self.SENSITIVE_PATHS.items():
            test_url = urljoin(base + '/', path)
            resp1 = self.safe_request("GET", test_url)
            if resp1 and resp1.status_code == 200:
                if self._has_keywords(resp1.text, keywords):
                    resp2 = self.safe_request("GET", test_url)
                    if resp2 and self._has_keywords(resp2.text, keywords):
                        return self._build_result(
                            "unauthorized_access",
                            f"发现未授权访问路径: {path}",
                            {"url": test_url, "keywords": keywords}
                        )
        return False, {}

    def check_post(self, url, params):
        return False, {}

    def _has_keywords(self, text, keywords):
        return any(k.lower() in text.lower() for k in keywords)