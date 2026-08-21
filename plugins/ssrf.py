# plugins/ssrf.py
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import random, string

class SSRFPlugin(ScannerPlugin):
    name = "ssrf"
    description = "检测服务端请求伪造（SSRF）漏洞（基于回显）"
    severity = "high"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.marker = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        # 可替换为 DNSLog 地址
        self.test_url = f"http://127.0.0.1:1/{self.marker}"

    def check_get(self, url):
        testable = self.get_testable_params(url, method="GET")
        if not testable:
            return False, {}
        for param, original_value in testable.items():
            result = self._test_param(url, param, original_value, method="GET")
            if result:
                return True, result
        return False, {}

    def check_post(self, url, params):
        if not params:
            return False, {}
        testable = self.get_testable_params(url, method="POST", params=params)
        if not testable:
            return False, {}
        for param, original_value in testable.items():
            result = self._test_param(url, param, original_value, method="POST", params=params)
            if result:
                return True, result
        return False, {}

    def _test_param(self, url, param, original_value, method="GET", params=None):
        payload = self.test_url
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            resp1 = self.safe_request("GET", test_url)
            if resp1 and self.marker in resp1.text:
                resp2 = self.safe_request("GET", test_url)
                if resp2 and self.marker in resp2.text:
                    return self._build_result(
                        "ssrf",
                        f"参数 {param} 存在 SSRF，可访问 {self.test_url}",
                        {"param": param, "payload": payload}
                    )
        else:
            test_params = params.copy()
            test_params[param] = payload
            resp1 = self.safe_request("POST", url, data=test_params)
            if resp1 and self.marker in resp1.text:
                resp2 = self.safe_request("POST", url, data=test_params)
                if resp2 and self.marker in resp2.text:
                    return self._build_result(
                        "ssrf",
                        f"参数 {param} 存在 SSRF，可访问 {self.test_url}",
                        {"param": param, "payload": payload}
                    )
        return None