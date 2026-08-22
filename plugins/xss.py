from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

class XSSPlugin(ScannerPlugin):
    name = "xss"
    description = "反射型XSS检测"
    severity = "medium"

    payloads = [
        '<script>alert("XSS_MARKER")</script>',
        '"><script>alert("XSS_MARKER")</script>',
        '"><img src=x onerror=alert("XSS_MARKER")>',
        "';alert('XSS_MARKER')//",
        '" onmouseover="alert(\'XSS_MARKER\')"',
        "{{XSS_MARKER}}",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.marker = "XSS_" + str(id(self)) + "_MARKER"

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
        for payload in self.payloads:
            payload_with_marker = payload.replace("XSS_MARKER", self.marker)
            if method == "GET":
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                query[param] = [payload_with_marker]
                test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                resp = self.safe_request("GET", test_url)
            else:
                test_params = params.copy()
                test_params[param] = payload_with_marker
                resp = self.safe_request("POST", url, data=test_params)
            if resp and self.marker in resp.text:
                if self._is_executable_context(resp.text, self.marker):
                    return self._build_result(
                        "reflected_xss",
                        f"参数 {param} 存在反射型XSS",
                        {"param": param, "payload": payload_with_marker, "url": url}
                    )
        return None

    def _is_executable_context(self, html, marker):
        patterns = [
            r'<script[^>]*>.*?' + re.escape(marker) + r'.*?</script>',
            r'on\w+\s*=\s*["\'][^"\']*' + re.escape(marker),
            r'<[^>]+[^>]*' + re.escape(marker),
        ]
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE | re.DOTALL):
                return True
        return False