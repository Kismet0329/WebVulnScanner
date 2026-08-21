# plugins/command_injection.py
import random
import string
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class CommandInjectionPlugin(ScannerPlugin):
    name = "command_injection"
    description = "检测命令注入漏洞"
    severity = "critical"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.marker = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    def check_get(self, url):
        testable = self.get_testable_params(url, method="GET")
        if not testable:
            return False, {}
        for param, original_value in testable.items():
            result = self._test_injection(url, param, original_value, method="GET")
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
            result = self._test_injection(url, param, original_value, method="POST", params=params)
            if result:
                return True, result
        return False, {}

    def _test_injection(self, url, param, original_value, method="GET", params=None):
        separators = [';', '&&', '|', '||', '\n', '`']
        for sep in separators:
            payload = f"{original_value}{sep}echo {self.marker}"
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
                            "command_injection",
                            f"参数 {param} 存在命令注入，分隔符: {sep}",
                            {"param": param, "payload": payload, "separator": sep}
                        )
            else:
                test_params = params.copy()
                test_params[param] = payload
                resp1 = self.safe_request("POST", url, data=test_params)
                if resp1 and self.marker in resp1.text:
                    resp2 = self.safe_request("POST", url, data=test_params)
                    if resp2 and self.marker in resp2.text:
                        return self._build_result(
                            "command_injection",
                            f"参数 {param} 存在命令注入，分隔符: {sep}",
                            {"param": param, "payload": payload, "separator": sep}
                        )
        return None