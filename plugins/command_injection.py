import random
import string
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class CommandInjectionPlugin(ScannerPlugin):
    name = "command_injection"
    description = "检测命令注入漏洞"
    severity = "critical"

    # 收敛后的分隔符：覆盖三大类语义
    #   ;   - 顺序执行（Unix）
    #   |   - 管道（Unix/Windows）
    #   &&  - 短路与执行（Unix/Windows）
    #   &   - 后台执行（Unix/Windows）
    #   $() - 命令替换（Unix）
    separators = [';', '|', '&&', '&']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # uuid4 hex 保证 marker 在响应中唯一可识别，避免与页面已有内容冲突
        self.marker = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

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
        for sep in self.separators:
            # 普通分隔符 + echo
            payload = f"{original_value}{sep}echo {self.marker}"
            result = self._try_payload(url, param, payload, sep, method, params)
            if result:
                return result
        # 命令替换：$(echo marker)
        payload = f"{original_value}$(echo {self.marker})"
        result = self._try_payload(url, param, payload, "$()", method, params)
        if result:
            return result
        return None

    def _try_payload(self, url, param, payload, sep_label, method="GET", params=None):
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
                        f"参数 {param} 存在命令注入，分隔符: {sep_label}",
                        {
                            "param": param,
                            "payload": payload,
                            "separator": sep_label,
                            "evidence_url": test_url,
                        },
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
                        f"参数 {param} 存在命令注入，分隔符: {sep_label}",
                        {
                            "param": param,
                            "payload": payload,
                            "separator": sep_label,
                        },
                    )
        return None
