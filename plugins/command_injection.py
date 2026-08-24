import random
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

    def _gen_math_payload(self, original_value, sep):
        """生成数学运算 payload：执行后输出与反射输入不同。

        例如： 127.0.0.1;echo ABC$((123+456))XYZ
        - 反射：响应包含 ABC$((123+456))XYZ （字面量）
        - 执行：响应包含 ABC579XYZ （计算结果）
        检测 ABC579XYZ 是否出现，而非检测 marker。

        对 $() 命令替换分隔符，用 $(echo ...) 包裹。
        """
        a = random.randint(100, 999)
        b = random.randint(100, 999)
        expected = f"ABC{a + b}XYZ"
        if sep == "$()":
            payload = f"{original_value}$(echo ABC$(({a}+{b}))XYZ)"
        else:
            payload = f"{original_value}{sep}echo ABC$(({a}+{b}))XYZ"
        return payload, expected

    def _test_injection(self, url, param, original_value, method="GET", params=None):
        for sep in self.separators:
            payload, expected = self._gen_math_payload(original_value, sep)
            result = self._try_payload(url, param, payload, sep, expected, method, params)
            if result:
                return result
        # 命令替换：$(echo ...)
        payload, expected = self._gen_math_payload(original_value, "$()")
        result = self._try_payload(url, param, payload, "$()", expected, method, params)
        if result:
            return result
        return None

    def _try_payload(self, url, param, payload, sep_label, expected, method="GET", params=None):
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            resp1 = self.safe_request("GET", test_url)
            if resp1 and expected in resp1.text:
                resp2 = self.safe_request("GET", test_url)
                if resp2 and expected in resp2.text:
                    return self._build_result(
                        "command_injection",
                        f"参数 {param} 存在命令注入，分隔符: {sep_label}",
                        {
                            "param": param,
                            "payload": payload,
                            "separator": sep_label,
                            "evidence_url": test_url,
                            "expected_output": expected,
                        },
                    )
        else:
            test_params = params.copy()
            test_params[param] = payload
            resp1 = self.safe_request("POST", url, data=test_params)
            if resp1 and expected in resp1.text:
                resp2 = self.safe_request("POST", url, data=test_params)
                if resp2 and expected in resp2.text:
                    return self._build_result(
                        "command_injection",
                        f"参数 {param} 存在命令注入，分隔符: {sep_label}",
                        {
                            "param": param,
                            "payload": payload,
                            "separator": sep_label,
                            "expected_output": expected,
                        },
                    )
        return None
