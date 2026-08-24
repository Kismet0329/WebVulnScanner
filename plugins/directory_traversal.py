from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class DirectoryTraversalPlugin(ScannerPlugin):
    name = "directory_traversal"
    description = "目录遍历漏洞检测"
    severity = "high"

    # 收敛后的遍历序列：覆盖 Unix/Windows/编码绕过三类
    traversal_sequences = ["../", "..\\", "..%2f"]

    # 第一阶段快速探测用单一文件（最广泛存在）
    PROBE_FILE = "etc/passwd"
    PROBE_SIGNATURES = ["root:", "daemon:"]

    # 命中后扩展测试的完整文件列表
    FILE_SIGNATURES = {
        "etc/passwd": ["root:", "daemon:", "bin:"],
        "boot.ini": ["[boot loader]"],
        "win.ini": ["[fonts]"],
        "web.config": ["<configuration>"],
    }

    def check_get(self, url):
        testable = self.get_testable_params(url, method="GET")
        for param, original_value in testable.items():
            found, result = self._test_param(url, param, original_value, method="GET")
            if found:
                return True, result
        return self._test_path(url)

    def check_post(self, url, params):
        if not params:
            return False, {}
        testable = self.get_testable_params(url, method="POST", params=params)
        for param, original_value in testable.items():
            found, result = self._test_param(url, param, original_value, method="POST", params=params)
            if found:
                return True, result
        return False, {}

    def _test_param(self, url, param, original_value, method="GET", params=None):
        # 阶段 1：每个序列仅用 PROBE_FILE 快速探测，命中后扩展测试
        for seq in self.traversal_sequences:
            payload = seq * 5 + self.PROBE_FILE
            if method == "GET":
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                query[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                resp = self.safe_request("GET", test_url)
            else:
                test_params = params.copy()
                test_params[param] = payload
                resp = self.safe_request("POST", url, data=test_params)

            if resp and self._has_file_content(resp.text, self.PROBE_SIGNATURES):
                # 二次确认避免误报
                resp2 = self.safe_request("GET", test_url) if method == "GET" else self.safe_request("POST", url, data=test_params)
                if resp2 and self._has_file_content(resp2.text, self.PROBE_SIGNATURES):
                    return True, self._build_result(
                        "directory_traversal",
                        f"参数 {param} 存在目录遍历，可读取 {self.PROBE_FILE}",
                        {
                            "param": param,
                            "payload": payload,
                            "evidence_url": test_url if method == "GET" else url,
                            "file_content": resp.text[:300],
                        },
                    )
        return False, {}

    def _test_path(self, url):
        # 使用 urlunparse 正确拼接遍历序列到 URL 路径，避免破坏查询字符串
        parsed = urlparse(url)
        base_path = parsed.path or "/"
        for seq in self.traversal_sequences:
            new_path = base_path.rstrip('/') + '/' + seq * 5 + self.PROBE_FILE
            test_url = urlunparse(parsed._replace(path=new_path, query=""))
            resp = self.safe_request("GET", test_url)
            if resp and self._has_file_content(resp.text, self.PROBE_SIGNATURES):
                resp2 = self.safe_request("GET", test_url)
                if resp2 and self._has_file_content(resp2.text, self.PROBE_SIGNATURES):
                    return True, self._build_result(
                        "directory_traversal",
                        f"路径存在目录遍历，可读取 {self.PROBE_FILE}",
                        {
                            "url": test_url,
                            "file_content": resp.text[:300],
                        },
                    )
        return False, {}

    def _has_file_content(self, text, signatures):
        # 所有特征都必须出现，降低误报
        return all(sig in text for sig in signatures)
