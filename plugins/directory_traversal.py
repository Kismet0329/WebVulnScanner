from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin


class DirectoryTraversalPlugin(ScannerPlugin):
    name = "directory_traversal"
    description = "目录遍历漏洞检测"
    severity = "high"

    # 敏感文件特征（全部使用列表）
    FILE_SIGNATURES = {
        "etc/passwd": ["root:", "daemon:", "bin:"],
        "boot.ini": ["[boot loader]"],
        "win.ini": ["[fonts]"],
        "web.config": ["<configuration>"],
    }
    traversal_sequences = [
        "../", "..\\", "..%2f", "..%5c", "....//", "....\\\\",
        "%2e%2e%2f", "%2e%2e%5c",
    ]

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
        for seq in self.traversal_sequences:
            for file_path, signatures in self.FILE_SIGNATURES.items():
                payload = seq * 5 + file_path
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
                if resp and self._has_file_content(resp.text, signatures):
                    resp2 = self.safe_request("GET", test_url) if method == "GET" else self.safe_request("POST", url, data=test_params)
                    if resp2 and self._has_file_content(resp2.text, signatures):
                        return True, self._build_result(
                            "directory_traversal",
                            f"参数 {param} 存在目录遍历，可读取 {file_path}",
                            {
                                "param": param,
                                "payload": payload,
                                "evidence_url": test_url if method == "GET" else url,
                                "file_content": resp.text[:300],
                            },
                        )
        return False, {}

    def _test_path(self, url):
        # 使用 urljoin 正确拼接遍历序列到 URL 路径，避免破坏查询字符串
        parsed = urlparse(url)
        base_path = parsed.path or "/"
        for seq in self.traversal_sequences:
            for file_path, signatures in self.FILE_SIGNATURES.items():
                new_path = base_path.rstrip('/') + '/' + seq * 5 + file_path
                test_url = urlunparse(parsed._replace(path=new_path, query=""))
                resp = self.safe_request("GET", test_url)
                if resp and self._has_file_content(resp.text, signatures):
                    resp2 = self.safe_request("GET", test_url)
                    if resp2 and self._has_file_content(resp2.text, signatures):
                        return True, self._build_result(
                            "directory_traversal",
                            f"路径存在目录遍历，可读取 {file_path}",
                            {
                                "url": test_url,
                                "file_content": resp.text[:300],
                            },
                        )
        return False, {}

    def _has_file_content(self, text, signatures):
        # 所有特征都必须出现，降低误报
        return all(sig in text for sig in signatures)
