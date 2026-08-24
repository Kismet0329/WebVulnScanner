from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class FileInclusionPlugin(ScannerPlugin):
    name = "file_inclusion"
    description = "检测本地文件包含（LFI）漏洞"
    severity = "high"

    # 第一阶段快速探测用单文件（Linux 最广泛存在）
    PROBE_FILE = "/etc/passwd"
    PROBE_SIGNATURES = ["root:", "daemon:"]

    # 命中后扩展测试的完整文件列表
    FILE_TESTS = {
        "/etc/passwd": ["root:", "daemon:", "nobody:"],
        "/etc/hosts": ["localhost"],
        "C:\\Windows\\win.ini": ["[fonts]", "[extensions]"],
        "C:\\boot.ini": ["[boot loader]"],
    }

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
        traversal = "../../../../../../"

        # 阶段 1：仅用 PROBE_FILE 快速探测
        payload = traversal + self.PROBE_FILE
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            resp1 = self.safe_request("GET", test_url)
            if resp1 and self._has_file_content(resp1.text, self.PROBE_SIGNATURES):
                resp2 = self.safe_request("GET", test_url)
                if resp2 and self._has_file_content(resp2.text, self.PROBE_SIGNATURES):
                    return self._build_result(
                        "local_file_inclusion",
                        f"参数 {param} 存在文件包含，可读取 {self.PROBE_FILE}",
                        {
                            "param": param,
                            "payload": payload,
                            "evidence_url": test_url,
                            "file_content": resp1.text[:300],
                        },
                    )
        else:
            test_params = params.copy()
            test_params[param] = payload
            resp1 = self.safe_request("POST", url, data=test_params)
            if resp1 and self._has_file_content(resp1.text, self.PROBE_SIGNATURES):
                resp2 = self.safe_request("POST", url, data=test_params)
                if resp2 and self._has_file_content(resp2.text, self.PROBE_SIGNATURES):
                    return self._build_result(
                        "local_file_inclusion",
                        f"参数 {param} 存在文件包含，可读取 {self.PROBE_FILE}",
                        {
                            "param": param,
                            "payload": payload,
                            "file_content": resp1.text[:300],
                        },
                    )

        # 阶段 2：PROBE 未命中时，再测剩余文件（覆盖 Windows 路径等）
        for file_path, signatures in self.FILE_TESTS.items():
            if file_path == self.PROBE_FILE:
                continue
            payload = traversal + file_path
            if method == "GET":
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                query[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                resp1 = self.safe_request("GET", test_url)
                if resp1 and self._has_file_content(resp1.text, signatures):
                    resp2 = self.safe_request("GET", test_url)
                    if resp2 and self._has_file_content(resp2.text, signatures):
                        return self._build_result(
                            "local_file_inclusion",
                            f"参数 {param} 存在文件包含，可读取 {file_path}",
                            {
                                "param": param,
                                "payload": payload,
                                "evidence_url": test_url,
                                "file_content": resp1.text[:300],
                            },
                        )
            else:
                test_params = params.copy()
                test_params[param] = payload
                resp1 = self.safe_request("POST", url, data=test_params)
                if resp1 and self._has_file_content(resp1.text, signatures):
                    resp2 = self.safe_request("POST", url, data=test_params)
                    if resp2 and self._has_file_content(resp2.text, signatures):
                        return self._build_result(
                            "local_file_inclusion",
                            f"参数 {param} 存在文件包含，可读取 {file_path}",
                            {
                                "param": param,
                                "payload": payload,
                                "file_content": resp1.text[:300],
                            },
                        )
        return None

    def _has_file_content(self, text, signatures):
        return all(sig in text for sig in signatures)
