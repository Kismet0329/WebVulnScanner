from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class FileInclusionPlugin(ScannerPlugin):
    name = "file_inclusion"
    description = "检测本地文件包含（LFI）漏洞"
    severity = "high"

    # 第一阶段快速探测用单文件（Linux 最广泛存在）
    PROBE_FILE = "/etc/passwd"

    # 命中后扩展测试的完整文件列表
    # 签名收紧：每个文件至少 3 个强特征，避免普通页面内容误匹配
    # 关键：签名必须组合出现，单字符串几乎不会同时出现在正常页面里
    FILE_TESTS = {
        # /etc/passwd：3 个字段，passwd 格式独有
        "/etc/passwd": ["root:x:", ":0:0:", "/bin/"],
        # /etc/hosts：3 个特征组合，避免单 "localhost" 误报
        "/etc/hosts": ["127.0.0.1", "localhost", "::1"],
        # Windows win.ini：必须有 [fonts] + [extensions] 同时出现
        "C:\\Windows\\win.ini": ["[fonts]", "[extensions]", "[files]"],
        # Windows boot.ini：必须含 boot loader 段
        "C:\\boot.ini": ["[boot loader]", "timeout=", "default="],
    }

    # 探测文件直接复用 FILE_TESTS 的签名（统一管理）
    @property
    def PROBE_SIGNATURES(self):
        return self.FILE_TESTS[self.PROBE_FILE]

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

        # 关键修正：先发原始请求，记录 baseline 响应
        # 如果原始响应已含签名，说明页面本身有这些字符（非 LFI 触发），直接跳过该文件
        if method == "GET":
            baseline_resp = self.safe_request("GET", url)
        else:
            baseline_params = params.copy()
            baseline_resp = self.safe_request("POST", url, data=baseline_params)
        baseline_text = baseline_resp.text if baseline_resp else ""

        # 阶段 1：用 PROBE_FILE 快速探测
        result = self._try_file(url, param, original_value, method, params,
                                traversal, self.PROBE_FILE,
                                self.PROBE_SIGNATURES, baseline_text)
        if result:
            return result

        # 阶段 2：PROBE 未命中时，再测剩余文件（覆盖 Windows 路径等）
        for file_path, signatures in self.FILE_TESTS.items():
            if file_path == self.PROBE_FILE:
                continue
            result = self._try_file(url, param, original_value, method, params,
                                    traversal, file_path, signatures, baseline_text)
            if result:
                return result
        return None

    def _try_file(self, url, param, original_value, method, params,
                  traversal, file_path, signatures, baseline_text):
        """测试单个文件：构造 payload → 请求 → 对比 baseline → 二次确认"""
        # baseline 已含签名：页面本身就有这些字符，跳过避免误报
        if all(sig in baseline_text for sig in signatures):
            return None

        payload = traversal + file_path
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            resp1 = self.safe_request("GET", test_url)
            if not (resp1 and self._has_file_content(resp1.text, signatures)):
                return None
            # 二次确认
            resp2 = self.safe_request("GET", test_url)
            if not (resp2 and self._has_file_content(resp2.text, signatures)):
                return None
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
            if not (resp1 and self._has_file_content(resp1.text, signatures)):
                return None
            resp2 = self.safe_request("POST", url, data=test_params)
            if not (resp2 and self._has_file_content(resp2.text, signatures)):
                return None
            return self._build_result(
                "local_file_inclusion",
                f"参数 {param} 存在文件包含，可读取 {file_path}",
                {
                    "param": param,
                    "payload": payload,
                    "file_content": resp1.text[:300],
                },
            )

    def _has_file_content(self, text, signatures):
        # 所有特征都必须同时出现（AND 语义），收紧误报
        return all(sig in text for sig in signatures)
