import uuid
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
        # 使用 uuid4 保证进程内/跨进程都不冲突，避免 id() 在对象回收后复用
        self.marker = "XSS_" + uuid.uuid4().hex[:16] + "_MARKER"

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
                        {
                            "param": param,
                            "payload": payload_with_marker,
                            "evidence_url": url,
                        },
                    )
        return None

    def _is_executable_context(self, html, marker):
        """判定 marker 是否出现在可执行上下文中：
        - <script>...</script> 内
        - HTML 标签的事件处理器属性值内（on*=...）
        - 作为新 HTML 元素的一部分（marker 位于标签名或属性之外但被解析为标签）
        注意：原第三条正则 `<[^>]+[^>]*marker` 会匹配 marker 出现在标签文本节点等任意位置，
        造成误报，这里收紧为 marker 紧跟 < 后或位于事件处理器值内。
        """
        escaped = re.escape(marker)
        patterns = [
            # <script>...marker...</script>
            r'<script[^>]*>[\s\S]*?' + escaped + r'[\s\S]*?</script>',
            # 事件处理器：on\w+="..." 内含 marker
            r'on\w+\s*=\s*["\'][^"\']*' + escaped,
            # marker 作为新标签起始（如反射出 <marker... 或 "><img...marker）
            r'<' + escaped,
            # marker 出现在标签名或属性中（如 <a href=marker），需 marker 跟在标签内
            r'<[^>]*\b\w+\s*=\s*["\']?\s*' + escaped,
        ]
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                return True
        return False
