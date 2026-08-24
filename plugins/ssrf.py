import random
import string
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class _CallbackHandler(BaseHTTPRequestHandler):
    """回调监听器：记录收到的请求路径。"""

    def log_message(self, fmt, *args):
        pass  # 静默

    def do_GET(self):
        self.server.received_paths.add(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_HEAD(self):
        self.do_GET()


class _CallbackServer:
    """临时 HTTP 监听器，用于 SSRF 回调确认。

    在随机端口上启动，等待目标服务器发起的 HTTP 请求。
    若收到带特定 token 的请求，则确认 SSRF。
    """

    def __init__(self, host="127.0.0.1"):
        self.received_paths = set()
        self._httpd = HTTPServer((host, 0), _CallbackHandler)
        self._httpd.received_paths = self.received_paths
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self.port = self._httpd.server_address[1]
        self.host = host

    def was_hit(self, token, timeout=2.0):
        """等待 timeout 秒，检查是否收到 /{token} 请求。"""
        deadline = time.monotonic() + timeout
        expected = f"/{token}"
        while time.monotonic() < deadline:
            if any(p == expected or p.startswith(expected + "?") for p in self.received_paths):
                return True
            time.sleep(0.1)
        return any(p == expected or p.startswith(expected + "?") for p in self.received_paths)

    def stop(self):
        try:
            self._httpd.shutdown()
        except Exception:
            pass
        try:
            self._httpd.server_close()
        except Exception:
            pass


class SSRFPlugin(ScannerPlugin):
    name = "ssrf"
    description = "检测服务端请求伪造（SSRF）漏洞（基于回调确认）"
    severity = "high"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        server = _CallbackServer()
        try:
            callback_url = f"http://{server.host}:{server.port}/{token}"
            if method == "GET":
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                query[param] = [callback_url]
                test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                self.safe_request("GET", test_url)
            else:
                test_params = params.copy()
                test_params[param] = callback_url
                self.safe_request("POST", url, data=test_params)

            # 等待回调（给目标服务器留出发起请求的时间）
            if server.was_hit(token, timeout=2.0):
                return self._build_result(
                    "ssrf",
                    f"参数 {param} 存在 SSRF，服务器请求了回调地址 {callback_url}",
                    {
                        "param": param,
                        "payload": callback_url,
                        "callback_hit": True,
                    },
                )
        finally:
            server.stop()
        return None
