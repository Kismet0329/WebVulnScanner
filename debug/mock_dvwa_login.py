import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""Mock DVWA 登录流程测试

模拟 DVWA 的真实登录流程：
1. GET /login.php 返回带 user_token 的表单
2. POST /login.php 必须同时提交 user_token + 正确凭据
3. 缺失 user_token 时返回 "CSRF token is missing"
4. 错误凭据返回 "Login failed"
5. 登录成功后设置 PHPSESSID cookie，并允许访问受保护页面

用法：
    # 终端 1：启动 mock DVWA
    python mock_dvwa_login.py --port 8888

    # 终端 2：测试登录
    python test_login.py --url http://127.0.0.1:8888/login.php --user admin --pass password
"""
import argparse
import http.server
import socketserver
import threading
import secrets
import time


# 全局状态：已认证的 session id → True
AUTHENTICATED_SESSIONS = set()
# 每个未认证 session 对应的 user_token
PENDING_TOKENS = {}


class MockDVWAHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _session_id(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("PHPSESSID="):
                return part[len("PHPSESSID="):]
        return None

    def _begin_response(self, status, content_type="text/html; charset=utf-8", extra_headers=None):
        """统一响应入口：发状态行 + 必需头 + 额外头"""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)

    def _set_session_cookie_header(self, sid):
        self.send_header("Set-Cookie", f"PHPSESSID={sid}; path=/")

    def do_GET(self):
        # 登录页
        if self.path.startswith("/login.php"):
            sid = self._session_id()
            new_cookie = sid is None
            if not sid:
                sid = secrets.token_hex(16)
            # 生成该 session 对应的 user_token
            token = secrets.token_hex(16)
            PENDING_TOKENS[sid] = token

            html = f"""<!DOCTYPE html>
<html>
<body>
<form action="login.php" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="hidden" name="user_token" value="{token}">
    <input type="submit" name="Login" value="Login">
</form>
</body>
</html>"""
            if new_cookie:
                data = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self._set_session_cookie_header(sid)
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send_html(html)
            return

        # 受保护页面
        if self.path.startswith("/vulnerabilities/"):
            sid = self._session_id()
            if not sid or sid not in AUTHENTICATED_SESSIONS:
                # 重定向到登录页
                self.send_response(302)
                self.send_header("Location", "/login.php")
                self.end_headers()
                return
            self._send_html("<html><body>Protected page content</body></html>")
            return

        # 首页
        if self.path == "/" or self.path == "/index.php":
            self._send_html("<html><body><a href='/login.php'>Login</a></body></html>")
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if not self.path.startswith("/login.php"):
            self.send_response(404)
            self.end_headers()
            return

        sid = self._session_id()
        new_cookie = sid is None
        if not sid:
            sid = secrets.token_hex(16)

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""

        # 解析表单
        form = {}
        for part in body.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                form[k] = v

        # CSRF 校验
        expected_token = PENDING_TOKENS.get(sid)
        submitted_token = form.get("user_token")

        if not submitted_token or submitted_token != expected_token:
            self._send_html("<html><body>CSRF token is missing or incorrect</body></html>", status=200, new_cookie=new_cookie, sid=sid)
            return

        # 凭据校验（DVWA 默认 admin/password）
        if form.get("username") == "admin" and form.get("password") == "password":
            AUTHENTICATED_SESSIONS.add(sid)
            PENDING_TOKENS.pop(sid, None)
            self._send_html("<html><body>Welcome to DVWA! <a href='logout.php'>Logout</a></body></html>", status=200, new_cookie=new_cookie, sid=sid)
        else:
            self._send_html("<html><body>Username and/or password incorrect.</body></html>", status=200, new_cookie=new_cookie, sid=sid)

    def _send_html(self, html, status=200, new_cookie=False, sid=None):
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if new_cookie and sid:
            self._set_session_cookie_header(sid)
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description="Mock DVWA 登录服务器")
    parser.add_argument("--port", type=int, default=8888)
    args = parser.parse_args()

    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", args.port), MockDVWAHandler)
    httpd.daemon_threads = True
    print(f"[*] Mock DVWA 监听 http://127.0.0.1:{args.port}/login.php")
    print(f"[*] 凭据: admin / password")
    print(f"[*] 登录页带 user_token（CSRF）")
    print(f"[*] 受保护页面: /vulnerabilities/exec/")
    print(f"[*] Ctrl+C 停止")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 停止")
        httpd.shutdown()


if __name__ == "__main__":
    main()

