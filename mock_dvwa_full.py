"""扩展 Mock DVWA：登录 + 漏洞页面

模拟完整 DVWA 流程：
1. GET /login.php 返回带 user_token 的登录表单
2. POST /login.php 校验 user_token + admin/password，成功后设置 PHPSESSID
3. /vulnerabilities/* 受保护，未登录重定向
4. 各漏洞页面模拟真实漏洞：
   - /vulnerabilities/sqli/?id=1 真实报错注入
   - /vulnerabilities/sqli_blind/?id=1 真实时间盲注（SLEEP(2)）
   - /vulnerabilities/exec/ 真实命令注入
   - /vulnerabilities/xss_r/?name=test 真实反射 XSS
   - /vulnerabilities/fi/?page=../../../../etc/passwd 真实 LFI
"""
import http.server
import socketserver
import threading
import secrets
import time
import re


AUTHENTICATED_SESSIONS = set()
PENDING_TOKENS = {}
WELL_KNOWN_SESSIONS = {
    # 支持 --cookie 模式自测：扫描器直接提供此 PHPSESSID 即可跳过登录
    "e8a5b6c2d4f0a8b2c4d6e8f0a2c4b6d8",
}
# 初始化时把已知 session 加入已认证集合
AUTHENTICATED_SESSIONS.update(WELL_KNOWN_SESSIONS)


class MockDVWAHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _log_req(self, label=""):
        """调试：打印所有请求"""
        import sys
        sid = self._session_id() or "-"
        auth = "AUTH" if self._is_authenticated() else "anon"
        print(f"[{label}] {self.command} {self.path}  sid={sid[:8]} {auth}", file=sys.stderr)

    def _session_id(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("PHPSESSID="):
                return part[len("PHPSESSID="):]
        return None

    def _set_session_cookie_header(self, sid):
        self.send_header("Set-Cookie", f"PHPSESSID={sid}; path=/")

    def _is_authenticated(self):
        sid = self._session_id()
        return sid is not None and sid in AUTHENTICATED_SESSIONS

    def do_GET(self):
        # 登录页
        if self.path.startswith("/login.php"):
            sid = self._session_id()
            new_cookie = sid is None
            if not sid:
                sid = secrets.token_hex(16)
            token = secrets.token_hex(16)
            PENDING_TOKENS[sid] = token

            html = f"""<!DOCTYPE html>
<html><body>
<form action="login.php" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="hidden" name="user_token" value="{token}">
    <input type="submit" name="Login" value="Login">
</form>
</body></html>"""
            self._send_html(html, new_cookie=new_cookie, sid=sid)
            return

        # robots.txt
        if self.path == "/robots.txt":
            self._send_text("User-agent: *\nDisallow: /vulnerabilities/\nDisallow: /admin/")
            return

        # 首页
        if self.path in ("/", "/index.php"):
            if not self._is_authenticated():
                self._redirect("/login.php")
                return
            html = """<!DOCTYPE html>
<html><body>
<h1>DVWA</h1>
<a href="/vulnerabilities/sqli/">SQL Injection</a>
<a href="/vulnerabilities/sqli_blind/">SQL Blind</a>
<a href="/vulnerabilities/exec/">Command Injection</a>
<a href="/vulnerabilities/xss_r/">XSS Reflected</a>
<a href="/vulnerabilities/fi/">File Inclusion</a>
<a href="/logout.php">Logout</a>
</body></html>"""
            self._send_html(html)
            return

        # 受保护页面
        if self.path.startswith("/vulnerabilities/"):
            if not self._is_authenticated():
                self._redirect("/login.php")
                return
            self._handle_vuln_page()
            return

        if self.path.startswith("/logout.php"):
            sid = self._session_id()
            AUTHENTICATED_SESSIONS.discard(sid)
            self._redirect("/login.php")
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

        form = {}
        for part in body.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                form[k] = v

        expected_token = PENDING_TOKENS.get(sid)
        submitted_token = form.get("user_token")

        if not submitted_token or submitted_token != expected_token:
            self._send_html("<html><body>CSRF token is missing or incorrect</body></html>",
                            new_cookie=new_cookie, sid=sid)
            return

        if form.get("username") == "admin" and form.get("password") == "password":
            AUTHENTICATED_SESSIONS.add(sid)
            PENDING_TOKENS.pop(sid, None)
            self._send_html("<html><body>Welcome to DVWA! <a href='logout.php'>Logout</a></body></html>",
                            new_cookie=new_cookie, sid=sid)
        else:
            self._send_html("<html><body>Username and/or password incorrect.</body></html>",
                            new_cookie=new_cookie, sid=sid)

    def _simulate_shell(self, cmd):
        """模拟 shell 命令执行：提取 echo 参数并计算 $((expr))。"""
        import re as _re
        # 提取 echo 后的内容（支持 $(echo ...) 和 sep echo ... 两种形式）
        m = _re.search(r'echo\s+(.+)', cmd)
        if not m:
            return ""
        arg = m.group(1).strip()
        # 计算 $((expr)) 形式
        def _eval_math(match):
            expr = match.group(1).strip()
            if not _re.match(r'^[\d\s+\-*/]+$', expr):
                return match.group(0)
            try:
                return str(int(eval(expr, {"__builtins__": {}}, {})))
            except Exception:
                return match.group(0)
        return _re.sub(r'\$\(\(([^)]+)\)\)', _eval_math, arg)

    def _handle_vuln_page(self):
        """模拟 DVWA 各漏洞页面"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        # 调试：打印漏洞页请求
        self._log_req("VULN")

        # SQL Injection（报错）
        if path == "/vulnerabilities/sqli/":
            id_val = qs.get("id", [""])[0]
            if "'" in id_val:
                self._send_text("You have an error in your SQL syntax; check the manual for MySQL: select * from users where id='" + id_val + "'")
            else:
                self._send_html(f"<html><body>ID: {id_val}<form action='/vulnerabilities/sqli/' method='get'>ID: <input type='text' name='id' value='1'><input type='submit'></form></body></html>")
            return

        # SQL Blind（时间盲注）
        if path == "/vulnerabilities/sqli_blind/":
            id_val = qs.get("id", [""])[0]
            if "SLEEP(2)" in id_val.upper():
                time.sleep(2)
                self._send_text("ok")
            elif "'" in id_val:
                self._send_text("error in SQL syntax")
            else:
                self._send_html(f"<html><body>User ID exists<form action='/vulnerabilities/sqli_blind/' method='get'>ID: <input type='text' name='id' value='1'><input type='submit'></form></body></html>")
            return

        # Command Injection
        if path == "/vulnerabilities/exec/":
            ip = qs.get("ip", [""])[0]
            # 模拟 shell_exec("ping -c 4 $ip")
            if ";" in ip or "|" in ip or "&" in ip or "$(" in ip:
                output = self._simulate_shell(ip)
                self._send_text(f"PING ok\n{output}\nuid=33(www-data)")
            else:
                self._send_html(f"<html><body>PING {ip}<form action='/vulnerabilities/exec/' method='get'>IP: <input type='text' name='ip' value='127.0.0.1'><input type='submit'></form></body></html>")
            return

        # XSS Reflected
        if path == "/vulnerabilities/xss_r/":
            name = qs.get("name", [""])[0]
            # 真实回显
            self._send_html(f"<html><body>Hello {name}<form action='/vulnerabilities/xss_r/' method='get'>Name: <input type='text' name='name' value='test'><input type='submit'></form></body></html>")
            return

        # File Inclusion
        if path == "/vulnerabilities/fi/":
            page = qs.get("page", [""])[0]
            if "../" in page and "etc/passwd" in page:
                self._send_text("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            elif "../" in page and "etc/hosts" in page:
                self._send_text("127.0.0.1\tlocalhost\n::1\tlocalhost\n")
            else:
                self._send_html(f"<html><body>Page: {page}<form action='/vulnerabilities/fi/' method='get'>Page: <input type='text' name='page' value='file1'><input type='submit'></form></body></html>")
            return

        # 默认漏洞列表页
        if path in ("/vulnerabilities/", "/vulnerabilities/sqli/",
                    "/vulnerabilities/sqli_blind/", "/vulnerabilities/exec/",
                    "/vulnerabilities/xss_r/", "/vulnerabilities/fi/"):
            # 每个漏洞页都返回对应的输入表单，让爬虫能爬到带参数的 URL
            html_forms = {
                "/vulnerabilities/sqli/": '<form action="/vulnerabilities/sqli/" method="get">ID: <input type="text" name="id" value="1"><input type="submit"></form>',
                "/vulnerabilities/sqli_blind/": '<form action="/vulnerabilities/sqli_blind/" method="get">ID: <input type="text" name="id" value="1"><input type="submit"></form>',
                "/vulnerabilities/exec/": '<form action="/vulnerabilities/exec/" method="get">IP: <input type="text" name="ip" value="127.0.0.1"><input type="submit"></form>',
                "/vulnerabilities/xss_r/": '<form action="/vulnerabilities/xss_r/" method="get">Name: <input type="text" name="name" value="test"><input type="submit"></form>',
                "/vulnerabilities/fi/": '<form action="/vulnerabilities/fi/" method="get">Page: <input type="text" name="page" value="file1"><input type="submit"></form>',
                "/vulnerabilities/": '<a href="/vulnerabilities/sqli/">SQLi</a> <a href="/vulnerabilities/sqli_blind/">SQLi Blind</a> <a href="/vulnerabilities/exec/">Exec</a> <a href="/vulnerabilities/xss_r/">XSS</a> <a href="/vulnerabilities/fi/">FI</a>',
            }
            html = f"<html><body>{html_forms.get(path, '')}</body></html>"
            self._send_html(html)
            return

        self.send_response(404)
        self.end_headers()

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send_html(self, html, status=200, new_cookie=False, sid=None):
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if new_cookie and sid:
            self._set_session_cookie_header(sid)
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, text, status=200):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mock DVWA 完整漏洞靶场")
    parser.add_argument("--port", type=int, default=8888)
    args = parser.parse_args()

    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", args.port), MockDVWAHandler)
    httpd.daemon_threads = True
    print(f"[*] Mock DVWA 监听 http://127.0.0.1:{args.port}/login.php")
    print(f"[*] 凭据: admin / password")
    print(f"[*] --cookie 自测: PHPSESSID={next(iter(WELL_KNOWN_SESSIONS))}; security=low")
    print(f"[*] 漏洞页面:")
    print(f"    /vulnerabilities/sqli/?id=1'         报错注入")
    print(f"    /vulnerabilities/sqli_blind/?id=1'    时间盲注")
    print(f"    /vulnerabilities/exec/?ip=127.0.0.1   命令注入")
    print(f"    /vulnerabilities/xss_r/?name=test     XSS")
    print(f"    /vulnerabilities/fi/?page=file        LFI")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
