"""Mock Pikachu：复现导致重复漏洞报告的页面结构。

真实 Pikachu 的典型特征（DVWA 较少）：
1. 侧边栏多次链接同一漏洞页，query 值不同（name=test / name=admin）
2. 父页面 iframe 嵌入同一漏洞页
3. 同一端点同时存在 GET 链接与 POST 表单
4. 菜单页 + 内容页路径重叠

本 Mock 提供可注入的 SQLi / XSS / LFI，供扫描器端到端验证去重。
"""
import argparse
import http.server
import socketserver
import urllib.parse
import re
import time


PORT_DEFAULT = 8765


def _html(body, title="Pikachu Mock"):
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body>
{body}
</body></html>"""


def _nav():
    # 故意用不同 query 值重复指向同一漏洞页 —— 这是 Pikachu 重复报告的主因
    return """
<div id="menu">
  <h3>Pikachu Mock</h3>
  <ul>
    <li><a href="/">首页</a></li>
    <li><a href="/vul/sqli/sqli_search.php">SQLi 搜索</a></li>
    <li><a href="/vul/sqli/sqli_search.php?name=test">SQLi 搜索(test)</a></li>
    <li><a href="/vul/sqli/sqli_search.php?name=admin">SQLi 搜索(admin)</a></li>
    <li><a href="/vul/xss/xss_reflected.php">XSS 反射</a></li>
    <li><a href="/vul/xss/xss_reflected.php?message=hello">XSS 反射(hello)</a></li>
    <li><a href="/vul/xss/xss_reflected.php?message=world">XSS 反射(world)</a></li>
    <li><a href="/vul/rce/rce_ping.php">命令执行</a></li>
    <li><a href="/vul/rce/rce_ping.php?ip=127.0.0.1">命令执行(ping)</a></li>
    <li><a href="/vul/fileinclude/fi_local.php">文件包含</a></li>
    <li><a href="/vul/fileinclude/fi_local.php?filename=include.php">文件包含(include)</a></li>
    <li><a href="/vul/fileinclude/fi_local.php?filename=header.php">文件包含(header)</a></li>
    <li><a href="/pkxss/index.php">XSS 管理后台</a></li>
  </ul>
</div>
"""


class PikachuHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, html, code=200):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.php"):
            # 首页：侧边栏 + iframe（iframe 再指向漏洞页，扩大重复目标）
            body = _nav() + """
<iframe src="/vul/sqli/sqli_search.php?name=iframe" width="800" height="200"></iframe>
<iframe src="/vul/xss/xss_reflected.php?message=iframe" width="800" height="200"></iframe>
<p>欢迎使用 Pikachu Mock（用于验证扫描器去重）</p>
"""
            return self._send(_html(body))

        if path == "/robots.txt":
            text = "User-agent: *\nDisallow: /vul/\nDisallow: /pkxss/\n"
            data = text.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/vul/sqli/sqli_search.php":
            name = (qs.get("name") or [""])[0]
            result = self._sqli_search(name)
            body = _nav() + f"""
<h2>SQL注入 - 搜索型</h2>
<form method="get" action="/vul/sqli/sqli_search.php">
  <input type="text" name="name" value="{self._esc(name)}">
  <input type="submit" name="submit" value="search">
</form>
<form method="post" action="/vul/sqli/sqli_search.php">
  <input type="text" name="name" value="">
  <input type="submit" name="submit" value="post search">
</form>
<div>{result}</div>
"""
            return self._send(_html(body))

        if path == "/vul/xss/xss_reflected.php":
            msg = (qs.get("message") or [""])[0]
            body = _nav() + f"""
<h2>XSS - 反射型</h2>
<form method="get" action="/vul/xss/xss_reflected.php">
  <input type="text" name="message" value="{self._esc(msg)}">
  <input type="submit" name="submit" value="提交">
</form>
<form method="post" action="/vul/xss/xss_reflected.php">
  <input type="text" name="message" value="">
  <input type="submit" name="submit" value="POST提交">
</form>
<p>你输入的内容是: {msg}</p>
"""
            return self._send(_html(body))

        if path == "/vul/rce/rce_ping.php":
            ip = (qs.get("ip") or ["127.0.0.1"])[0]
            out = self._rce(ip)
            body = _nav() + f"""
<h2>RCE - ping</h2>
<form method="get" action="/vul/rce/rce_ping.php">
  <input type="text" name="ip" value="{self._esc(ip)}">
  <input type="submit" name="submit" value="ping">
</form>
<form method="post" action="/vul/rce/rce_ping.php">
  <input type="text" name="ip" value="127.0.0.1">
  <input type="submit" name="submit" value="POST ping">
</form>
<pre>{self._esc(out)}</pre>
"""
            return self._send(_html(body))

        if path == "/vul/fileinclude/fi_local.php":
            filename = (qs.get("filename") or ["include.php"])[0]
            content = self._lfi(filename)
            body = _nav() + f"""
<h2>文件包含</h2>
<form method="get" action="/vul/fileinclude/fi_local.php">
  <input type="text" name="filename" value="{self._esc(filename)}">
  <input type="submit" name="submit" value="include">
</form>
<form method="post" action="/vul/fileinclude/fi_local.php">
  <input type="text" name="filename" value="include.php">
  <input type="submit" name="submit" value="POST include">
</form>
<pre>{self._esc(content)}</pre>
"""
            return self._send(_html(body))

        if path == "/pkxss/index.php":
            body = _nav() + "<h2>XSS 管理后台</h2><p>cookie 捞取面板（mock）</p>"
            return self._send(_html(body))

        self._send(_html(_nav() + "<p>404</p>"), code=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        form = urllib.parse.parse_qs(raw)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/vul/sqli/sqli_search.php":
            name = (form.get("name") or [""])[0]
            result = self._sqli_search(name)
            body = _nav() + f"<h2>SQL注入 POST</h2><div>{result}</div>"
            return self._send(_html(body))

        if path == "/vul/xss/xss_reflected.php":
            msg = (form.get("message") or [""])[0]
            body = _nav() + f"<h2>XSS POST</h2><p>你输入的内容是: {msg}</p>"
            return self._send(_html(body))

        if path == "/vul/rce/rce_ping.php":
            ip = (form.get("ip") or ["127.0.0.1"])[0]
            out = self._rce(ip)
            body = _nav() + f"<h2>RCE POST</h2><pre>{self._esc(out)}</pre>"
            return self._send(_html(body))

        if path == "/vul/fileinclude/fi_local.php":
            filename = (form.get("filename") or ["include.php"])[0]
            content = self._lfi(filename)
            body = _nav() + f"<h2>LFI POST</h2><pre>{self._esc(content)}</pre>"
            return self._send(_html(body))

        self._send(_html("<p>404</p>"), code=404)

    @staticmethod
    def _esc(s):
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _sqli_search(self, name):
        if not name:
            return "<p>请输入关键字</p>"
        # 报错注入：单引号触发 MySQL 风格错误
        if "'" in name or re.search(r"(union|sleep|and\s+\d)", name, re.I):
            return (
                "You have an error in your SQL syntax; check the manual that "
                "corresponds to your MySQL server version for the right syntax "
                "to use near ''' at line 1"
            )
        return f"<p>找到用户: {self._esc(name)}</p>"

    def _rce(self, ip):
        # 简易命令注入：分号/管道后跟 echo 会回显
        m = re.search(r"[;|&]|\$\((.+)\)", ip)
        if m:
            # 模拟 echo MARKER 输出
            echo = re.search(r"echo\s+(\S+)", ip)
            if echo:
                return f"PING 127.0.0.1\n{echo.group(1)}\n"
            return "PING 127.0.0.1\ninjected\n"
        return f"PING {ip}: 64 bytes from {ip}: icmp_seq=1 ttl=64"

    def _lfi(self, filename):
        if "etc/passwd" in filename.replace("\\", "/"):
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        if ".." in filename:
            time.sleep(0.01)
        return f"<!-- included {filename} -->\nok"


def main():
    parser = argparse.ArgumentParser(description="Mock Pikachu for dedup testing")
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    args = parser.parse_args()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", args.port), PikachuHandler) as httpd:
        print(f"Mock Pikachu running at http://127.0.0.1:{args.port}/", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
