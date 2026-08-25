import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""调试：scanner 跑完后再用插件直接测一次"""
import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
from http_client import HttpClient
from rate_limiter import TokenBucket
from plugins.sqli import SQLiPlugin

c = HttpClient(timeout=15)
ok = c.login("http://127.0.0.1:8888/login.php", "admin", "password")
print(f"login: {ok}, cookies: {[ck.name for ck in c.session.cookies]}")

# 直接访问 sqli URL 看响应
r = c.get("http://127.0.0.1:8888/vulnerabilities/sqli/?id=1")
print(f"\n正常 GET sqli?id=1: status={r.status_code}, body={r.text[:200]}")

r = c.get("http://127.0.0.1:8888/vulnerabilities/sqli/?id=1'")
print(f"注入 GET sqli?id=1': status={r.status_code}, body={r.text[:200]}")

rl = TokenBucket(rate=20, capacity=20)
p = SQLiPlugin(http_client=c, rate_limiter=rl, logger=logging.getLogger("sqli"),
               skip_params=None, fixed_delay=0.0)
target = {"url": "http://127.0.0.1:8888/vulnerabilities/sqli/?id=1", "method": "GET", "params": None}
found, result = p.check(target)
print(f"\nplugin.check 结果: found={found}")
if found:
    print(f"  type: {result.get('type')}")
    print(f"  detail: {result.get('detail')}")

