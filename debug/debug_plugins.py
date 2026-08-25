import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""调试：完全模拟 scanner 调用插件的方式"""
import logging
logging.basicConfig(level=logging.WARNING)
from http_client import HttpClient
from rate_limiter import TokenBucket
from plugins.sqli import SQLiPlugin
from plugins.command_injection import CommandInjectionPlugin
from plugins.xss import XSSPlugin
from plugins.file_inclusion import FileInclusionPlugin

c = HttpClient(timeout=15)
c.login("http://127.0.0.1:8888/login.php", "admin", "password")

# 完全按 scanner.py 的方式构造（含 skip_params=fixed_delay=None）
rl = TokenBucket(rate=20, capacity=20)
for cls, test_url in [
    (SQLiPlugin, "http://127.0.0.1:8888/vulnerabilities/sqli/?id=1"),
    (SQLiPlugin, "http://127.0.0.1:8888/vulnerabilities/sqli_blind/?id=1"),
    (CommandInjectionPlugin, "http://127.0.0.1:8888/vulnerabilities/exec/?ip=127.0.0.1"),
    (XSSPlugin, "http://127.0.0.1:8888/vulnerabilities/xss_r/?name=test"),
    (FileInclusionPlugin, "http://127.0.0.1:8888/vulnerabilities/fi/?page=file1"),
]:
    p = cls(http_client=c, rate_limiter=rl, logger=logging.getLogger(cls.__name__),
            skip_params=None, fixed_delay=0.0)
    # 模拟 scanner 的 plugin.check(target)
    target = {"url": test_url, "method": "GET", "params": None}
    found, result = p.check(target)
    if found:
        print(f"[+] {cls.__name__}: {result.get('type')} - {result.get('detail')}")
    else:
        print(f"[-] {cls.__name__}: 未发现  url={test_url}")

