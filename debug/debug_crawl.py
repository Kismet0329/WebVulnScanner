import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""调试：复用 scanner 的 crawler，看爬到哪些 URL"""
import logging
logging.basicConfig(level=logging.WARNING)
from http_client import HttpClient
from rate_limiter import TokenBucket
from crawler import Crawler
from config import DEFAULT_CONFIG

c = HttpClient(timeout=15, verify_ssl=False, user_agent=DEFAULT_CONFIG["user_agent"])
c.login("http://127.0.0.1:8888/login.php", "admin", "password")
print("登录成功")

rl = TokenBucket(rate=20, capacity=20)
crawler = Crawler(c, rl, depth=2, max_urls=50, allow_external=False, js_render=False)
targets = crawler.crawl("http://127.0.0.1:8888/")
print(f"\n爬到 {len(targets)} 个 targets:")
for t in targets:
    print(f"  [{t['method']}] {t['url']}  params={t.get('params')}")

