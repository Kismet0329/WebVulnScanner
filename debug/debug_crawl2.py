import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import logging
logging.basicConfig(level=logging.WARNING)
from http_client import HttpClient
from rate_limiter import TokenBucket
from crawler import Crawler

c = HttpClient(timeout=15)
c.login("http://127.0.0.1:8888/login.php", "admin", "password")
rl = TokenBucket(rate=20, capacity=20)
crawler = Crawler(c, rl, depth=2, max_urls=50, allow_external=False, js_render=False)
targets = crawler.crawl("http://127.0.0.1:8888/")
print(f"爬到 {len(targets)} 个 targets")
for t in targets:
    u = t["url"]
    if "sqli" in u or "exec" in u or "xss" in u or "fi/" in u or "fi?" in u:
        print(f"  [{t['method']}] {u}")

