"""调试 crawler 单 URL 解析"""
import logging
logging.basicConfig(level=logging.WARNING)
from http_client import HttpClient
from rate_limiter import TokenBucket
from crawler import Crawler
from utils import normalize_url
from bs4 import BeautifulSoup
from urllib.parse import urljoin

c = HttpClient(timeout=15)
c.login("http://127.0.0.1:8888/login.php", "admin", "password")
rl = TokenBucket(rate=20, capacity=20)
crawler = Crawler(c, rl, depth=2, max_urls=50)
crawler.start_domain = "127.0.0.1:8888"

# 调 _process_url 处理 sqli 页面
print("=== /vulnerabilities/sqli/ ===")
new_links = crawler._process_url("http://127.0.0.1:8888/vulnerabilities/sqli/", 0)
print(f"new_links ({len(new_links)}):")
for l in new_links:
    print(f"  {l}")
print(f"found_targets ({len(crawler.found_targets)}):")
for t in crawler.found_targets:
    print(f"  [{t['method']}] {t['url']}")
