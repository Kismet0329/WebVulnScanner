"""Crawl Pikachu and show target dedup effectiveness."""
import logging
from collections import Counter
from urllib.parse import urlparse

from http_client import HttpClient
from rate_limiter import TokenBucket
from crawler import Crawler
from utils import normalize_path, target_dedup_key

logging.basicConfig(level=logging.WARNING)
client = HttpClient(timeout=10)
crawler = Crawler(client, TokenBucket(20, 20), depth=2, max_urls=80)
targets = crawler.crawl("http://192.168.222.134:8765/")
print(f"targets after crawl dedup: {len(targets)}")

paths = Counter(normalize_path(t["url"]) for t in targets)
print("same path appearing >1 (should be rare; GET+POST ok):")
for path, n in paths.most_common(15):
    methods = [t["method"] for t in targets if normalize_path(t["url"]) == path]
    if n > 1:
        print(f"  {n}x {path} methods={methods}")

# simulate old key: full URL would explode
old_urls = set()
for t in targets:
    old_urls.add((t["method"], t["url"]))
print(f"unique (method,url) now: {len(old_urls)}")

# show sample sqli-related targets
print("\nsqli-related targets:")
for t in targets:
    if "sqli" in t["url"]:
        print(f"  [{t['method']}] {t['url']}")
