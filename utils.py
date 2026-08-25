# utils.py
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import hashlib
import re
from bs4 import BeautifulSoup

def normalize_url(url):
    """规范化 URL：小写 host、排序 query、去掉 fragment（#...）。"""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if netloc.endswith(':80') and scheme == 'http':
        netloc = netloc[:-3]
    elif netloc.endswith(':443') and scheme == 'https':
        netloc = netloc[:-4]
    path = parsed.path or "/"
    if path.endswith("/#"):
        path = path[:-1]
    query = parsed.query
    if query:
        params = sorted(parse_qsl(query, keep_blank_values=True))
        query = urlencode(params)
    # fragment 一律丢弃：浏览器不会发给服务器，带 # 只会干扰去重/日志
    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def strip_url_fragment(url):
    """仅去掉 fragment，保留其余部分（请求前调用）。"""
    if not url or "#" not in url:
        return url
    return url.split("#", 1)[0]

def is_same_domain(url1, url2):
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    return p1.netloc == p2.netloc

def response_similarity(text1, text2):
    import difflib
    return difflib.SequenceMatcher(None, text1, text2).ratio()

def hash_content(content):
    return hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()

def get_meaningful_content(resp_text, max_length=500):
    if not resp_text:
        return ""
    soup = BeautifulSoup(resp_text, "lxml")
    for tag in soup(["script", "style", "noscript", "iframe", "head"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    text = re.sub(r'\b\d{10,13}\b', '', text)
    text = re.sub(r'\b[0-9a-f]{32}\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\b[0-9a-f]{40}\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'name=["\']?csrf[^>]*value=["\'][^"\']*["\']', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:max_length]