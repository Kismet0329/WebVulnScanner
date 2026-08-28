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


def normalize_path(url):
    """提取用于去重的路径（小写、去掉末尾斜杠）。"""
    if not url:
        return ""
    parsed = urlparse(normalize_url(url))
    return ((parsed.path or "/").rstrip("/") or "/").lower()


def target_dedup_key(method, url, params=None):
    """爬虫目标去重键：同一 method + 路径视为同一目标。

    Pikachu 等靶场常在菜单/iframe 中多次链接同一漏洞页：
    - 无 query / 有不同 query 值（name=test vs name=admin）
    - 空路径页与带默认参数的表单 GET
    这些都必须合并，否则会重复扫描。参数名差异通过升级保留“信息更全”的那条。
    """
    return (method.upper(), normalize_path(url))


def target_param_richness(method, url, params=None):
    """估计目标可测参数丰富度，用于合并时保留更好的那条。"""
    parsed = urlparse(normalize_url(url))
    if method.upper() == "GET":
        return len(parse_qsl(parsed.query, keep_blank_values=True))
    return len(params) if params else 0


def result_dedup_key(result):
    """漏洞结果去重键：路径 + 插件 + 类型 + 参数名。

    同一端点的 GET/POST 或不同 query 占位值触发的相同漏洞只保留一条。
    """
    evidence = result.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}

    param = evidence.get("param", "")
    url = (
        evidence.get("url")
        or evidence.get("evidence_url")
        or result.get("url", "")
    )
    path = normalize_path(url)
    return (path, result.get("plugin", ""), result.get("type", ""), param)


def deduplicate_results(results):
    """按 result_dedup_key 去重，保留首次出现的条目。"""
    seen = set()
    unique = []
    for item in results:
        key = result_dedup_key(item)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


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