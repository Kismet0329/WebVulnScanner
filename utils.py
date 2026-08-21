# utils.py
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import hashlib
import re
from bs4 import BeautifulSoup

def normalize_url(url):
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if netloc.endswith(':80') and scheme == 'http':
        netloc = netloc[:-3]
    elif netloc.endswith(':443') and scheme == 'https':
        netloc = netloc[:-4]
    path = parsed.path
    query = parsed.query
    if query:
        params = sorted(parse_qsl(query, keep_blank_values=True))
        query = urlencode(params)
    return urlunparse((scheme, netloc, path, parsed.params, query, ''))

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
    """
    从响应文本中提取用于比较的有意义内容，去除动态噪声。
    处理步骤：
    1. 删除 script/style/noscript 等标签内容
    2. 移除常见的动态模式（时间戳、随机字符串、CSRF token等）
    3. 提取纯文本并截断
    """
    if not resp_text:
        return ""
    soup = BeautifulSoup(resp_text, "lxml")
    for tag in soup(["script", "style", "noscript", "iframe", "head"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    
    # 移除常见动态模式
    # 1. Unix时间戳（10位或13位数字）
    text = re.sub(r'\b\d{10,13}\b', '', text)
    # 2. 常见随机token（32位或40位hex）
    text = re.sub(r'\b[0-9a-f]{32}\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\b[0-9a-f]{40}\b', '', text, flags=re.IGNORECASE)
    # 3. CSRF token 常见模式
    text = re.sub(r'name=["\']?csrf[^>]*value=["\'][^"\']*["\']', '', text, flags=re.IGNORECASE)
    # 4. 其他可能的动态内容可在此扩展
    
    # 压缩空白
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:max_length]