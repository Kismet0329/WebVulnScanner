import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""调试：直接构造 form HTML 看 crawler 如何解析"""
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode

html = """<html><body>
<form action="/vulnerabilities/sqli/" method="get">
    ID: <input type="text" name="id" value="1">
    <input type="submit">
</form>
</body></html>"""

soup = BeautifulSoup(html, "lxml")
for form in soup.find_all("form"):
    action = form.get("action", "")
    method = form.get("method", "get").lower()
    full_action = urljoin("http://127.0.0.1:8888/vulnerabilities/", action) if action else "http://127.0.0.1:8888/vulnerabilities/"
    inputs = form.find_all(["input", "textarea", "select"])
    params = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            params[name] = inp.get("value", "")
    print(f"method={method} action={full_action} params={params}")
    if method == "get" and params:
        full_url_with_params = full_action + "?" + urlencode(params)
        print(f"  -> {full_url_with_params}")

