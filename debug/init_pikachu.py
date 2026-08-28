import re
import requests

BASE = "http://192.168.222.134:8765"
s = requests.Session()
r = s.post(f"{BASE}/install.php", data={"submit": "1"}, timeout=60)
print("install status", r.status_code, "len", len(r.text))
notices = re.findall(r"class='notice'[^>]*>([^<]+)", r.text)
print("notices:", notices[:15])
print("success markers:", ("成功" in r.text), ("notice" in r.text))

for path in [
    "/vul/sqli/sqli_search.php",
    "/vul/xss/xss_reflected_get.php",
    "/vul/rce/rce_ping.php",
]:
    resp = s.get(BASE + path, timeout=30)
    print(path, resp.status_code, len(resp.text), "form" in resp.text.lower())
