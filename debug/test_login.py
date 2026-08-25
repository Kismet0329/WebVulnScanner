import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""验证 http_client.login 能成功登录 DVWA

用法：
    # 假设 DVWA 监听在 127.0.0.1:42001
    python test_login.py --url http://127.0.0.1:42001/login.php --user admin --pass password

    # 如果不知道字段名，默认 username/password
    python test_login.py --url http://127.0.0.1:42001/login.php --user admin --pass password
"""
import argparse
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

from http_client import HttpClient


def main():
    parser = argparse.ArgumentParser(description="验证 DVWA 登录")
    parser.add_argument("--url", required=True, help="登录页 URL")
    parser.add_argument("--user", required=True)
    parser.add_argument("--pass", dest="password", required=True)
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")
    args = parser.parse_args()

    client = HttpClient(timeout=15, verify_ssl=False)

    print(f"[*] 尝试登录 {args.url} (user={args.user})")
    ok = client.login(
        args.url, args.user, args.password,
        args.username_field, args.password_field,
    )
    print(f"\n[*] 登录结果: {'成功' if ok else '失败'}")

    # 打印当前 session cookies 便于确认
    print("\n[*] 当前 session cookies:")
    for c in client.session.cookies:
        print(f"    {c.name} = {c.value[:30]}{'...' if len(c.value) > 30 else ''}")

    # 验证能否访问受保护页面：访问 vulnerabilities/exec/ 看是否被重定向到 login
    if ok:
        print("\n[*] 验证受保护页面访问：")
        test_url = args.url.rsplit("/", 1)[0] + "/vulnerabilities/exec/"
        print(f"    访问 {test_url}")
        try:
            resp = client.get(test_url)
            # 被重定向到 login.php 说明登录态未生效
            redirected_to_login = (
                "login.php" in resp.url
                or "login" in resp.text.lower()[:500]
            )
            if redirected_to_login:
                print(f"    [!] 仍被重定向到登录页（status={resp.status_code}），登录态未生效")
            else:
                print(f"    [+] 访问成功（status={resp.status_code}），登录态生效")
                print(f"    最终 URL: {resp.url}")
        except Exception as e:
            print(f"    [!] 访问异常: {e}")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

