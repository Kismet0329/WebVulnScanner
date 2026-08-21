# config.py
import argparse

DEFAULT_CONFIG = {
    "depth": 2,                 # 爬虫深度
    "threads": 10,              # 扫描线程数
    "crawl_threads": 5,         # 爬虫线程数
    "rate": 10,                 # 每秒请求数（令牌桶速率）
    "burst": 20,                # 令牌桶容量（突发请求数）
    "timeout": 10,              # 请求超时（秒）
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "proxy": None,              # 代理，如 http://127.0.0.1:8080
    "output": "report",         # 报告文件名前缀
    "allow_external": False,    # 是否允许爬取外域链接
    "js_render": False,         # 是否启用JS渲染（需要playwright）
    "login": None,              # 登录信息：url,username,password,username_field,password_field
    "headers": {},              # 自定义请求头
    "cookies": {},              # 自定义Cookie
    "verify_ssl": False,        # 是否验证SSL证书
    "max_urls": 500,            # 最大爬取URL数量
}

def parse_args():
    parser = argparse.ArgumentParser(description="Web漏洞扫描器")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("--depth", type=int, default=DEFAULT_CONFIG["depth"])
    parser.add_argument("--threads", type=int, default=DEFAULT_CONFIG["threads"])
    parser.add_argument("--rate", type=float, default=DEFAULT_CONFIG["rate"])
    parser.add_argument("--burst", type=int, default=DEFAULT_CONFIG["burst"])
    parser.add_argument("--timeout", type=int, default=DEFAULT_CONFIG["timeout"])
    parser.add_argument("--proxy", default=None)
    parser.add_argument("-o", "--output", default=DEFAULT_CONFIG["output"])
    parser.add_argument("--allow-external", action="store_true")
    parser.add_argument("--js-render", action="store_true")
    parser.add_argument("--login-url", help="登录页面URL")
    parser.add_argument("--username", help="登录用户名")
    parser.add_argument("--password", help="登录密码")
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")
    parser.add_argument("--cookie", action="append", help="自定义Cookie，格式 key=value")
    parser.add_argument("--header", action="append", help="自定义Header，格式 key:value")
    parser.add_argument("--max-urls", type=int, default=DEFAULT_CONFIG["max_urls"])
    parser.add_argument("--list-plugins", action="store_true", help="列出所有插件")
    parser.add_argument("--only-plugins", help="逗号分隔的插件名称，只运行这些插件")
    parser.add_argument("--exclude-plugins", help="逗号分隔的插件名称，跳过这些插件")
    parser.add_argument("--skip-params", nargs="*", default=[], help="额外跳过的参数名正则列表")
    parser.add_argument("--fixed-delay", type=float, default=0.0, help="每个请求的固定延迟（秒）")
    parser.add_argument("--jitter", type=float, default=0.2, help="限速抖动比例（0-1）")
    args = parser.parse_args()
    return args