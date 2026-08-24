import argparse

DEFAULT_CONFIG = {
    "depth": 2,
    "threads": 10,
    "rate": 10,
    "burst": 20,
    "jitter": 0.2,
    "timeout": 10,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "proxy": None,
    "output": "report",
    "allow_external": False,
    "js_render": False,
    "login": None,
    "headers": {},
    "cookies": {},
    "verify_ssl": False,
    "max_urls": 500,
    "skip_params": [],
    "fixed_delay": 0.0,
}

def parse_args():
    parser = argparse.ArgumentParser(description="Web漏洞扫描器")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("--depth", type=int, default=DEFAULT_CONFIG["depth"])
    parser.add_argument("--threads", type=int, default=DEFAULT_CONFIG["threads"])
    parser.add_argument("--rate", type=float, default=DEFAULT_CONFIG["rate"])
    parser.add_argument("--burst", type=int, default=DEFAULT_CONFIG["burst"])
    parser.add_argument("--jitter", type=float, default=DEFAULT_CONFIG["jitter"])
    parser.add_argument("--fixed-delay", type=float, default=DEFAULT_CONFIG["fixed_delay"])
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
    parser.add_argument("--skip-params", nargs="*", default=[], help="额外跳过的参数名正则列表")
    parser.add_argument("--list-plugins", action="store_true", help="列出所有插件")
    parser.add_argument("--only-plugins", help="逗号分隔的插件名称，只运行这些插件")
    parser.add_argument("--exclude-plugins", help="逗号分隔的插件名称，跳过这些插件")
    args = parser.parse_args()
    return args