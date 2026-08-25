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
    "security_level": "low",
}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Web漏洞扫描器（仅用于授权测试环境）",
    )
    parser.add_argument("-u", "--url", help="目标URL")
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
    parser.add_argument(
        "--js-render",
        action="store_true",
        help="启用 Playwright 渲染（需额外安装 playwright）",
    )
    parser.add_argument("--login-url", help="登录页面URL")
    parser.add_argument("--username", help="登录用户名")
    parser.add_argument("--password", help="登录密码")
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")
    parser.add_argument(
        "--cookie",
        action="append",
        help='自定义Cookie，格式 key=value；可多次或用分号：PHPSESSID=xxx; security=low',
    )
    parser.add_argument("--header", action="append", help="自定义Header，格式 key:value")
    parser.add_argument("--max-urls", type=int, default=DEFAULT_CONFIG["max_urls"])
    parser.add_argument("--skip-params", nargs="*", default=[], help="额外跳过的参数名正则列表")
    parser.add_argument("--list-plugins", action="store_true", help="列出所有插件（无需 -u）")
    parser.add_argument("--only-plugins", help="逗号分隔的插件名称，只运行这些插件")
    parser.add_argument("--exclude-plugins", help="逗号分隔的插件名称，跳过这些插件")
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        default=DEFAULT_CONFIG["verify_ssl"],
        help="校验证书（默认关闭，便于本地靶场）",
    )
    parser.add_argument(
        "--security-level",
        default=DEFAULT_CONFIG["security_level"],
        choices=["low", "medium", "high", "impossible", "none"],
        help="DVWA security Cookie 等级；默认 low。none 表示不自动设置",
    )
    args = parser.parse_args(argv)

    if args.list_plugins:
        return args
    if not args.url:
        parser.error("扫描时必须提供 -u/--url（仅 --list-plugins 时可省略）")
    return args
