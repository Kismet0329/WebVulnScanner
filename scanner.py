import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse as _urlparse

from config import parse_args, DEFAULT_CONFIG
from http_client import HttpClient
from rate_limiter import TokenBucket
from crawler import Crawler
from plugin_loader import load_plugins
from reporter import generate_html_report, generate_json_report
from utils import deduplicate_results


def setup_logging(log_file="scanner.log"):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    return logging.getLogger("WebVulnScanner")


def _probe_session(url, args, client, logger):
    """会话有效性预检。

    探测目标 URL，判断当前 cookie/登录态是否真正生效。
    若被重定向到登录页或返回登录表单，说明会话失效，
    此时所有受保护页面的 param 级插件都会漏报，必须明确警告。
    """
    active_cookies = {c.name: c.value for c in client.session.cookies}
    if active_cookies:
        cookie_summary = {
            k: (v[:16] + "...") if len(v) > 16 else v for k, v in active_cookies.items()
        }
        logger.info(f"当前生效 cookies: {cookie_summary}")
    else:
        logger.warning("当前无任何 cookie，若目标需要登录将漏扫受保护页面")

    try:
        resp = client.get(url, allow_redirects=False)
    except Exception as e:
        logger.warning(f"会话预检请求失败: {e}")
        return False

    if resp is None:
        logger.warning("会话预检：服务器无响应")
        return False

    location = resp.headers.get("Location", "")
    body_lower = resp.text[:2000].lower() if resp.text else ""

    is_login_redirect = (
        resp.status_code in (301, 302, 303, 307, 308)
        and any(kw in location.lower() for kw in ("login", "signin", "auth", "account/login"))
    )
    is_login_form = any(
        kw in body_lower
        for kw in (
            "user_token",
            'name="username"',
            'name="password"',
            "please enter your credentials",
            "用户登录",
            "登录",
        )
    )

    if is_login_redirect:
        logger.error(
            f"会话预检失败：访问 {url} 被重定向到 {location}。"
            "当前 cookie/登录态已失效，受保护页面全部漏报。"
            "请重新获取有效 cookie（浏览器刷新目标页面后从 DevTools 复制），"
            "或改用 --login-url/--username/--password 自动登录。"
            "注意 DVWA 必须带小写 security=low（不是 Security=low）。"
        )
        return False
    if is_login_form and not args.login_url:
        logger.error(
            f"会话预检失败：访问 {url} 返回登录表单。"
            "当前 cookie 已失效或未提供，受保护页面全部漏报。"
            "请重新获取有效 cookie 或使用 --login-url 参数。"
        )
        return False

    logger.info(f"会话预检通过：访问 {url} 返回 {resp.status_code}（长度 {len(resp.text)}）")
    return True


def _count_param_targets(targets):
    """统计带可测参数的目标数量（GET query 或 POST body）。"""
    n = 0
    for t in targets:
        if t.get("method") == "POST" and t.get("params"):
            n += 1
            continue
        if t.get("method") == "GET" and _urlparse(t.get("url", "")).query:
            n += 1
    return n


def main():
    args = parse_args()
    logger = setup_logging()

    if args.list_plugins:
        plugin_classes = load_plugins()
        print("可用插件:")
        for cls in plugin_classes:
            scope = getattr(cls, "scope", "param")
            print(f"- {cls.name}: {cls.description} (severity: {cls.severity}, scope: {scope})")
        return

    only_plugins = args.only_plugins.split(",") if args.only_plugins else None
    exclude_plugins = args.exclude_plugins.split(",") if args.exclude_plugins else None

    client = HttpClient(
        proxy=args.proxy,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        user_agent=DEFAULT_CONFIG["user_agent"],
        headers=args.header,
        cookies=args.cookie,
    )

    # DVWA：纠正 Security→security，并设置安全等级。
    # 这是「会话有效却只扫到 1 个漏洞（robots.txt）」的最常见根因之一。
    if args.security_level and args.security_level != "none":
        client.ensure_dvwa_security(args.security_level)

    if args.login_url:
        if not client.login(
            args.login_url,
            args.username,
            args.password,
            args.username_field,
            args.password_field,
        ):
            logger.warning("登录可能失败，继续扫描...")
        else:
            logger.info(f"登录成功: {args.login_url}")
            cookie_names = [c.name for c in client.session.cookies]
            logger.info(f"登录后 cookies: {cookie_names}")
            if args.security_level and args.security_level != "none":
                client.ensure_dvwa_security(args.security_level)

    session_ok = _probe_session(args.url, args, client, logger)

    rate_limiter = TokenBucket(rate=args.rate, capacity=args.burst, jitter=args.jitter)

    plugin_classes = load_plugins(only=only_plugins, exclude=exclude_plugins)
    plugins = []
    for cls in plugin_classes:
        plugins.append(
            cls(
                http_client=client,
                rate_limiter=rate_limiter,
                logger=logger,
                skip_params=args.skip_params,
                fixed_delay=args.fixed_delay,
            )
        )
    logger.info(f"已加载插件: {[p.name for p in plugins]}")

    crawler = Crawler(
        client,
        rate_limiter,
        depth=args.depth,
        max_urls=args.max_urls,
        allow_external=args.allow_external,
        js_render=args.js_render,
        logger=logger,
    )
    targets = crawler.crawl(args.url)
    logger.info(f"爬取完成，待扫描目标数量: {len(targets)}")
    for t in targets:
        logger.debug(f"TARGET: [{t['method']}] {t['url']} params={t.get('params')}")

    parsed_root = _urlparse(args.url)
    site_target = {
        "url": f"{parsed_root.scheme}://{parsed_root.netloc}/",
        "method": "GET",
        "params": None,
    }

    # 会话失效时爬虫会跳过所有登录重定向页，targets 可能为空；
    # 仍继续跑站点级插件（robots.txt 等不依赖登录），避免“无报告可看”。
    if not targets:
        logger.warning(
            "没有发现可扫描的业务 URL（常见于登录态失效）。"
            "将仅运行站点级插件。"
        )
        if not session_ok:
            logger.error("会话预检未通过，请先修复登录态后再扫描受保护页面。")

    auth_keywords = ("login", "signin", "signup", "register", "auth")
    biz_keywords = (
        "user", "admin", "api", "v1", "product", "order", "profile",
        "account", "dashboard", "manage", "console", "portal", "vulnerabilit",
    )
    total_t = len(targets) or 1
    auth_count = 0
    biz_count = 0
    for t in targets:
        p = _urlparse(t["url"]).path.lower()
        if any(k in p for k in auth_keywords):
            auth_count += 1
        if any(k in p for k in biz_keywords):
            biz_count += 1
    auth_ratio = auth_count / total_t if targets else 1.0
    has_auth = bool(args.login_url) or bool(args.cookie)
    if not has_auth and (not targets or auth_ratio > 0.3 or biz_count == 0):
        logger.warning(
            f"检测到登录页占比 {auth_ratio:.0%}，业务路径 {biz_count} 个；"
            "目标可能需要登录，未登录将漏扫受保护页面。"
            "建议加 --login-url/--username/--password 或 --cookie 参数。"
        )
    elif has_auth and (not targets or auth_ratio > 0.3):
        logger.info(
            f"登录页占比 {auth_ratio:.0%}，已提供认证凭据；"
            "若仍漏扫受保护页面，请检查 --cookie 值或登录凭据是否正确。"
        )

    param_targets = _count_param_targets(targets)
    logger.info(f"带参数可测目标: {param_targets}/{len(targets)}")
    if param_targets == 0:
        logger.error(
            "没有任何带查询参数/POST 参数的目标。"
            "参数级漏洞（SQLi/XSS/命令注入等）将全部漏报，通常只会剩下 robots.txt。"
            "常见原因：1) cookie/登录失效 2) DVWA 未设 security=low 3) 爬取深度不够。"
            "请使用: --login-url ... --username admin --password password "
            "或 --cookie \"PHPSESSID=xxx; security=low\""
        )
        if not session_ok:
            logger.error("会话预检未通过，强烈建议先修复登录态再扫描。")

    results = []
    site_plugins = [p for p in plugins if getattr(p, "scope", "param") == "site"]
    url_plugins = [p for p in plugins if getattr(p, "scope", "param") == "url"]
    param_plugins = [p for p in plugins if getattr(p, "scope", "param") == "param"]

    submitted_site_plugins = set()

    def _has_path(target):
        p = _urlparse(target["url"]).path
        return bool(p) and not p.endswith("/")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for plugin in site_plugins:
            if plugin.name in submitted_site_plugins:
                continue
            submitted_site_plugins.add(plugin.name)
            future = executor.submit(plugin.check, site_target)
            futures[future] = (plugin.name, site_target)

        for target in targets:
            if not _has_path(target):
                continue
            for plugin in url_plugins:
                future = executor.submit(plugin.check, target)
                futures[future] = (plugin.name, target)

        for target in targets:
            for plugin in param_plugins:
                future = executor.submit(plugin.check, target)
                futures[future] = (plugin.name, target)

        for future in as_completed(futures):
            plugin_name, target = futures[future]
            try:
                found, result = future.result()
                if found:
                    result["url"] = target["url"]
                    result["method"] = target["method"]
                    results.append(result)
                    logger.warning(
                        f"发现漏洞: {plugin_name} - {target['url']} ({result['severity']})"
                    )
            except Exception as e:
                logger.error(f"插件 {plugin_name} 在 {target['url']} 出错: {e}", exc_info=True)

    unique_results = deduplicate_results(results)
    if len(results) != len(unique_results):
        logger.info(
            f"去重: {len(results)} 条原始结果 -> {len(unique_results)} 条"
            "（按路径+插件+类型+参数名合并）"
        )

    logger.info(f"扫描完成，发现 {len(unique_results)} 个漏洞（去重后）")
    if len(unique_results) <= 1 and param_targets == 0:
        logger.warning(
            "结果极少且无参数目标，极像会话/DVWA security 配置问题，请复查登录态与 security=low。"
        )

    html_file = generate_html_report(unique_results, args.url, f"{args.output}.html")
    json_file = generate_json_report(unique_results, args.url, f"{args.output}.json")
    logger.info(f"报告已保存: {html_file}, {json_file}")

    client.close()


if __name__ == "__main__":
    main()
