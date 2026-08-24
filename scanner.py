import sys
import logging
from config import parse_args, DEFAULT_CONFIG
from http_client import HttpClient
from rate_limiter import TokenBucket
from crawler import Crawler
from plugin_loader import load_plugins
from reporter import generate_html_report, generate_json_report
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import normalize_url

def setup_logging(log_file="scanner.log"):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("WebVulnScanner")

def main():
    args = parse_args()
    logger = setup_logging()

    if args.list_plugins:
        plugin_classes = load_plugins()
        print("可用插件:")
        for cls in plugin_classes:
            print(f"- {cls.name}: {cls.description} (severity: {cls.severity})")
        return

    only_plugins = args.only_plugins.split(',') if args.only_plugins else None
    exclude_plugins = args.exclude_plugins.split(',') if args.exclude_plugins else None

    client = HttpClient(
        proxy=args.proxy,
        timeout=args.timeout,
        verify_ssl=DEFAULT_CONFIG["verify_ssl"],
        user_agent=DEFAULT_CONFIG["user_agent"],
        headers=args.header,
        cookies=args.cookie
    )

    if args.login_url:
        if not client.login(args.login_url, args.username, args.password,
                            args.username_field, args.password_field):
            logger.warning("登录可能失败，继续扫描...")

    rate_limiter = TokenBucket(rate=args.rate, capacity=args.burst, jitter=args.jitter)

    plugin_classes = load_plugins(only=only_plugins, exclude=exclude_plugins)
    plugins = []
    for cls in plugin_classes:
        plugins.append(cls(
            http_client=client,
            rate_limiter=rate_limiter,
            logger=logger,
            skip_params=args.skip_params,
            fixed_delay=args.fixed_delay
        ))
    logger.info(f"已加载插件: {[p.name for p in plugins]}")

    crawler = Crawler(
        client, rate_limiter,
        depth=args.depth,
        max_urls=args.max_urls,
        allow_external=args.allow_external,
        js_render=args.js_render,
        logger=logger
    )
    targets = crawler.crawl(args.url)
    logger.info(f"爬取完成，待扫描目标数量: {len(targets)}")

    if not targets:
        logger.warning("没有发现可扫描的URL，退出。")
        return

    results = []
    # 按 scope 路由提交任务：
    #   site  - 整个站点只对首个 target 提交一次（结果代表整个站点）
    #   url   - 每个有 path 的 target 提交一次
    #   param - 每个 target 都提交（参数测试在插件内部完成）
    from urllib.parse import urlparse as _urlparse
    site_plugins = [p for p in plugins if getattr(p, "scope", "param") == "site"]
    url_plugins = [p for p in plugins if getattr(p, "scope", "param") == "url"]
    param_plugins = [p for p in plugins if getattr(p, "scope", "param") == "param"]

    submitted_site_plugins = set()
    # 用于站点级插件的目标：选一个能代表整个站点的 URL（用根 URL）
    parsed_root = _urlparse(args.url)
    site_target = {
        "url": f"{parsed_root.scheme}://{parsed_root.netloc}/",
        "method": "GET",
        "params": None,
    }

    def _has_path(target):
        p = _urlparse(target["url"]).path
        return bool(p) and not p.endswith("/")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        # site 级：每个站点级插件仅提交一次
        for plugin in site_plugins:
            if plugin.name in submitted_site_plugins:
                continue
            submitted_site_plugins.add(plugin.name)
            future = executor.submit(plugin.check, site_target)
            futures[future] = (plugin.name, site_target)

        # url 级：每个有 path 的 target 提交一次
        for target in targets:
            if not _has_path(target):
                continue
            for plugin in url_plugins:
                future = executor.submit(plugin.check, target)
                futures[future] = (plugin.name, target)

        # param 级：每个 target 都提交
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
                    logger.warning(f"发现漏洞: {plugin_name} - {target['url']} ({result['severity']})")
            except Exception as e:
                logger.error(f"插件 {plugin_name} 在 {target['url']} 出错: {e}")

    seen = set()
    unique_results = []
    for r in results:
        # 优先使用证据 URL（如敏感文件自身的 URL）作为去重键，
        # 否则回退到被扫描页面 URL，避免同一发现被绑定到不同页面 URL 而重复上报
        evidence = r.get("evidence") or {}
        if isinstance(evidence, dict):
            ev_url = evidence.get("url")
        else:
            ev_url = None
        primary_url = ev_url or r.get("url", "")
        key = (primary_url, r["plugin"], r.get("type", ""))
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    logger.info(f"扫描完成，发现 {len(unique_results)} 个漏洞（去重后）")

    html_file = generate_html_report(unique_results, args.url, f"{args.output}.html")
    json_file = generate_json_report(unique_results, args.url, f"{args.output}.json")
    logger.info(f"报告已保存: {html_file}, {json_file}")

    client.close()

if __name__ == "__main__":
    main()