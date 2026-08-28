"""对比旧/新去重逻辑在 Mock Pikachu 扫描结果上的效果。"""
import json
import sys
from collections import Counter
from urllib.parse import urlparse


def old_dedup_key(r):
    evidence = r.get("evidence") or {}
    ev_url = evidence.get("url") if isinstance(evidence, dict) else None
    primary_url = ev_url or r.get("url", "")
    return (primary_url, r.get("plugin", ""), r.get("type", ""))


def analyze(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    results = data.get("results", [])
    print(f"报告文件: {path}")
    print(f"报告中漏洞数（新去重后）: {data.get('total_vulns')} / {len(results)}")

    old_seen = set()
    old_unique = []
    for r in results:
        k = old_dedup_key(r)
        if k not in old_seen:
            old_seen.add(k)
            old_unique.append(r)
    # 新去重已在 scanner 内完成；这里用结果再按「路径+插件+类型+参数」检查是否还有重复
    from utils import result_dedup_key, deduplicate_results

    again = deduplicate_results(results)
    print(f"再按新键去重: {len(again)}（应为 {len(results)}，否则仍有漏网）")

    # 按路径统计
    by_path_plugin = Counter()
    for r in results:
        path_only = urlparse(r.get("url", "")).path
        param = (r.get("evidence") or {}).get("param", "")
        by_path_plugin[(path_only, r.get("plugin"), param)] += 1

    dups = {k: v for k, v in by_path_plugin.items() if v > 1}
    print(f"同路径+插件+参数出现多次: {len(dups)} 组")
    for k, v in sorted(dups.items(), key=lambda x: -x[1])[:10]:
        print(f"  {v}x  {k}")

    print("\n漏洞清单:")
    for r in results:
        param = (r.get("evidence") or {}).get("param", "-")
        print(f"  [{r.get('plugin')}] {r.get('type')} param={param} url={r.get('url')}")


if __name__ == "__main__":
    analyze(sys.argv[1] if len(sys.argv) > 1 else "report_pikachu_mock.json")
