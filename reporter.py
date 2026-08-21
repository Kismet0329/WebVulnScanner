# reporter.py
import json
from datetime import datetime
from jinja2 import Template, Environment, FileSystemLoader

def generate_html_report(results, target, output_file="report.html", template_dir=None):
    """生成HTML报告"""
    # 可以自定义模板，这里使用内嵌模板
    html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Web漏洞扫描报告 - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; font-weight: bold; }
        .medium { color: #ffcc00; font-weight: bold; }
        .low { color: #0066cc; }
        .info { color: #666; }
        .detail { max-width: 500px; word-wrap: break-word; }
    </style>
</head>
<body>
    <h1>Web漏洞扫描报告</h1>
    <p>目标：<strong>{{ target }}</strong></p>
    <p>扫描时间：{{ scan_time }}</p>
    <p>漏洞总数：{{ results|length }}</p>
    
    <h2>漏洞列表</h2>
    {% if results %}
    <table>
        <tr>
            <th>#</th>
            <th>插件</th>
            <th>漏洞类型</th>
            <th>严重程度</th>
            <th>URL</th>
            <th>详情</th>
            <th>证据</th>
        </tr>
        {% for r in results %}
        <tr>
            <td>{{ loop.index }}</td>
            <td>{{ r.plugin }}</td>
            <td>{{ r.type }}</td>
            <td class="{{ r.severity }}">{{ r.severity }}</td>
            <td>{{ r.url }}</td>
            <td class="detail">{{ r.detail }}</td>
            <td class="detail"><pre>{{ r.evidence | tojson(indent=2) }}</pre></td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p>未发现漏洞。</p>
    {% endif %}
</body>
</html>
"""
    template = Template(html_template)
    html_content = template.render(
        target=target,
        scan_time=datetime.now().isoformat(),
        results=results
    )
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return output_file

def generate_json_report(results, target, output_file="report.json"):
    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "total_vulns": len(results),
        "results": results
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False, default=str)
    return output_file