# WebVulnScanner

基于 Python 的插件化 Web 漏洞扫描器，支持多线程、速率控制、参数白名单与误报控制，输出 HTML/JSON 报告。

**仅用于授权测试环境（如自建 DVWA）。禁止对未授权目标扫描。**

## 功能特性

- **插件化架构**：漏洞检测逻辑独立成类，动态加载，易于扩展
- **检测插件**：SQLi、反射 XSS、目录遍历、LFI、命令注入、SSRF、IDOR、未授权访问、敏感文件、备份文件
- **误报控制**：参数白名单、响应净化、多重验证、相似度阈值、confidence 分级
- **爬虫**：并发爬取、表单提取、URL 去重、深度限制、外域过滤、跳过 logout、识别登录重定向
- **限速**：令牌桶 + 抖动 + 固定延迟
- **会话**：Cookie / Header / 代理 / 自动登录（含 CSRF）/ DVWA `security=low` 自动纠正

## 环境要求

- Python 3.8+
- pip

## 安装

```bash
git clone https://github.com/Kismet0329/WebVulnScanner.git
cd WebVulnScanner
python -m venv venv

# Windows
venv\Scripts\activate
# Linux / macOS
# source venv/bin/activate

pip install -r requirements.txt
```

可选 JS 渲染：

```bash
pip install playwright
playwright install chromium
```

## 快速开始

列出插件（无需 `-u`）：

```bash
python scanner.py --list-plugins
```

### 扫描本地 Mock DVWA

```bash
# 终端 1
python mock_dvwa_full.py --port 8888

# 终端 2：推荐用自动登录
python scanner.py -u http://127.0.0.1:8888/ \
  --login-url http://127.0.0.1:8888/login.php \
  --username admin --password password \
  -o report_dvwa
```

或使用 Cookie（**必须小写 `security=low`**）：

```bash
python scanner.py -u http://127.0.0.1:8888/ \
  --cookie "PHPSESSID=e8a5b6c2d4f0a8b2c4d6e8f0a2c4b6d8; security=low" \
  -o report_cookie
```

### 扫描真实 DVWA

```bash
python scanner.py -u http://127.0.0.1/DVWA/ \
  --login-url http://127.0.0.1/DVWA/login.php \
  --username admin --password password \
  --security-level low \
  -o report_dvwa
```

## 常见问题：为什么只扫到 1 个漏洞？

日志里若几乎只有 `sensitive_files` / `robots.txt`，通常是：

1. **登录态失效**：Cookie 过期或错误 → 受保护页全部 302 到登录页 → 参数插件无目标可测  
2. **`Security=low` 写成了大写**：真实 DVWA 只认小写 `security`；会话看起来正常，但漏洞页仍为 high/impossible，注入全部失败  
3. **未登录就扫**：请加 `--login-url` 或有效 `--cookie`

扫描器会自动把 `Security` 纠正为 `security`，并在登录后设置 `--security-level`（默认 `low`）。若仍只有 1 条结果，请查看日志中的「会话预检」与「带参数可测目标」提示。

## 主要参数

| 参数 | 说明 |
|------|------|
| `-u/--url` | 目标 URL |
| `--login-url` / `--username` / `--password` | 自动登录 |
| `--cookie` | 手动 Cookie（可多次或分号分隔） |
| `--security-level` | DVWA 等级：low/medium/high/impossible/none |
| `--threads` / `--rate` / `--depth` | 并发、限速、爬取深度 |
| `--only-plugins` / `--exclude-plugins` | 插件过滤 |
| `--verify-ssl` | 开启证书校验（默认关闭） |
| `--js-render` | Playwright 渲染 |
| `-o` | 报告文件名前缀 |

## 项目结构

```
scanner.py          # 入口
crawler.py          # 爬虫
http_client.py      # HTTP / 登录 / Cookie
plugins/            # 检测插件
reporter.py         # HTML/JSON 报告
mock_dvwa_full.py   # 本地靶场
debug/              # 调试脚本
tests/              # 单元测试
```

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 免责声明

本工具仅供安全研究与授权渗透测试使用。使用者须确保已获得目标系统书面授权，并对自身行为负责。
