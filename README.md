# WebVulnScanner

一个基于 Python 的插件化 Web 漏洞扫描器，支持多线程、速率控制、参数白名单、误报控制，输出 HTML/JSON 报告。适用于授权测试环境。

## 功能特性

- **插件化架构**：每个漏洞检测逻辑独立成类，支持动态加载，易于扩展。
- **多种漏洞检测插件**：
  - SQL 注入（布尔盲注、时间盲注、报错注入）
  - 反射型 XSS
  - 目录遍历
  - 本地文件包含（LFI）
  - 命令注入
  - SSRF（基于回显）
  - 水平越权（IDOR，基础版）
  - 未授权访问
  - 敏感文件泄露
  - 备份文件泄露
- **误报控制**：
  - 参数白名单：自动跳过 `csrf_token`、`timestamp`、`sign` 等无意义参数
  - 响应净化：移除动态内容（时间戳、随机 token）后再比较相似度
  - 多重验证：同一 payload 两次请求一致才确认
  - 响应相似度阈值判断
- **爬虫**：支持并发爬取、表单提取（GET/POST）、URL 去重、深度限制、外域过滤
- **限速与隐蔽**：令牌桶算法 + 随机抖动 + 固定延迟，降低被 WAF 拦截风险
- **报告**：生成专业的 HTML 报告和 JSON 报告，包含漏洞详情与证据
- **会话管理**：支持 Cookie、自定义 Header、代理、登录

## 安装

### 环境要求

- Python 3.8+
- pip

### 安装依赖

```bash
git clone https://github.com/Kismet0329/WebVulnScanner.git
cd WebVulnScanner
pip install -r requirements.txt