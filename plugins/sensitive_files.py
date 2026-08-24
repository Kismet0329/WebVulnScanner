from .base import ScannerPlugin
from urllib.parse import urljoin, urlparse


class SensitiveFilesPlugin(ScannerPlugin):
    name = "sensitive_files"
    description = "常见敏感文件与信息泄露检测"
    severity = "medium"

    # 敏感文件路径 -> 内容特征关键字（必须全部出现，避免通用词误报）
    SENSITIVE_FILES = {
        "/.git/config": ["[core]", "repositoryformatversion"],
        "/.svn/entries": ["svn:entries", "dir\n"],
        "/.svn/wc.db": ["SQLite format", "PRAGMA"],
        "/.env": ["APP_ENV", "DB_PASSWORD"],
        "/robots.txt": ["User-agent:", "Disallow:"],
        "/crossdomain.xml": ["<cross-domain-policy>"],
        "/web.config": ["<configuration>", "connectionStrings"],
        "/phpinfo.php": ["PHP Version", "phpinfo()"],
        "/server-status": ["Apache Server Status", "Server uptime"],
        "/.DS_Store": ["Bud1", "Bud2"],
        "/.htaccess": ["AuthType", "RewriteEngine"],
        "/config.php.bak": ["<?php", "DB_"],
        "/database.sql": ["CREATE TABLE", "INSERT INTO"],
        "/wp-config.php.bak": ["DB_NAME", "DB_USER"],
        "/adminer.php": ["Adminer", "adminer.php"],
        "/.gitignore": ["*.log", "node_modules"],
        "/sitemap.xml": ["<urlset", "<url>"],
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 实例级去重：避免对同一敏感文件重复检测
        self._reported_files = set()

    def check_get(self, url):
        # 敏感文件位于站点根目录，使用 urljoin 正确拼接
        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}"

        for file_path, keywords in self.SENSITIVE_FILES.items():
            # 跳过已检测并上报过的文件
            if file_path in self._reported_files:
                continue
            test_url = urljoin(root + "/", file_path.lstrip("/"))
            resp = self.safe_request("GET", test_url, timeout=10)
            if resp and resp.status_code == 200:
                content = resp.text
                # 所有关键字都必须出现，降低误报
                if all(k in content for k in keywords):
                    self._reported_files.add(file_path)
                    return True, self._build_result(
                        "sensitive_file",
                        f"发现敏感文件: {file_path}",
                        {"url": test_url, "evidence": content[:200]},
                    )
        return False, {}

    def check_post(self, url, params):
        return False, {}
