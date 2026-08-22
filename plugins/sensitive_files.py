from .base import ScannerPlugin
from urllib.parse import urljoin, urlparse

class SensitiveFilesPlugin(ScannerPlugin):
    name = "sensitive_files"
    description = "常见敏感文件与信息泄露检测"
    severity = "medium"

    # 文件路径 -> 内容特征关键词（使用列表，避免 None 解包）
    SENSITIVE_FILES = {
        "/.git/config": ["[core]", "repositoryformatversion"],
        "/.svn/entries": ["dir", "file"],
        "/.env": ["APP_ENV", "DB_PASSWORD", "SECRET_KEY"],
        "/robots.txt": ["User-agent", "Disallow"],
        "/crossdomain.xml": ["<cross-domain-policy>"],
        "/web.config": ["<configuration>", "connectionStrings"],
        "/phpinfo.php": ["PHP Version", "phpinfo"],
        "/server-status": ["Apache Server Status"],
        "/.DS_Store": ["Bud1"],
        "/.htaccess": ["AuthType", "RewriteEngine"],
        "/config.php.bak": ["<?php", "DB_"],
        "/database.sql": ["CREATE TABLE", "INSERT INTO"],
        "/wp-config.php.bak": ["DB_NAME", "DB_USER"],
        "/adminer.php": ["Adminer"],
        "/.gitignore": ["*.log", "node_modules"],
        "/sitemap.xml": ["<urlset"],
    }

    def check_get(self, url):
        # 仅测试根域名和主路径，避免拼接出奇怪 URL
        base = url.rstrip('/')
        candidates = [base]
        # 添加父目录（最多一层，防止过度拼接）
        parsed = urlparse(base)
        path = parsed.path
        if path and path != '/':
            parent = base.rsplit('/', 1)[0]
            candidates.append(parent)

        for path_url in candidates:
            for file_path, keywords in self.SENSITIVE_FILES.items():
                test_url = path_url + file_path
                resp = self.safe_request("GET", test_url, timeout=10)
                if resp and resp.status_code == 200:
                    content = resp.text
                    # 使用关键字列表逐一检查
                    if any(k in content for k in keywords):
                        return self._build_result(
                            "sensitive_file",
                            f"发现敏感文件: {file_path}",
                            {"url": test_url, "evidence": content[:200]}
                        )
        return False, {}