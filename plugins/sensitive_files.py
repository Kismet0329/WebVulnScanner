# plugins/sensitive_files.py
from .base import ScannerPlugin
from urllib.parse import urljoin, urlparse

class SensitiveFilesPlugin(ScannerPlugin):
    name = "sensitive_files"
    description = "常见敏感文件与信息泄露检测"
    severity = "medium"

    SENSITIVE_FILES = {
        "/.git/config": ["[core]", "repositoryformatversion"],
        "/.svn/entries": ["dir", "file"],
        "/.env": ["APP_ENV", "DB_PASSWORD", "SECRET_KEY"],
        "/robots.txt": None,
        "/crossdomain.xml": ["<cross-domain-policy>"],
        "/web.config": ["<configuration>", "connectionStrings"],
        "/phpinfo.php": ["PHP Version", "phpinfo"],
        "/server-status": ["Apache Server Status"],
        "/.DS_Store": ["Bud1"],
        "/.htaccess": ["AuthType", "RewriteEngine"],
        "/.bash_history": ["#", "cd "],
        "/config.php.bak": ["<?php", "DB_"],
        "/database.sql": ["CREATE TABLE", "INSERT INTO"],
        "/wp-config.php.bak": ["DB_NAME", "DB_USER"],
        "/adminer.php": ["Adminer"],
        "/.gitignore": ["*.log", "node_modules"],
        "/sitemap.xml": ["<urlset"],
        "/backup.zip": None,
    }

    def check_get(self, url):
        base = url.rstrip('/')
        paths_to_test = set()
        paths_to_test.add(base)

        # 正确获取路径
        parsed = urlparse(base)
        path = parsed.path
        parts = path.split('/')
        for i in range(len(parts)-1, -1, -1):
            dir_url = urljoin(base, "/".join(parts[:i]) + "/")
            paths_to_test.add(dir_url.rstrip('/'))

        for path_url in paths_to_test:
            for file_path, signatures in self.SENSITIVE_FILES.items():
                test_url = path_url + file_path if not path_url.endswith(file_path) else path_url
                resp = self.safe_request("GET", test_url, timeout=10)
                if resp and resp.status_code == 200:
                    content = resp.text
                    if file_path == "/robots.txt":
                        if "User-agent" in content or "Disallow" in content:
                            return self._build_result(
                                "sensitive_file",
                                f"发现敏感文件: {file_path}",
                                {"url": test_url, "content": content[:100]}
                            )
                    elif signatures:
                        if any(sig in content for sig in signatures):
                            return self._build_result(
                                "sensitive_file",
                                f"发现敏感文件: {file_path}",
                                {"url": test_url, "evidence": content[:200]}
                            )
                    else:
                        if "text" in resp.headers.get("Content-Type", "") or len(content) > 0:
                            return self._build_result(
                                "sensitive_file",
                                f"发现可疑文件: {file_path}",
                                {"url": test_url, "size": len(content)}
                            )
        return False, {}