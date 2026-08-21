# plugins/sensitive_files.py
from .base import ScannerPlugin
from urllib.parse import urljoin

class SensitiveFilesPlugin(ScannerPlugin):
    name = "sensitive_files"
    description = "常见敏感文件与信息泄露检测"
    severity = "medium"

    # 文件路径 -> 内容特征关键词
    SENSITIVE_FILES = {
        "/.git/config": ["[core]", "repositoryformatversion"],
        "/.svn/entries": ["dir", "file"],
        "/.env": ["APP_ENV", "DB_PASSWORD", "SECRET_KEY"],
        "/robots.txt": None,  # 任何内容都算，但需要特殊判断
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
        "/backup.zip": None,  # 需要检查Content-Type
    }

    def check_get(self, url):
        base = url.rstrip('/')
        # 测试根路径及每个目录层级
        paths_to_test = set()
        paths_to_test.add(base)
        # 添加父路径
        parts = urlparse(base).path.split('/')
        for i in range(len(parts)-1, -1, -1):
            dir_url = urljoin(base, "/".join(parts[:i]) + "/")
            paths_to_test.add(dir_url.rstrip('/'))

        for path_url in paths_to_test:
            for file_path, signatures in self.SENSITIVE_FILES.items():
                test_url = path_url + file_path if not path_url.endswith(file_path) else path_url
                resp = self.safe_request("GET", test_url, timeout=10)
                if resp and resp.status_code == 200:
                    content = resp.text
                    # 对于robots.txt特殊处理
                    if file_path == "/robots.txt":
                        if "User-agent" in content or "Disallow" in content:
                            return self._build_result(
                                "sensitive_file",
                                f"发现敏感文件: {file_path}",
                                {"url": test_url, "content": content[:100]}
                            )
                    # 其他文件必须包含特征
                    elif signatures:
                        if any(sig in content for sig in signatures):
                            return self._build_result(
                                "sensitive_file",
                                f"发现敏感文件: {file_path}",
                                {"url": test_url, "evidence": content[:200]}
                            )
                    else:
                        # 无特征要求，但检查Content-Type
                        if "text" in resp.headers.get("Content-Type", "") or len(content) > 0:
                            return self._build_result(
                                "sensitive_file",
                                f"发现可疑文件: {file_path}",
                                {"url": test_url, "size": len(content)}
                            )
        return False, {}