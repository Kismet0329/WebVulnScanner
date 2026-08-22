from .base import ScannerPlugin
from urllib.parse import urlparse
import re

class BackupFilesPlugin(ScannerPlugin):
    name = "backup_files"
    description = "备份文件泄露检测"
    severity = "medium"

    backup_extensions = [
        '.bak', '.backup', '.old', '.swp', '.save', '.orig', '.tmp',
        '.zip', '.tar', '.tar.gz', '.tgz', '.rar', '.7z', '.gz',
        '~', '.pyc', '.class', '.jar', '.war', '.sql', '.dump'
    ]
    source_patterns = [
        r'<\?php', r'import java', r'package ', r'using System',
        r'CREATE TABLE', r'INSERT INTO', r'class ', r'def ', r'function '
    ]

    def check_get(self, url):
        parsed = urlparse(url)
        path = parsed.path
        if not path or path.endswith('/'):
            return False, {}
        filename = path.split('/')[-1]
        if not filename:
            return False, {}
        for ext in self.backup_extensions:
            test_url = url + ext
            resp = self.safe_request("GET", test_url, timeout=10)
            if resp and resp.status_code == 200:
                content = resp.text
                if self._is_source_content(content, resp.headers.get("Content-Type", "")):
                    return True, self._build_result(
                        "backup_file",
                        f"发现备份文件: {test_url}",
                        {"url": test_url, "size": len(resp.content)}
                    )
        return False, {}

    def check_post(self, url, params):
        return False, {}

    def _is_source_content(self, content, content_type):
        if "text" in content_type:
            for pat in self.source_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    return True
        if content.startswith("PK\x03\x04") or content.startswith("\x1f\x8b"):
            return True
        return False