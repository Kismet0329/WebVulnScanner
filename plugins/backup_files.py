# plugins/backup_files.py
from .base import ScannerPlugin
from urllib.parse import urlparse, urljoin
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
    # 源代码特征
    source_patterns = [
        r'<\?php', r'import java', r'package ', r'using System',
        r'CREATE TABLE', r'INSERT INTO', r'class ', r'def ', r'function '
    ]

    def check_get(self, url):
        parsed = urlparse(url)
        path = parsed.path
        if not path or path.endswith('/'):
            return False, {}
        # 测试当前路径文件名的备份
        filename = path.split('/')[-1]
        if not filename:
            return False, {}
        for ext in self.backup_extensions:
            test_url = url + ext  # 如 index.php.bak
            resp = self.safe_request("GET", test_url, timeout=10)
            if resp and resp.status_code == 200:
                content = resp.text
                # 检查是否包含源代码特征
                if self._is_source_content(content, resp.headers.get("Content-Type", "")):
                    return self._build_result(
                        "backup_file",
                        f"发现备份文件: {test_url}",
                        {"url": test_url, "size": len(resp.content)}
                    )
        # 也尝试常见归档名
        return False, {}

    def check_post(self, url, params):
        return False, {}

    def _is_source_content(self, content, content_type):
        if "text" in content_type:
            for pat in self.source_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    return True
        # 如果是二进制，检查前几个字节（如zip的PK）
        if content.startswith("PK\x03\x04") or content.startswith("\x1f\x8b"):
            return True
        return False