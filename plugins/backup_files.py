from .base import ScannerPlugin
from urllib.parse import urlparse, urlunparse
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 实例级去重：避免对同一原 URL 重复扫描备份扩展名
        self._tested_urls = set()

    def check_get(self, url):
        # 跳过已测试过的 URL，避免重复扫描
        if url in self._tested_urls:
            return False, {}
        self._tested_urls.add(url)

        parsed = urlparse(url)
        path = parsed.path
        if not path or path.endswith('/'):
            return False, {}
        filename = path.split('/')[-1]
        if not filename:
            return False, {}

        # 仅对路径追加备份扩展名，避免破坏查询字符串
        for ext in self.backup_extensions:
            new_path = path + ext
            test_url = urlunparse(parsed._replace(path=new_path))
            resp = self.safe_request("GET", test_url, timeout=10)
            if resp and resp.status_code == 200:
                content = resp.text
                if self._is_source_content(content, resp.headers.get("Content-Type", "")):
                    return True, self._build_result(
                        "backup_file",
                        f"发现备份文件: {test_url}",
                        {
                            "url": test_url,
                            "size": len(resp.content),
                            "content_snippet": content[:200],
                        },
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
