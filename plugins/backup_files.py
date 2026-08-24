from .base import ScannerPlugin
from urllib.parse import urlparse, urlunparse
import re


class BackupFilesPlugin(ScannerPlugin):
    name = "backup_files"
    description = "备份文件泄露检测"
    severity = "medium"
    scope = "url"

    # 收敛后的核心扩展名：覆盖最常见的备份/编辑器残留类型
    backup_extensions = ['.bak', '.old', '.orig', '.swp', '~']
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

        # 两阶段：先 HEAD 探测存在性（轻量），命中后再 GET 验证内容
        for ext in self.backup_extensions:
            new_path = path + ext
            test_url = urlunparse(parsed._replace(path=new_path))

            # 阶段 1：HEAD 探测，避免下载完整内容
            head_resp = self.safe_request("HEAD", test_url, timeout=10)
            if not head_resp or head_resp.status_code != 200:
                continue

            # 阶段 2：GET 验证内容是否为源码/备份
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
