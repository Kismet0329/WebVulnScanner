# plugins/idor.py
import re
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils import response_similarity, get_meaningful_content

class IDORPlugin(ScannerPlugin):
    name = "idor"
    description = "检测水平越权（IDOR）漏洞（基础版）"
    severity = "high"

    def check_get(self, url):
        testable = self.get_testable_params(url, method="GET")
        if not testable:
            return False, {}
        for param, original_value in testable.items():
            if re.fullmatch(r'\d+', original_value):
                original_id = original_value
                new_id = str(int(original_id) + 1)
                result = self._test_id_change(url, param, original_id, new_id, method="GET")
                if result:
                    return True, result
        return False, {}

    def check_post(self, url, params):
        if not params:
            return False, {}
        testable = self.get_testable_params(url, method="POST", params=params)
        for param, original_value in testable.items():
            if re.fullmatch(r'\d+', str(original_value)):
                original_id = str(original_value)
                new_id = str(int(original_id) + 1)
                result = self._test_id_change(url, param, original_id, new_id, method="POST", params=params)
                if result:
                    return True, result
        return False, {}

    def _test_id_change(self, url, param, original_id, new_id, method="GET", params=None):
        normal_resp = self._send_with_id(url, param, original_id, method, params)
        if not normal_resp:
            return None
        modified_resp = self._send_with_id(url, param, new_id, method, params)
        if not modified_resp:
            return None

        # 使用净化后的内容进行相似度比较
        normal_content = get_meaningful_content(normal_resp.text)
        modified_content = get_meaningful_content(modified_resp.text)
        similarity = response_similarity(normal_content, modified_content)

        # 如果相似度较低且两个响应都成功，提示可能存在越权
        if similarity < 0.5 and normal_resp.status_code == 200 and modified_resp.status_code == 200:
            # 可进一步检查是否包含用户数据特征，这里简化
            return self._build_result(
                "idor",
                f"参数 {param} 修改 ID 从 {original_id} 到 {new_id} 后返回不同内容，可能存在水平越权",
                {"param": param, "original_id": original_id, "new_id": new_id, "similarity": similarity}
            )
        return None

    def _send_with_id(self, url, param, id_value, method="GET", params=None):
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [id_value]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            return self.safe_request("GET", test_url)
        else:
            test_params = params.copy()
            test_params[param] = id_value
            return self.safe_request("POST", url, data=test_params)