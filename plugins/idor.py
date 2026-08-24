import re
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils import response_similarity, get_meaningful_content


class IDORPlugin(ScannerPlugin):
    name = "idor"
    description = "检测水平越权（IDOR）漏洞（基础版）"
    severity = "high"

    # 明显不是资源 ID 的参数名（跳过这些参数避免误报）
    NON_RESOURCE_PARAM_PATTERNS = [
        r'^redirect$',
        r'^return$',
        r'^url$',
        r'^next$',
        r'^goto$',
        r'^target$',
        r'^page$',
        r'^page_id$',
        r'^tab$',
        r'^view$',
        r'^action$',
        r'^cmd$',
        r'^cmd$',
        r'^do$',
        r'^type$',
        r'^category$',
        r'^lang$',
        r'^language$',
        r'^theme$',
        r'^sort$',
        r'^order$',
        r'^dir$',
        r'^format$',
        r'^mode$',
        r'^ref$',
        r'^referral$',
        r'^source$',
        r'^campaign$',
        r'^token$',
        r'^csrf',
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._skip_patterns = [re.compile(p, re.IGNORECASE) for p in self.NON_RESOURCE_PARAM_PATTERNS]

    def _is_resource_id_param(self, param):
        for pat in self._skip_patterns:
            if pat.match(param):
                return False
        return True

    def check_get(self, url):
        testable = self.get_testable_params(url, method="GET")
        if not testable:
            return False, {}
        for param, original_value in testable.items():
            if not self._is_resource_id_param(param):
                continue
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
            if not self._is_resource_id_param(param):
                continue
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

        # 授权边界判别：若新 ID 返回 401/403/404，说明有权限隔离，不算 IDOR
        if modified_resp.status_code in (401, 403, 404):
            return None
        # 原始 ID 必须正常返回
        if normal_resp.status_code != 200:
            return None
        # 两个响应都必须是 200 才比对内容
        if modified_resp.status_code != 200:
            return None

        normal_content = get_meaningful_content(normal_resp.text)
        modified_content = get_meaningful_content(modified_resp.text)
        similarity = response_similarity(normal_content, modified_content)

        # 内容确实不同（低相似度）才上报
        if similarity < 0.5:
            # 额外验证：若新 ID 对应不存在的资源，服务端往往会返回
            # 明显的 "not found" / "无此记录" 等内容，相似度也可能低
            not_found_indicators = [
                "not found", "no such", "不存在", "无此记录",
                "记录不存在", "404", "resource not found",
            ]
            modified_lower = modified_content.lower()
            if any(ind in modified_lower for ind in not_found_indicators):
                # 新 ID 触发了 not-found 提示，更像"资源不存在"而非越权
                return None
            return self._build_result(
                "idor",
                f"参数 {param} 修改 ID 从 {original_id} 到 {new_id} 后返回不同内容，可能存在水平越权",
                {
                    "param": param,
                    "original_id": original_id,
                    "new_id": new_id,
                    "similarity": round(similarity, 4),
                    "original_status": normal_resp.status_code,
                    "modified_status": modified_resp.status_code,
                },
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
