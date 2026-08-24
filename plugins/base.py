import logging
import re
import time

class ScannerPlugin:
    name = "base"
    description = "基础插件"
    severity = "low"
    # 插件作用域：
    #   "site"  - 整个站点只跑一次（如敏感文件、未授权路径）
    #   "url"   - 每个爬到的 URL 跑一次（如备份文件）
    #   "param" - 每个 URL 的每个参数都跑（默认，向后兼容）
    scope = "param"

    SKIP_PARAM_PATTERNS = [
        # CSRF / 一次性 token
        r'^csrf[_-]?token$',
        r'^token$',
        r'^authenticity_token$',
        r'^_wpnonce$',
        r'^user_token$',           # DVWA
        r'^anticsrf$',
        r'^__requestverificationtoken$',
        r'^csrfmiddlewaretoken$',
        # 时间戳/签名/防重放
        r'^timestamp$',
        r'^sign$',
        r'^signature$',
        r'^nonce$',
        r'^nonce_str$',
        r'^verify$',
        # 验证码
        r'^captcha$',
        r'^verification_code$',
        r'^vcode$',
        r'^img_code$',
        # 密码类字段（非注入点）
        r'^password$',
        r'^passwd$',
        r'^pwd$',
        r'^password_conf$',
        r'^password_confirmation$',
        r'^confirm_password$',
        r'^old_password$',
        r'^new_password$',
        r'^current_password$',
        # 表单按钮/控制字段
        r'^submit$',
        r'^btnsubmit$',
        r'^submitbtn$',
        r'^action$',
        r'^operation$',
        r'^form_id$',
        r'^form_build_id$',
        # 文件上传字段名本身（其值是文件，非 SQL/反射上下文）
        r'^uploaded$',
        r'^file$',
        r'^upload$',
        r'^attachment$',
        r'^image$',
        r'^avatar$',
        # 视图状态
        r'^__viewstate$',
        r'^_viewstate$',
        r'^eventtarget$',
        r'^eventargument$',
        # 框架特定
        r'^yii[_-]?csrf$',
        r'^_csrf$',
    ]

    def __init__(self, http_client, rate_limiter=None, logger=None,
                 skip_params=None, fixed_delay=0.0):
        self.client = http_client
        self.rate_limiter = rate_limiter
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.fixed_delay = fixed_delay
        self.skip_param_patterns = self.SKIP_PARAM_PATTERNS.copy()
        if skip_params:
            self.skip_param_patterns.extend(skip_params)

    def safe_request(self, method, url, **kwargs):
        if self.rate_limiter:
            self.rate_limiter.acquire()
        if self.fixed_delay > 0:
            time.sleep(self.fixed_delay)
        try:
            response = self.client.request(method, url, **kwargs)
            return response
        except Exception as e:
            self.logger.error(f"请求异常 {url}: {e}")
            return None

    def check(self, target):
        if target["method"] == "GET":
            return self.check_get(target["url"])
        elif target["method"] == "POST":
            return self.check_post(target["url"], target.get("params"))
        return False, {}

    def check_get(self, url):
        return False, {}

    def check_post(self, url, params):
        return False, {}

    def should_skip_param(self, param):
        for pattern in self.skip_param_patterns:
            if re.match(pattern, param, re.IGNORECASE):
                return True
        return False

    def get_testable_params(self, url, method="GET", params=None):
        testable = {}
        if method == "GET":
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            for param, values in query.items():
                if not self.should_skip_param(param):
                    testable[param] = values[0] if values else ''
        else:
            if params:
                for param, value in params.items():
                    if not self.should_skip_param(param):
                        testable[param] = value
        return testable

    def _build_result(self, vuln_type, detail, evidence=None, severity=None, confidence="high"):
        """构造漏洞结果

        confidence: 漏洞可信度
            "high"   - 强证据：如报错注入匹配到真实 SQL 错误、LFI 读到完整文件内容
            "medium" - 中等证据：如布尔盲注相似度差异、XSS 在可执行上下文中回显
            "low"    - 弱证据：如时间盲注仅略超阈值，需人工复核
        """
        return {
            "plugin": self.name,
            "type": vuln_type,
            "severity": severity or self.severity,
            "confidence": confidence,
            "detail": detail,
            "evidence": evidence or {},
        }