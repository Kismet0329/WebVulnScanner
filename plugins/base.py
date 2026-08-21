# plugins/base.py
import logging
import re

class ScannerPlugin:
    name = "base"
    description = "基础插件"
    severity = "low"
    # 默认忽略的参数名（正则匹配）
    SKIP_PARAM_PATTERNS = [
        r'^csrf[_-]?token$',      # CSRF token
        r'^timestamp$',           # 时间戳
        r'^sign$',                # 签名
        r'^signature$',
        r'^nonce$',               # 一次性随机数
        r'^verification_code$',   # 验证码
        r'^captcha$',
        r'^token$',               # 通用token
        r'^authenticity_token$',
        r'^_wpnonce$',            # WordPress nonce
    ]
    
    def __init__(self, http_client, rate_limiter=None, logger=None, skip_params=None):
        self.client = http_client
        self.rate_limiter = rate_limiter
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        # 允许外部传入自定义跳过参数模式
        self.skip_param_patterns = self.SKIP_PARAM_PATTERNS.copy()
        if skip_params:
            self.skip_param_patterns.extend(skip_params)

    def should_skip_param(self, param):
        """判断参数是否应跳过测试"""
        for pattern in self.skip_param_patterns:
            if re.match(pattern, param, re.IGNORECASE):
                return True
        return False

    def get_testable_params(self, url, method="GET", params=None):
        """
        返回需要测试的参数列表（过滤掉忽略参数）
        :param url: 请求URL
        :param method: 请求方法
        :param params: POST参数字典（GET时可为None，从URL解析）
        :return: dict {param_name: original_value}
        """
        testable = {}
        if method == "GET":
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            for param, values in query.items():
                if not self.should_skip_param(param):
                    testable[param] = values[0] if values else ''
        else:  # POST
            if params:
                for param, value in params.items():
                    if not self.should_skip_param(param):
                        testable[param] = value
        return testable

    def __init__(self, http_client, rate_limiter=None, logger=None):
        self.client = http_client
        self.rate_limiter = rate_limiter
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    def safe_request(self, method, url, **kwargs):
        if self.rate_limiter:
            self.rate_limiter.acquire()
        try:
            response = self.client.request(method, url, **kwargs)
            return response
        except Exception as e:
            self.logger.error(f"请求异常 {url}: {e}")
            return None

    def check(self, target):
        """
        默认入口：根据请求方法分发到对应的检测函数
        target 结构：{"url": str, "method": "GET"/"POST", "params": dict 或 None}
        """
        if target["method"] == "GET":
            return self.check_get(target["url"])
        elif target["method"] == "POST":
            return self.check_post(target["url"], target.get("params"))
        return False, {}

    # 子类按需覆盖以下两个方法
    def check_get(self, url):
        return False, {}

    def check_post(self, url, params):
        return False, {}

    def _build_result(self, vuln_type, detail, evidence=None, severity=None):
        return {
            "plugin": self.name,
            "type": vuln_type,
            "severity": severity or self.severity,
            "detail": detail,
            "evidence": evidence or {},
        }