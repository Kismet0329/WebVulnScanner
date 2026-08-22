import logging
import re
import time

class ScannerPlugin:
    name = "base"
    description = "基础插件"
    severity = "low"

    SKIP_PARAM_PATTERNS = [
        r'^csrf[_-]?token$',
        r'^timestamp$',
        r'^sign$',
        r'^signature$',
        r'^nonce$',
        r'^verification_code$',
        r'^captcha$',
        r'^token$',
        r'^authenticity_token$',
        r'^_wpnonce$',
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

    def _build_result(self, vuln_type, detail, evidence=None, severity=None):
        return {
            "plugin": self.name,
            "type": vuln_type,
            "severity": severity or self.severity,
            "detail": detail,
            "evidence": evidence or {},
        }