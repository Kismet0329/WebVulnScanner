import re
from .base import ScannerPlugin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils import response_similarity, get_meaningful_content


class SQLiPlugin(ScannerPlugin):
    name = "sqli"
    description = "SQL注入检测（布尔盲注+时间盲注+报错注入）"
    severity = "high"

    # 真实数据库报错特征（正则），避免 "PostgreSQL" / "SQLite" 等通用词误报
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*?MySQL",                      # MySQL 语法错误
        r"Warning.*?\Wmysqli?_",                    # PHP mysqli 警告
        r"MySQLSyntaxErrorException",
        r"You have an error in your SQL syntax",
        r"ORA-\d{5}",                               # Oracle 错误码
        r"OracleException",
        r"PostgreSQL.*?ERROR",                       # PostgreSQL 错误
        r"PSQLException",
        r"SQLite3?::(query|execute|prepare)\b",     # SQLite 异常类
        r"SQLite3?::(SQLException|Exception)",
        r"Microsoft OLE DB Provider for SQL Server",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"'[^']*' is not a valid numeric",
        r"quoted string not properly terminated",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 编译正则提升性能
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SQL_ERROR_PATTERNS
        ]

    def check_get(self, url):
        testable = self.get_testable_params(url, method="GET")
        if not testable:
            return False, {}
        for param, original_value in testable.items():
            result = self._test_injection(url, param, original_value, method="GET")
            if result:
                return True, result
        return False, {}

    def check_post(self, url, params):
        if not params:
            return False, {}
        testable = self.get_testable_params(url, method="POST", params=params)
        if not testable:
            return False, {}
        for param, original_value in testable.items():
            result = self._test_injection(url, param, original_value, method="POST", params=params)
            if result:
                return True, result
        return False, {}

    def _test_injection(self, url, param, original_value, method, params=None):
        # 报错注入：用单引号触发，匹配真实数据库错误特征
        error_payload = original_value + "'"
        resp = self._send_payload(url, param, error_payload, method, params)
        if resp:
            evidence = self._match_sql_error(resp.text)
            if evidence:
                return self._build_result(
                    "error_based_sqli",
                    f"参数 {param} 存在报错注入",
                    {
                        "param": param,
                        "payload": error_payload,
                        "evidence": evidence,
                    },
                )
        # 布尔盲注
        true_payload = original_value + "' AND '1'='1"
        false_payload = original_value + "' AND '1'='2"
        resp_true = self._send_payload(url, param, true_payload, method, params)
        resp_false = self._send_payload(url, param, false_payload, method, params)
        if resp_true and resp_false:
            true_content = get_meaningful_content(resp_true.text)
            false_content = get_meaningful_content(resp_false.text)
            sim = response_similarity(true_content, false_content)
            if sim < 0.95:
                resp_true2 = self._send_payload(url, param, true_payload, method, params)
                resp_false2 = self._send_payload(url, param, false_payload, method, params)
                if resp_true2 and resp_false2:
                    sim2 = response_similarity(
                        get_meaningful_content(resp_true2.text),
                        get_meaningful_content(resp_false2.text),
                    )
                    if sim2 < 0.95:
                        return self._build_result(
                            "boolean_based_sqli",
                            f"参数 {param} 存在布尔盲注",
                            {
                                "param": param,
                                "true_payload": true_payload,
                                "false_payload": false_payload,
                                "similarity": round(sim, 4),
                            },
                            confidence="medium",  # 布尔盲注为相似度推断
                        )
        # 时间盲注：基线对比模式
        # 1) 先发正常请求测 baseline 延迟（取 2 次平均，降低单次抖动）
        # 2) 再发 SLEEP payload，判定 sleep_elapsed > baseline + SLEEP_SECONDS * 0.7
        # 3) 二次确认：避免偶发慢请求误报
        return self._test_time_based(url, param, original_value, method, params)

    def _match_sql_error(self, text):
        """返回首个匹配的 SQL 报错片段，否则返回 None"""
        for pattern in self._compiled_patterns:
            m = pattern.search(text)
            if m:
                # 截取匹配位置上下文，便于人工复核
                start = max(0, m.start() - 50)
                end = min(len(text), m.end() + 100)
                return text[start:end]
        return None

    # 时间盲注配置
    SLEEP_SECONDS = 2
    # 判定阈值：sleep_elapsed > baseline + SLEEP_SECONDS * 0.7
    # 即 SLEEP(2) 时阈值约 baseline + 1.4s
    SLEEP_THRESHOLD_RATIO = 0.7
    # baseline 采样次数（取平均降低抖动）
    BASELINE_SAMPLES = 2

    # 多数据库时间盲注 payload 模板（覆盖主流数据库）
    # key: db_type, value: (sleep_payload_template, zero_payload_template, 注释符)
    TIME_PAYLOADS = {
        "mysql":      ("' AND SLEEP({seconds})-- -",            "' AND SLEEP(0)-- -"),
        "postgresql": ("'; SELECT pg_sleep({seconds})-- -",     "'; SELECT pg_sleep(0)-- -"),
        "mssql":      ("'; WAITFOR DELAY '0:0:{seconds}'-- -",   "'; WAITFOR DELAY '0:0:0'-- -"),
        "oracle":     ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds})=1-- -",
                       "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',0)=1-- -"),
        "sqlite":    ("' AND randomblob({seconds}*10000000) IS NOT NULL-- -",
                       "' AND randomblob(0) IS NOT NULL-- -"),
    }

    def _test_time_based(self, url, param, original_value, method, params=None):
        """时间盲注基线对比检测（多数据库）

        策略：
        1. 发 BASELINE_SAMPLES 次正常请求，取平均作为 baseline
        2. 依次尝试每种数据库的 SLEEP payload
        3. 判定：elapsed > baseline + SLEEP_SECONDS * SLEEP_THRESHOLD_RATIO
        4. 对照组：同数据库 SLEEP(0) 不应超阈值
        5. 二次确认：再发一次 SLEEP payload

        关键：使用 resp.elapsed（requests 内部记录的服务器响应耗时），
        而非 time.time() 差值，避免限流器等待时间被计入 baseline，
        导致并发扫描时 baseline 被夸大而漏报。
        """
        # 1. baseline
        baseline_total = 0.0
        baseline_count = 0
        for _ in range(self.BASELINE_SAMPLES):
            resp = self._send_payload(url, param, original_value, method, params, timeout=10)
            if resp is not None:
                baseline_total += resp.elapsed.total_seconds()
                baseline_count += 1
        if baseline_count == 0:
            self.logger.debug(f"TIME_BASED baseline 全部失败 url={url} param={param}")
            return None
        baseline = baseline_total / baseline_count

        threshold = baseline + self.SLEEP_SECONDS * self.SLEEP_THRESHOLD_RATIO
        self.logger.debug(f"TIME_BASED url={url} param={param} baseline={baseline:.2f}s threshold={threshold:.2f}s")

        # 2. 逐个数据库测试
        for db_type, (sleep_tpl, zero_tpl) in self.TIME_PAYLOADS.items():
            time_payload = original_value + sleep_tpl.format(seconds=self.SLEEP_SECONDS)
            resp = self._send_payload(url, param, time_payload, method, params, timeout=15)
            elapsed = resp.elapsed.total_seconds() if resp is not None else 0.0
            self.logger.debug(f"TIME_BASED db={db_type} sleep_elapsed={elapsed:.2f}s resp={resp is not None}")
            if resp is None or elapsed <= threshold:
                continue

            # 3. 对照组
            control_payload = original_value + zero_tpl
            ctrl_resp = self._send_payload(url, param, control_payload, method, params, timeout=15)
            ctrl_elapsed = ctrl_resp.elapsed.total_seconds() if ctrl_resp is not None else 0.0
            self.logger.debug(f"TIME_BASED db={db_type} ctrl_elapsed={ctrl_elapsed:.2f}s")
            if ctrl_resp is not None and ctrl_elapsed > threshold:
                continue  # payload 处理本身慢，非 SLEEP 生效

            # 4. 二次确认
            resp2 = self._send_payload(url, param, time_payload, method, params, timeout=15)
            elapsed2 = resp2.elapsed.total_seconds() if resp2 is not None else 0.0
            self.logger.debug(f"TIME_BASED db={db_type} sleep2_elapsed={elapsed2:.2f}s")
            if resp2 is None or elapsed2 <= threshold:
                continue

            return self._build_result(
                "time_based_sqli",
                f"参数 {param} 存在时间盲注（{db_type}，baseline={baseline:.2f}s, "
                f"sleep={elapsed:.2f}s/{elapsed2:.2f}s）",
                {
                    "param": param,
                    "payload": time_payload,
                    "db_type": db_type,
                    "baseline_elapsed": round(baseline, 2),
                    "sleep_elapsed": round(elapsed, 2),
                    "sleep_elapsed_2": round(elapsed2, 2),
                    "threshold": round(threshold, 2),
                },
                confidence="low",  # 时间盲注为基线推断，需人工复核
            )
        self.logger.debug(f"TIME_BASED 未检出 url={url} param={param}")
        return None

    def _send_payload(self, url, param, payload, method="GET", params=None, timeout=10):
        if method == "GET":
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            return self.safe_request("GET", test_url, timeout=timeout)
        else:
            test_params = params.copy()
            test_params[param] = payload
            return self.safe_request("POST", url, data=test_params, timeout=timeout)
