import unittest
from urllib.parse import urlparse

from config import parse_args
from http_client import HttpClient
from plugin_loader import load_plugins
from utils import normalize_url, response_similarity, get_meaningful_content


class TestConfig(unittest.TestCase):
    def test_list_plugins_without_url(self):
        args = parse_args(["--list-plugins"])
        self.assertTrue(args.list_plugins)
        self.assertIsNone(args.url)

    def test_url_required_for_scan(self):
        with self.assertRaises(SystemExit):
            parse_args([])


class TestCookieNormalization(unittest.TestCase):
    def test_security_cookie_case_fixed(self):
        client = HttpClient(cookies=["PHPSESSID=abc123; Security=low"])
        names = {c.name: c.value for c in client.session.cookies}
        self.assertIn("PHPSESSID", names)
        # 原始 Security 会被 normalize 成 security
        self.assertNotIn("Security", names)
        self.assertEqual(names.get("security"), "low")

    def test_ensure_dvwa_security_rewrites_wrong_case(self):
        client = HttpClient(cookies=["PHPSESSID=abc123"])
        # 手动塞一个错误大小写（绕过 normalize）
        client.session.cookies.set("Security", "low")
        client.ensure_dvwa_security("low")
        names = {c.name: c.value for c in client.session.cookies}
        self.assertNotIn("Security", names)
        self.assertEqual(names.get("security"), "low")
        self.assertEqual(names.get("PHPSESSID"), "abc123")


class TestPluginLoader(unittest.TestCase):
    def test_loads_expected_plugins(self):
        plugins = load_plugins()
        names = {p.name for p in plugins}
        expected = {
            "sqli", "xss", "command_injection", "file_inclusion",
            "directory_traversal", "ssrf", "idor", "backup_files",
            "sensitive_files", "unauthorized_access",
        }
        self.assertTrue(expected.issubset(names))

    def test_only_filter(self):
        plugins = load_plugins(only=["sqli", "xss"])
        self.assertEqual({p.name for p in plugins}, {"sqli", "xss"})


class TestUtils(unittest.TestCase):
    def test_normalize_url(self):
        u = normalize_url("HTTP://Example.COM:80/a?b=2&a=1")
        self.assertEqual(urlparse(u).netloc, "example.com")
        self.assertIn("a=1", u)
        self.assertIn("b=2", u)

    def test_normalize_strips_fragment(self):
        from utils import strip_url_fragment
        u = normalize_url("http://127.0.0.1:42001/vulnerabilities/captcha/#")
        self.assertNotIn("#", u)
        self.assertEqual(
            strip_url_fragment("http://t/vulnerabilities/captcha/#"),
            "http://t/vulnerabilities/captcha/",
        )

    def test_similarity(self):
        self.assertGreater(response_similarity("hello world", "hello world"), 0.99)
        self.assertLess(response_similarity("aaa", "zzz"), 0.5)

    def test_meaningful_content_strips_noise(self):
        html = "<html><script>x</script><body>Hello 1234567890123 world</body></html>"
        text = get_meaningful_content(html)
        self.assertIn("Hello", text)
        self.assertNotIn("1234567890123", text)


class TestCrawlerLoginDetection(unittest.TestCase):
    def test_login_response_detection(self):
        from crawler import Crawler
        from rate_limiter import TokenBucket

        class DummyClient:
            pass

        c = Crawler(DummyClient(), TokenBucket(10, 10), logger=None)

        class Resp:
            def __init__(self, url, text):
                self.url = url
                self.text = text
                self.status_code = 200

        # 业务页被重定向到登录
        r = Resp(
            "http://t/login.php",
            '<form><input name="username"><input name="password"></form>',
        )
        self.assertTrue(c._response_is_login_page(r, "http://t/vulnerabilities/sqli/"))

        # 本来就是登录页
        self.assertFalse(
            c._response_is_login_page(r, "http://t/login.php")
        )

    def test_skip_captcha_path(self):
        from crawler import Crawler
        from rate_limiter import TokenBucket

        c = Crawler(object(), TokenBucket(10, 10), logger=None)
        self.assertTrue(c._is_skip_path("http://127.0.0.1:42001/vulnerabilities/captcha/"))
        self.assertTrue(c._is_skip_path("http://127.0.0.1:42001/vulnerabilities/captcha/#"))
        self.assertFalse(c._is_skip_path("http://127.0.0.1:42001/vulnerabilities/sqli/"))


if __name__ == "__main__":
    unittest.main()
