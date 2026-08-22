# rate_limiter.py
import time
import threading
import random

class TokenBucket:
    def __init__(self, rate, capacity, jitter=0.0):
        """
        :param rate: 每秒补充令牌数
        :param capacity: 桶容量（允许突发请求数）
        :param jitter: 抖动比例，例如0.2表示在基础间隔上增加±20%的随机延迟
        """
        self.rate = rate
        self.capacity = capacity
        self.jitter = jitter
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            self._refill()
            if self.tokens >= 1:
                self.tokens -= 1
                if self.jitter > 0:
                    base_interval = 1.0 / self.rate
                    jitter_amount = base_interval * self.jitter * random.uniform(-1, 1)
                    time.sleep(max(0, base_interval + jitter_amount))
                return True
            wait_time = (1 - self.tokens) / self.rate
            time.sleep(wait_time)
            self._refill()
            self.tokens -= 1
            return True

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now