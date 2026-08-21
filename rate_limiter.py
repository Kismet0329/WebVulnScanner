# rate_limiter.py
import time
import threading

class TokenBucket:
    def __init__(self, rate, capacity):
        """
        :param rate: 每秒补充令牌数
        :param capacity: 桶容量（允许突发请求数）
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        """获取一个令牌，若没有则阻塞直到可用"""
        with self.lock:
            self._refill()
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            # 计算需要等待的时间
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