import time
import threading
import random


class TokenBucket:
    """线程安全的令牌桶限流器。

    关键设计：所有 time.sleep 都在锁外执行，避免一个线程睡眠时
    阻塞其他线程获取令牌（否则会将并发请求串行化为单线程）。
    """

    def __init__(self, rate, capacity, jitter=0.0):
        self.rate = rate
        self.capacity = capacity
        self.jitter = jitter
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        while True:
            with self.lock:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    break
                # 计算等待时间：还需多少秒才能攒够 1 个令牌
                wait_time = (1 - self.tokens) / self.rate
            # 在锁外睡眠，其他线程可继续检查/获取令牌
            time.sleep(wait_time)

        # jitter 也在锁外执行：每个请求独立添加随机间隔，不影响其他线程
        if self.jitter > 0:
            base_interval = 1.0 / self.rate
            jitter_amount = base_interval * self.jitter * random.uniform(-1, 1)
            time.sleep(max(0, base_interval + jitter_amount))
        return True

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now
