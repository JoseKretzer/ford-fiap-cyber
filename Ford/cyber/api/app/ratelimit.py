"""Rate limiting por janela deslizante (OWASP API4 - Unrestricted Resource Consumption).

Em memória para a demo. Em produção com várias réplicas, o mesmo algoritmo roda
sobre Redis (ZADD/ZREMRANGEBYSCORE) e o API Gateway aplica um limite global extra.
"""
import time
from collections import defaultdict, deque
from threading import Lock


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Registra uma tentativa. Retorna (permitido, segundos_para_liberar)."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                retry_after = int(hits[0] + self.window - now) + 1
                return False, retry_after
            hits.append(now)
            return True, 0

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
