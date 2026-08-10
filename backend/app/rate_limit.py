"""In-memory per-IP sliding-window rate limiter.

Suits this deployment exactly: Render's free tier runs a single instance,
so process-local state is authoritative. On a multi-instance deployment
this would undercount (each instance keeps its own windows) — documented
trade-off, not an oversight.

The number of tracked IPs is bounded: an attacker rotating forged client
IPs must not be able to grow the dict without limit.
"""

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        max_ips: int = 10_000,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_ips = max_ips
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, ip: str, now: float | None = None) -> float | None:
        """Record a request from ``ip``. Returns None if allowed, else the
        number of seconds until the oldest request leaves the window."""
        now = time.monotonic() if now is None else now
        if ip not in self._hits and len(self._hits) >= self.max_ips:
            # evict the longest-idle tracked IP (dict preserves insertion order)
            self._hits.pop(next(iter(self._hits)))
        window = self._hits[ip]

        cutoff = now - self.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()

        if len(window) >= self.limit:
            return window[0] + self.window_seconds - now

        window.append(now)
        return None
