"""In-memory per-IP sliding-window rate limiter.

Suits this deployment exactly: Render's free tier runs a single instance,
so process-local state is authoritative. On a multi-instance deployment
this would undercount (each instance keeps its own windows) — documented
trade-off, not an oversight.
"""

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, ip: str, now: float | None = None) -> float | None:
        """Record a request from ``ip``. Returns None if allowed, else the
        number of seconds until the oldest request leaves the window."""
        now = time.monotonic() if now is None else now
        window = self._hits[ip]

        cutoff = now - self.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()

        if len(window) >= self.limit:
            return window[0] + self.window_seconds - now

        window.append(now)
        return None
