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

    # ------------------------------------------------------------------
    # Atomic check + record — use for every incoming request
    # ------------------------------------------------------------------

    def check(self, ip: str, now: float | None = None) -> float | None:
        """Record *ip*. Returns None when allowed; otherwise the seconds
        remaining until the oldest hit leaves the window."""
        now = time.monotonic() if now is None else now
        if ip not in self._hits and len(self._hits) >= self.max_ips:
            self._hits.pop(next(iter(self._hits)))
        window = self._hits[ip]

        cutoff = now - self.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()

        # Record the hit regardless (even if over limit, so we track
        # abuse accurately). But return a non-None result when the caller
        # should reject the request.
        if len(window) >= self.limit:
            window.append(now)
            return window[0] + self.window_seconds - now

        window.append(now)
        return None

    # ------------------------------------------------------------------
    # Peek operations (no mutation)
    # ------------------------------------------------------------------

    def peek(self, ip: str, now: float | None = None) -> dict | None:
        """Return window metadata for *ip*, or None if never seen."""
        if now is None:
            now = time.monotonic()
        hits = self._hits.get(ip)
        if hits is None:
            return None

        cutoff = now - self.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if not hits:
            return None

        oldest = hits[0]
        over = len(hits) >= self.limit
        return {
            "current": len(hits),
            "over": over,
            "oldest": oldest,
            "now": now,
            "window_end": oldest + self.window_seconds,
            "reset_ts": int(oldest + self.window_seconds),
        }

    def reset(self, ip: str) -> None:
        """Forget all history for *ip*. Use only for testing."""
        self._hits.pop(ip, None)
