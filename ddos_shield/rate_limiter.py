"""Sliding-window rate limiter.

Tracks recent request timestamps per client key (usually an IP address) and
decides whether a new request is within the allowed rate. Thread-safe and
memory-bounded: old timestamps are pruned as they age out of the window.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict


class RateLimiter:
    """Allow at most ``max_requests`` per ``window_seconds`` per client.

    Example:
        limiter = RateLimiter(max_requests=100, window_seconds=60)
        if limiter.allow(client_ip):
            ...  # serve
        else:
            ...  # return 429
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.max_requests = max_requests
        self.window_seconds = float(window_seconds)
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        """Return True if a request from ``key`` is allowed right now."""
        now = time.monotonic() if now is None else now
        cutoff = now - self.window_seconds

        with self._lock:
            hits = self._hits[key]
            # Drop timestamps that have aged out of the window.
            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= self.max_requests:
                return False

            hits.append(now)
            return True

    def remaining(self, key: str, now: float | None = None) -> int:
        """How many more requests ``key`` may make in the current window."""
        now = time.monotonic() if now is None else now
        cutoff = now - self.window_seconds
        with self._lock:
            # Use .get() so querying an unseen key doesn't create an entry.
            hits = self._hits.get(key)
            if not hits:
                return self.max_requests
            while hits and hits[0] <= cutoff:
                hits.popleft()
            return max(0, self.max_requests - len(hits))

    def retry_after(self, key: str, now: float | None = None) -> float:
        """Seconds until ``key`` may make another request (0.0 if it may now)."""
        now = time.monotonic() if now is None else now
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return 0.0
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) < self.max_requests:
                return 0.0
            # The oldest hit has to age out of the window first.
            return hits[0] + self.window_seconds - now

    def tracked_clients(self) -> int:
        """Number of clients currently held in memory."""
        with self._lock:
            return len(self._hits)

    def reset(self, key: str) -> None:
        """Forget all recorded activity for ``key``."""
        with self._lock:
            self._hits.pop(key, None)

    def prune(self, now: float | None = None) -> int:
        """Remove empty/expired client entries. Returns count removed.

        Call periodically in long-running services to bound memory when many
        distinct IPs are seen over time.
        """
        now = time.monotonic() if now is None else now
        cutoff = now - self.window_seconds
        removed = 0
        with self._lock:
            for key in list(self._hits.keys()):
                hits = self._hits[key]
                while hits and hits[0] <= cutoff:
                    hits.popleft()
                if not hits:
                    del self._hits[key]
                    removed += 1
        return removed
