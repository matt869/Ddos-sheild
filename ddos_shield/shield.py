"""Core request decision logic shared by the Flask and WSGI integrations.

``Shield`` bundles a rate limiter, blocklist and traffic monitor and answers
one question per request: let it through, or reject it (and how)?

    shield = Shield(max_requests=60, window_seconds=60, ban_seconds=300)
    decision = shield.check(client_ip)
    if not decision.allowed:
        respond(decision.status, retry_after=decision.retry_after)
"""

from __future__ import annotations

import ipaddress
import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable

from .blocklist import BlockList
from .monitor import TrafficMonitor
from .rate_limiter import RateLimiter


@dataclass(frozen=True)
class Decision:
    """Outcome of ``Shield.check``."""

    allowed: bool
    status: int = 200
    error: str = ""
    reason: str = ""
    retry_after: int = 0


ALLOW = Decision(allowed=True)


def client_ip(headers: Any, remote_addr: str) -> str:
    """Best-effort real client IP.

    Honors the first hop in X-Forwarded-For *only* — trust this only if your
    app sits behind a proxy you control, otherwise the header is spoofable.
    """
    forwarded = headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return remote_addr or "unknown"


class Shield:
    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        ban_seconds: float = 300.0,
        use_iptables: bool = False,
        spike_threshold: float = 500.0,
        sample_seconds: float = 5.0,
        allowlist: Iterable[str] = (),
        cleanup_interval: float = 60.0,
    ) -> None:
        """``allowlist`` takes IPs or CIDR ranges (e.g. ``"10.0.0.0/8"``) that are
        never limited — health checks, internal networks, your load balancer.

        Every ``cleanup_interval`` seconds, state for clients that have gone
        quiet and expired bans is dropped, so memory stays bounded however
        many distinct IPs the service sees.
        """
        if cleanup_interval <= 0:
            raise ValueError("cleanup_interval must be positive")
        self.limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
        self.blocklist = BlockList(ban_seconds=ban_seconds, use_iptables=use_iptables)
        self.monitor = TrafficMonitor(
            spike_threshold=spike_threshold, sample_seconds=sample_seconds
        )
        # strict=False lets "10.0.0.1/8" mean the whole 10.0.0.0/8 network.
        self.allowlist = tuple(
            ipaddress.ip_network(entry, strict=False) for entry in allowlist
        )
        self.cleanup_interval = float(cleanup_interval)
        self._next_cleanup: float | None = None
        self._lock = threading.Lock()

    def is_allowlisted(self, ip: str) -> bool:
        if not self.allowlist:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allowlist)

    def check(self, ip: str, now: float | None = None) -> Decision:
        """Record a request from ``ip`` and decide whether to serve it."""
        now = time.monotonic() if now is None else now
        self.monitor.record(now)
        self._maybe_cleanup(now)

        if self.is_allowlisted(ip):
            return ALLOW

        if self.blocklist.is_banned(ip, now):
            return Decision(
                allowed=False,
                status=403,
                error="forbidden",
                reason="temporarily blocked",
                retry_after=math.ceil(self.blocklist.time_remaining(ip, now)),
            )

        if not self.limiter.allow(ip, now):
            # Over the limit -> ban, so further requests are rejected cheaply.
            self.blocklist.ban(ip, now)
            return Decision(
                allowed=False,
                status=429,
                error="too_many_requests",
                reason="rate limit exceeded",
                retry_after=math.ceil(self.blocklist.ban_seconds),
            )

        return ALLOW

    def _maybe_cleanup(self, now: float) -> None:
        with self._lock:
            if self._next_cleanup is None:
                self._next_cleanup = now + self.cleanup_interval
                return
            if now < self._next_cleanup:
                return
            self._next_cleanup = now + self.cleanup_interval
        self.limiter.prune(now)
        self.blocklist.sweep(now)
