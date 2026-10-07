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
import logging
import math
import posixpath
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple, Union

from .blocklist import BlockList
from .monitor import TrafficMonitor
from .rate_limiter import RateLimiter

logger = logging.getLogger("ddos_shield")

PathLimit = Union[Tuple[int, float], Mapping[str, float]]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _parse_ip(ip: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


@dataclass(frozen=True)
class Decision:
    """Outcome of ``Shield.check``."""

    allowed: bool
    status: int = 200
    error: str = ""
    reason: str = ""
    retry_after: int = 0

    def payload(self) -> Dict[str, str]:
        """JSON body for a rejected request."""
        body = {"error": self.error}
        if self.status == 403:
            body["reason"] = self.reason
        return body


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


def normalize_path(path: str) -> str:
    """Canonical form of a URL path for rule matching.

    Collapses repeated slashes and resolves ``.``/``..`` segments, so
    ``//login``, ``/./login`` and ``/x/../login`` can't slip past a ``/login``
    rule when the app or server would route them to the same place.
    """
    return posixpath.normpath("/" + path.lstrip("/"))


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
        on_attack: Optional[Callable[[float], None]] = None,
        alert_cooldown: float = 60.0,
        ban_multiplier: float = 1.0,
        max_ban_seconds: Optional[float] = None,
        ipv6_prefix: int = 64,
        path_limits: Optional[Mapping[str, PathLimit]] = None,
        on_ban: Optional[Callable[[str, float], None]] = None,
    ) -> None:
        """``allowlist`` takes IPs or CIDR ranges (e.g. ``"10.0.0.0/8"``) that are
        never limited — health checks, internal networks, your load balancer.

        Every ``cleanup_interval`` seconds, state for clients that have gone
        quiet and expired bans is dropped, so memory stays bounded however
        many distinct IPs the service sees.

        ``on_attack(rate)`` is called when the global request rate crosses
        ``spike_threshold`` — page someone, tighten limits, scale up. It fires at
        most once per ``alert_cooldown`` seconds while the spike lasts.

        ``ban_multiplier`` > 1 makes repeat offenders' bans grow (see
        ``BlockList``), up to ``max_ban_seconds``.

        IPv6 clients are grouped by their ``/ipv6_prefix`` network: one host
        usually controls a whole /64 and can rotate through it freely. Use 128
        to limit each IPv6 address separately.

        ``path_limits`` adds stricter budgets for sensitive routes, e.g.
        ``{"/login": (5, 60)}`` = 5 attempts per minute per client. A rule
        covers the path and everything below it; the longest match wins.
        Going over a path limit returns 429 for that route only — no site-wide
        ban, so a user who mistypes a password can still browse.

        ``on_ban(client, seconds)`` is called whenever a client is banned —
        ship it to your logs, SIEM or chat.
        """
        if not 0 < ipv6_prefix <= 128:
            raise ValueError("ipv6_prefix must be between 1 and 128")
        if cleanup_interval <= 0:
            raise ValueError("cleanup_interval must be positive")
        if alert_cooldown < 0:
            raise ValueError("alert_cooldown must not be negative")
        self.limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
        self.blocklist = BlockList(
            ban_seconds=ban_seconds,
            use_iptables=use_iptables,
            ban_multiplier=ban_multiplier,
            max_ban_seconds=max_ban_seconds,
        )
        self.monitor = TrafficMonitor(
            spike_threshold=spike_threshold, sample_seconds=sample_seconds
        )
        # strict=False lets "10.0.0.1/8" mean the whole 10.0.0.0/8 network.
        self.allowlist = tuple(
            ipaddress.ip_network(entry, strict=False) for entry in allowlist
        )
        self.ipv6_prefix = ipv6_prefix
        self._ipv6_mask = ((1 << ipv6_prefix) - 1) << (128 - ipv6_prefix)
        self.path_limiters: Dict[str, RateLimiter] = {
            normalize_path(path): _path_limiter(path, rule)
            for path, rule in (path_limits or {}).items()
        }
        self.on_ban = on_ban
        self.cleanup_interval = float(cleanup_interval)
        self._next_cleanup: float | None = None
        self.on_attack = on_attack
        self.alert_cooldown = float(alert_cooldown)
        self._last_alert: float | None = None
        self._lock = threading.Lock()
        self._counts = {
            "allowed": 0,
            "allowlisted": 0,
            "rate_limited": 0,
            "path_limited": 0,
            "blocked": 0,
        }

    def is_allowlisted(self, ip: str) -> bool:
        return self._allowlisted(_parse_ip(ip))

    def client_key(self, ip: str) -> str:
        """The key a client is tracked under: its IPv4 address, or its IPv6
        ``/ipv6_prefix`` network. Unparseable values are used as-is."""
        return self._key(ip, _parse_ip(ip))

    def _allowlisted(self, addr: Optional[IPAddress]) -> bool:
        if addr is None or not self.allowlist:
            return False
        return any(addr in net for net in self.allowlist)

    def _key(self, ip: str, addr: Optional[IPAddress]) -> str:
        if addr is None:
            return ip
        if addr.version == 6:
            mapped = addr.ipv4_mapped  # type: ignore[union-attr]
            if mapped is not None:
                return str(mapped)
            if self.ipv6_prefix < 128:
                # Integer masking: far cheaper than building an ip_network.
                network = ipaddress.IPv6Address(int(addr) & self._ipv6_mask)
                return f"{network}/{self.ipv6_prefix}"
            return str(addr)
        return ip  # IPv4 parsing is strict, so the input is already canonical

    def path_limiter(self, path: str) -> Optional[RateLimiter]:
        """The limiter for the most specific ``path_limits`` rule covering ``path``."""
        path = normalize_path(path)
        best = None
        for rule in self.path_limiters:
            if rule == "/" or path == rule or path.startswith(rule + "/"):
                if best is None or len(rule) > len(best):
                    best = rule
        return None if best is None else self.path_limiters[best]

    def check(
        self, ip: str, now: float | None = None, *, path: Optional[str] = None
    ) -> Decision:
        """Record a request from ``ip`` (to ``path``) and decide whether to serve it."""
        now = time.monotonic() if now is None else now
        self.monitor.record(now)
        self._maybe_cleanup(now)
        self._maybe_alert(now)

        addr = _parse_ip(ip)
        if self._allowlisted(addr):
            self._count("allowlisted")
            return ALLOW

        key = self._key(ip, addr)
        if self.blocklist.is_banned(key, now):
            self._count("blocked")
            return Decision(
                allowed=False,
                status=403,
                error="forbidden",
                reason="temporarily blocked",
                retry_after=math.ceil(self.blocklist.time_remaining(key, now)),
            )

        if not self.limiter.allow(key, now):
            # Over the limit -> ban, so further requests are rejected cheaply.
            duration = self.blocklist.ban(key, now)
            self._count("rate_limited")
            self._notify_ban(key, duration)
            return Decision(
                allowed=False,
                status=429,
                error="too_many_requests",
                reason="rate limit exceeded",
                retry_after=math.ceil(duration),
            )

        limiter = self.path_limiter(path) if path is not None else None
        if limiter is not None and not limiter.allow(key, now):
            self._count("path_limited")
            return Decision(
                allowed=False,
                status=429,
                error="too_many_requests",
                reason="rate limit exceeded for this path",
                retry_after=max(1, math.ceil(limiter.retry_after(key, now))),
            )

        self._count("allowed")
        return ALLOW

    def stats(self, now: float | None = None) -> Dict[str, Any]:
        """Snapshot for dashboards and metrics exporters.

        Counters are cumulative since the Shield was created; ``current_rate``
        and ``under_attack`` describe the last ``sample_seconds``.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            counts = dict(self._counts)
        rate = self.monitor.current_rate(now)
        return {
            "requests": counts,
            "current_rate": rate,
            "under_attack": rate >= self.monitor.spike_threshold,
            "active_bans": len(self.blocklist.banned(now)),
            "tracked_clients": self.limiter.tracked_clients(),
        }

    def _notify_ban(self, key: str, duration: float) -> None:
        if self.on_ban is None:
            return
        try:
            self.on_ban(key, duration)
        except Exception:  # a logging hook must never take the app down
            logger.exception("on_ban callback failed")

    def _count(self, outcome: str) -> None:
        with self._lock:
            self._counts[outcome] += 1

    def _maybe_cleanup(self, now: float) -> None:
        with self._lock:
            if self._next_cleanup is None:
                self._next_cleanup = now + self.cleanup_interval
                return
            if now < self._next_cleanup:
                return
            self._next_cleanup = now + self.cleanup_interval
        self.limiter.prune(now)
        for limiter in self.path_limiters.values():
            limiter.prune(now)
        self.blocklist.sweep(now)

    def _maybe_alert(self, now: float) -> None:
        if not self.monitor.is_under_attack(now):
            return
        with self._lock:
            if (
                self._last_alert is not None
                and now - self._last_alert < self.alert_cooldown
            ):
                return
            self._last_alert = now
        rate = self.monitor.current_rate(now)
        logger.warning("Traffic spike: %.1f req/s (threshold %.1f)",
                       rate, self.monitor.spike_threshold)
        if self.on_attack is not None:
            try:
                self.on_attack(rate)
            except Exception:  # an alert hook must never take the app down
                logger.exception("on_attack callback failed")


def _path_limiter(path: str, rule: PathLimit) -> RateLimiter:
    if isinstance(rule, Mapping):
        unknown = set(rule) - {"max_requests", "window_seconds"}
        if unknown:
            raise ValueError(f"unknown keys in path limit {path!r}: {sorted(unknown)}")
        return RateLimiter(**rule)
    max_requests, window_seconds = rule
    return RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
