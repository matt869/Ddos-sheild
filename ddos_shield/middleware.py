"""Flask integration: one call to protect an app.

Usage:
    from flask import Flask
    from ddos_shield.middleware import protect

    app = Flask(__name__)
    protect(app, max_requests=60, window_seconds=60, ban_seconds=300)

Clients over the limit get a 429 with a ``Retry-After`` header. Repeat
offenders that keep hammering after being limited are added to the blocklist.
"""

from __future__ import annotations

from typing import Any

from .blocklist import BlockList
from .monitor import TrafficMonitor
from .rate_limiter import RateLimiter


def client_ip(headers: Any, remote_addr: str) -> str:
    """Best-effort real client IP.

    Honors the first hop in X-Forwarded-For *only* — trust this only if your
    app sits behind a proxy you control, otherwise the header is spoofable.
    """
    forwarded = headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return remote_addr or "unknown"


def protect(
    app: Any,
    max_requests: int = 60,
    window_seconds: float = 60.0,
    ban_seconds: float = 300.0,
    use_iptables: bool = False,
    spike_threshold: float = 500.0,
    trust_forwarded_for: bool = False,
) -> None:
    """Attach DDoS Shield protection to a Flask ``app``."""
    from flask import request, jsonify  # imported lazily so Flask stays optional

    limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
    blocklist = BlockList(ban_seconds=ban_seconds, use_iptables=use_iptables)
    monitor = TrafficMonitor(spike_threshold=spike_threshold)

    # Expose components for tests / advanced tuning.
    app.extensions = getattr(app, "extensions", {})
    app.extensions["ddos_shield"] = {
        "limiter": limiter,
        "blocklist": blocklist,
        "monitor": monitor,
    }

    @app.before_request
    def _guard():
        ip = (
            client_ip(request.headers, request.remote_addr)
            if trust_forwarded_for
            else (request.remote_addr or "unknown")
        )

        monitor.record()

        if blocklist.is_banned(ip):
            resp = jsonify(error="forbidden", reason="temporarily blocked")
            resp.status_code = 403
            return resp

        if not limiter.allow(ip):
            # Persistent flooding after being limited -> ban.
            blocklist.ban(ip)
            resp = jsonify(error="too_many_requests")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(int(window_seconds))
            return resp

        return None  # allow the request through
