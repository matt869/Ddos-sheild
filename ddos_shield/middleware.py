"""Flask integration: one call to protect an app.

Usage:
    from flask import Flask
    from ddos_shield.middleware import protect

    app = Flask(__name__)
    protect(app, max_requests=60, window_seconds=60, ban_seconds=300)

Clients over the limit get a 429 and are added to the blocklist; while banned
they get a 403. Both responses carry a ``Retry-After`` header telling the client
how long until the ban lifts.
"""

from __future__ import annotations

from typing import Any, Iterable

from .shield import Shield, client_ip

__all__ = ["protect", "client_ip"]


def protect(
    app: Any,
    max_requests: int = 60,
    window_seconds: float = 60.0,
    ban_seconds: float = 300.0,
    use_iptables: bool = False,
    spike_threshold: float = 500.0,
    sample_seconds: float = 5.0,
    trust_forwarded_for: bool = False,
    exempt_paths: Iterable[str] = (),
    **options: Any,
) -> Shield:
    """Attach DDoS Shield protection to a Flask ``app``. Returns the ``Shield``.

    Requests to ``exempt_paths`` (e.g. ``"/health"``) are never checked or
    counted. Extra keyword ``options`` (e.g. ``allowlist``) go to ``Shield``.
    """
    from flask import jsonify, request  # imported lazily so Flask stays optional

    shield = Shield(
        max_requests=max_requests,
        window_seconds=window_seconds,
        ban_seconds=ban_seconds,
        use_iptables=use_iptables,
        spike_threshold=spike_threshold,
        sample_seconds=sample_seconds,
        **options,
    )

    exempt = frozenset(exempt_paths)

    # Expose components for tests / advanced tuning.
    app.extensions = getattr(app, "extensions", {})
    app.extensions["ddos_shield"] = {
        "shield": shield,
        "limiter": shield.limiter,
        "blocklist": shield.blocklist,
        "monitor": shield.monitor,
    }

    @app.before_request
    def _guard():
        if request.path in exempt:
            return None

        ip = (
            client_ip(request.headers, request.remote_addr)
            if trust_forwarded_for
            else (request.remote_addr or "unknown")
        )

        decision = shield.check(ip)
        if decision.allowed:
            return None  # let the request through

        resp = jsonify(decision.payload())
        resp.status_code = decision.status
        resp.headers["Retry-After"] = str(decision.retry_after)
        return resp

    return shield
