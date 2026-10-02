"""Framework-agnostic WSGI middleware.

Wraps any WSGI application (Django, Bottle, Falcon, Pyramid, plain WSGI...):

    from ddos_shield.wsgi import ShieldMiddleware

    application = ShieldMiddleware(application, max_requests=60, window_seconds=60)

Rejected requests get a small JSON body and a ``Retry-After`` header, exactly
like the Flask integration.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any, Callable, Iterable, Optional

from .shield import Shield, client_ip

__all__ = ["ShieldMiddleware"]


class ShieldMiddleware:
    def __init__(
        self,
        app: Callable[..., Iterable[bytes]],
        shield: Optional[Shield] = None,
        trust_forwarded_for: bool = False,
        **options: Any,
    ) -> None:
        """Pass a ready-made ``shield``, or ``Shield`` keyword ``options``."""
        if shield is not None and options:
            raise TypeError("pass either a Shield or Shield options, not both")
        self.app = app
        self.shield = shield if shield is not None else Shield(**options)
        self.trust_forwarded_for = trust_forwarded_for

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        remote_addr = environ.get("REMOTE_ADDR", "")
        if self.trust_forwarded_for:
            headers = {"X-Forwarded-For": environ.get("HTTP_X_FORWARDED_FOR", "")}
            ip = client_ip(headers, remote_addr)
        else:
            ip = remote_addr or "unknown"

        decision = self.shield.check(ip)
        if decision.allowed:
            return self.app(environ, start_response)

        payload = {"error": decision.error}
        if decision.status == 403:
            payload["reason"] = decision.reason
        body = json.dumps(payload).encode("utf-8")
        status = HTTPStatus(decision.status)
        start_response(
            f"{status.value} {status.phrase}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Retry-After", str(decision.retry_after)),
            ],
        )
        return [body]
