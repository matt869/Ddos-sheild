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
from typing import Any, Callable, Iterable, Optional, Union

from .shield import Shield, client_ip, proxy_count

__all__ = ["ShieldMiddleware"]


class ShieldMiddleware:
    def __init__(
        self,
        app: Callable[..., Iterable[bytes]],
        shield: Optional[Shield] = None,
        trust_forwarded_for: Union[bool, int] = False,
        exempt_paths: Iterable[str] = (),
        **options: Any,
    ) -> None:
        """Pass a ready-made ``shield``, or ``Shield`` keyword ``options``.

        Requests to ``exempt_paths`` (e.g. ``"/health"``) are never checked.
        ``trust_forwarded_for`` is the number of reverse proxies in front of
        the app (``True`` = 1); see ``client_ip``.
        """
        if shield is not None and options:
            raise TypeError("pass either a Shield or Shield options, not both")
        self.app = app
        self.shield = shield if shield is not None else Shield(**options)
        self.trusted_proxies = proxy_count(trust_forwarded_for)
        self.exempt_paths = frozenset(exempt_paths)

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        if environ.get("PATH_INFO", "") in self.exempt_paths:
            return self.app(environ, start_response)

        remote_addr = environ.get("REMOTE_ADDR", "")
        headers = {"X-Forwarded-For": environ.get("HTTP_X_FORWARDED_FOR", "")}
        ip = client_ip(headers, remote_addr, self.trusted_proxies)

        decision = self.shield.check(ip, path=environ.get("PATH_INFO", "/"))
        if decision.allowed:
            extra = decision.headers()
            if not extra:
                return self.app(environ, start_response)

            def start_with_quota(status, headers, *exc_info):
                # Forward exc_info only if the app passed it (it's optional).
                return start_response(status, list(headers) + extra, *exc_info)

            return self.app(environ, start_with_quota)

        body = json.dumps(decision.payload()).encode("utf-8")
        status = HTTPStatus(decision.status)
        start_response(
            f"{status.value} {status.phrase}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                *decision.headers(),
            ],
        )
        return [body]
