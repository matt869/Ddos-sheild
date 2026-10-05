"""ASGI middleware for FastAPI, Starlette, Quart, Django (ASGI) and friends.

    from fastapi import FastAPI
    from ddos_shield.asgi import ShieldASGIMiddleware

    app = FastAPI()
    app.add_middleware(ShieldASGIMiddleware, max_requests=60, window_seconds=60)

or wrap any ASGI app directly: ``app = ShieldASGIMiddleware(app, ...)``.

HTTP requests are rejected with the same JSON body and ``Retry-After`` header
as the other integrations. Rejected WebSocket handshakes are closed with
code 1008 (policy violation), which servers turn into an HTTP 403.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional

from .shield import Shield, client_ip

__all__ = ["ShieldASGIMiddleware"]

Scope = Dict[str, Any]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]


class ShieldASGIMiddleware:
    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        shield: Optional[Shield] = None,
        trust_forwarded_for: bool = False,
        exempt_paths: Iterable[str] = (),
        **options: Any,
    ) -> None:
        """Pass a ready-made ``shield``, or ``Shield`` keyword ``options``.

        Requests to ``exempt_paths`` (e.g. ``"/health"``) are never checked.
        """
        if shield is not None and options:
            raise TypeError("pass either a Shield or Shield options, not both")
        self.app = app
        self.shield = shield if shield is not None else Shield(**options)
        self.trust_forwarded_for = trust_forwarded_for
        self.exempt_paths = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] not in ("http", "websocket")  # e.g. lifespan events
            or scope.get("path", "") in self.exempt_paths
        ):
            await self.app(scope, receive, send)
            return

        decision = self.shield.check(self._client_ip(scope))
        if decision.allowed:
            await self.app(scope, receive, send)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            body = json.dumps(decision.payload()).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": decision.status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(decision.retry_after).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})

    def _client_ip(self, scope: Scope) -> str:
        client = scope.get("client")
        remote_addr = client[0] if client else ""
        if not self.trust_forwarded_for:
            return remote_addr or "unknown"
        forwarded = ""
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for":
                forwarded = value.decode("latin-1")
                break
        return client_ip({"X-Forwarded-For": forwarded}, remote_addr)
