"""Tests for the ASGI middleware (standard library only, no ASGI server)."""

import asyncio
import json
import unittest

from ddos_shield import Shield
from ddos_shield.asgi import ShieldASGIMiddleware


async def hello_app(scope, receive, send):
    if scope["type"] == "websocket":
        await send({"type": "websocket.accept"})
        return
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"hello"})


def call(app, scope_type="http", ip="203.0.113.7", forwarded=None, path="/"):
    """Run one request through ``app``; returns the list of sent messages."""
    headers = [(b"host", b"example.test")]
    if forwarded:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    scope = {"type": scope_type, "client": (ip, 50000), "headers": headers,
             "path": path, "method": "GET"}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent


def status_of(messages):
    return messages[0].get("status") or messages[0]["type"]


class ShieldASGIMiddlewareTests(unittest.TestCase):
    def test_passes_through_then_limits(self):
        app = ShieldASGIMiddleware(hello_app, max_requests=2, window_seconds=10,
                                   ban_seconds=30)
        self.assertEqual(call(app)[1]["body"], b"hello")
        self.assertEqual(call(app)[1]["body"], b"hello")

        start, body = call(app)
        self.assertEqual(start["status"], 429)
        headers = dict(start["headers"])
        self.assertEqual(headers[b"retry-after"], b"30")
        self.assertEqual(headers[b"content-length"], str(len(body["body"])).encode())
        self.assertEqual(json.loads(body["body"]), {"error": "too_many_requests"})

        self.assertEqual(status_of(call(app)), 403)

    def test_websocket_rejected_with_policy_close(self):
        app = ShieldASGIMiddleware(hello_app, max_requests=1, window_seconds=10)
        self.assertEqual(call(app, "websocket"), [{"type": "websocket.accept"}])
        self.assertEqual(call(app, "websocket"), [{"type": "websocket.close", "code": 1008}])

    def test_lifespan_is_passed_through_untouched(self):
        seen = []

        async def app(scope, receive, send):
            seen.append(scope["type"])

        shield = Shield(max_requests=1)
        wrapped = ShieldASGIMiddleware(app, shield=shield)
        asyncio.run(wrapped({"type": "lifespan"}, None, None))
        self.assertEqual(seen, ["lifespan"])
        self.assertEqual(shield.stats()["current_rate"], 0.0)  # not counted

    def test_forwarded_for_only_when_trusted(self):
        untrusted = ShieldASGIMiddleware(hello_app, max_requests=1)
        call(untrusted, forwarded="198.51.100.1")
        self.assertEqual(status_of(call(untrusted, forwarded="198.51.100.2")), 429)

        trusted = ShieldASGIMiddleware(hello_app, trust_forwarded_for=True, max_requests=1)
        call(trusted, ip="10.0.0.1", forwarded="198.51.100.1")
        self.assertEqual(status_of(call(trusted, ip="10.0.0.1", forwarded="198.51.100.2")), 200)

    def test_exempt_paths_reachable_while_banned(self):
        app = ShieldASGIMiddleware(hello_app, max_requests=1, exempt_paths=["/shield/stats"])
        call(app)
        self.assertEqual(status_of(call(app)), 429)
        self.assertEqual(status_of(call(app, path="/shield/stats")), 200)

    def test_missing_client_is_unknown(self):
        app = ShieldASGIMiddleware(hello_app, max_requests=1)
        self.assertEqual(app._client_ip({"type": "http"}), "unknown")


if __name__ == "__main__":
    unittest.main()
