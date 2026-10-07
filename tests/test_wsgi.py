"""Tests for the plain WSGI middleware (standard library only)."""

import json
import unittest
from wsgiref.util import setup_testing_defaults

from ddos_shield import Shield
from ddos_shield.wsgi import ShieldMiddleware


def hello_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"hello"]


def call(app, ip="203.0.113.7", forwarded=None):
    environ = {"REMOTE_ADDR": ip}
    if forwarded:
        environ["HTTP_X_FORWARDED_FOR"] = forwarded
    setup_testing_defaults(environ)
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body


class ShieldMiddlewareTests(unittest.TestCase):
    def test_passes_through_then_limits(self):
        app = ShieldMiddleware(hello_app, max_requests=2, window_seconds=10, ban_seconds=30)
        self.assertEqual(call(app)[2], b"hello")
        self.assertEqual(call(app)[2], b"hello")

        status, headers, body = call(app)
        self.assertEqual(status, "429 Too Many Requests")
        self.assertEqual(headers["Retry-After"], "30")
        self.assertEqual(json.loads(body), {"error": "too_many_requests"})

        status, headers, body = call(app)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(json.loads(body)["reason"], "temporarily blocked")
        self.assertEqual(headers["Content-Length"], str(len(body)))

    def test_forwarded_for_ignored_unless_trusted(self):
        app = ShieldMiddleware(hello_app, max_requests=1, window_seconds=10)
        call(app, forwarded="198.51.100.1")
        # Different spoofed header, same socket address -> still limited.
        self.assertTrue(call(app, forwarded="198.51.100.2")[0].startswith("429"))

    def test_forwarded_for_when_trusted(self):
        app = ShieldMiddleware(hello_app, trust_forwarded_for=True,
                               max_requests=1, window_seconds=10)
        call(app, ip="10.0.0.1", forwarded="198.51.100.1")
        # Same proxy address, different real client -> allowed.
        self.assertEqual(call(app, ip="10.0.0.1", forwarded="198.51.100.2")[0], "200 OK")

    def test_exempt_paths_are_never_limited(self):
        app = ShieldMiddleware(hello_app, max_requests=1, exempt_paths=["/health"])

        def get(path):
            environ = {"REMOTE_ADDR": "203.0.113.7", "PATH_INFO": path}
            setup_testing_defaults(environ)
            status = []
            app(environ, lambda s, h: status.append(s))
            return status[0]

        self.assertEqual([get("/health") for _ in range(5)], ["200 OK"] * 5)
        self.assertEqual(get("/"), "200 OK")  # health checks didn't use the budget
        self.assertTrue(get("/").startswith("429"))
        self.assertEqual(get("/health"), "200 OK")  # still reachable while banned

    def test_path_limits_use_path_info(self):
        app = ShieldMiddleware(hello_app, path_limits={"/login": (1, 60)})

        def get(path):
            environ = {"REMOTE_ADDR": "203.0.113.7", "PATH_INFO": path}
            setup_testing_defaults(environ)
            status = []
            app(environ, lambda s, h: status.append(s))
            return status[0]

        self.assertEqual(get("/login"), "200 OK")
        self.assertTrue(get("/login").startswith("429"))
        self.assertEqual(get("/"), "200 OK")

    def test_forged_forwarded_for_cannot_rotate_identity(self):
        app = ShieldMiddleware(hello_app, trust_forwarded_for=True, max_requests=5)
        codes = [call(app, ip="10.0.0.1", forwarded=f"1.2.3.{i}, 203.0.113.66")[0][:3]
                 for i in range(50)]
        self.assertEqual(codes.count("200"), 5)

    def test_proxy_count(self):
        app = ShieldMiddleware(hello_app, trust_forwarded_for=2, max_requests=1)
        call(app, ip="10.0.0.1", forwarded="9.9.9.9, 198.51.100.1, 172.16.0.9")
        status = call(app, ip="10.0.0.1", forwarded="8.8.8.8, 198.51.100.1, 172.16.0.9")[0]
        self.assertTrue(status.startswith("429"))
        with self.assertRaises(ValueError):
            ShieldMiddleware(hello_app, trust_forwarded_for=-1)

    def test_rate_limit_headers(self):
        app = ShieldMiddleware(hello_app, max_requests=2, rate_limit_headers=True)
        status, headers, body = call(app)
        self.assertEqual((status, body), ("200 OK", b"hello"))
        self.assertEqual(headers["Content-Type"], "text/plain")   # app's own headers kept
        self.assertEqual(headers["RateLimit-Remaining"], "1")
        call(app)
        status, headers, _ = call(app)
        self.assertTrue(status.startswith("429"))
        self.assertEqual(headers["RateLimit-Remaining"], "0")

    def test_accepts_existing_shield(self):
        shield = Shield(max_requests=1)
        app = ShieldMiddleware(hello_app, shield=shield)
        self.assertIs(app.shield, shield)
        with self.assertRaises(TypeError):
            ShieldMiddleware(hello_app, shield=shield, max_requests=5)


if __name__ == "__main__":
    unittest.main()
