"""End-to-end tests against a real HTTP server on 127.0.0.1.

Spins up a threaded WSGI server in-process, wraps it with ShieldMiddleware and
talks to it over real sockets with urllib. Clients are told apart by
X-Forwarded-For, as they would be behind a reverse proxy.
"""

import json
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from ddos_shield.wsgi import ShieldMiddleware


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass


def _app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


class LiveServer:
    """Context manager running a protected app on an ephemeral local port."""

    def __init__(self, **options):
        self.alerts = []
        options.setdefault("on_attack", self.alerts.append)
        self.app = ShieldMiddleware(_app, trust_forwarded_for=True, **options)

    def __enter__(self):
        self.server = make_server("127.0.0.1", 0, self.app,
                                  server_class=_ThreadingWSGIServer,
                                  handler_class=_QuietHandler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def get(self, client):
        """GET / as ``client``; returns (status, headers, body)."""
        req = urllib.request.Request(self.url, headers={"X-Forwarded-For": client})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, err.headers, err.read()


class LiveServerTests(unittest.TestCase):
    def test_abuser_is_blocked_while_normal_users_are_served(self):
        with LiveServer(max_requests=5, window_seconds=60, ban_seconds=120) as srv:
            normal = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
            abuser = "203.0.113.66"

            abuser_codes = [srv.get(abuser)[0] for _ in range(10)]
            self.assertEqual(abuser_codes, [200] * 5 + [429] + [403] * 4)

            for user in normal:
                self.assertEqual([srv.get(user)[0] for _ in range(3)], [200, 200, 200])

            status, headers, body = srv.get(abuser)
            self.assertEqual(status, 403)
            self.assertLessEqual(int(headers["Retry-After"]), 120)
            self.assertEqual(json.loads(body)["error"], "forbidden")

    def test_concurrent_burst_admits_exactly_the_limit(self):
        with LiveServer(max_requests=10, window_seconds=60, ban_seconds=60) as srv:
            with ThreadPoolExecutor(max_workers=16) as pool:
                codes = list(pool.map(lambda _: srv.get("203.0.113.9")[0], range(40)))
            # Thread-safe limiter: exactly 10 get through, however they interleave.
            self.assertEqual(codes.count(200), 10)
            self.assertEqual(codes.count(429) + codes.count(403), 30)

    def test_allowlisted_health_checker_is_never_blocked(self):
        with LiveServer(max_requests=2, window_seconds=60,
                        allowlist=["10.0.0.0/8"]) as srv:
            self.assertEqual({srv.get("10.1.1.1")[0] for _ in range(20)}, {200})

    def test_spike_raises_alert(self):
        with LiveServer(max_requests=1000, spike_threshold=20, sample_seconds=5) as srv:
            with self.assertLogs("ddos_shield", level="WARNING") as logs:
                for i in range(150):  # needs 100 within the 5s window to trip
                    srv.get(f"198.51.100.{i}")
            self.assertIn("Traffic spike", logs.output[0])
            self.assertEqual(len(srv.alerts), 1)  # one alert, not one per request
            self.assertGreaterEqual(srv.alerts[0], 20)


if __name__ == "__main__":
    unittest.main()
