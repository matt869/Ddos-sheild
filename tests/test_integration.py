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

    def get(self, client, path="/"):
        """GET ``path`` as ``client``; returns (status, headers, body)."""
        req = urllib.request.Request(self.url.rstrip("/") + path,
                                     headers={"X-Forwarded-For": client})
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

    def test_login_brute_force_blocked_but_site_still_usable(self):
        with LiveServer(max_requests=100, path_limits={"/login": (3, 60)}) as srv:
            attempts = [srv.get("198.51.100.5", "/login")[0] for _ in range(6)]
            self.assertEqual(attempts, [200, 200, 200, 429, 429, 429])

            status, headers, body = srv.get("198.51.100.5", "/login")
            self.assertEqual(json.loads(body)["error"], "too_many_requests")
            self.assertGreater(int(headers["Retry-After"]), 50)

            self.assertEqual(srv.get("198.51.100.5", "/products")[0], 200)
            self.assertEqual(srv.get("198.51.100.6", "/login")[0], 200)

    def test_rotating_ipv6_attacker_is_caught(self):
        with LiveServer(max_requests=5, window_seconds=60, ban_seconds=60) as srv:
            codes = [srv.get(f"2001:db8:bad:1::{i:x}")[0] for i in range(1, 21)]
            self.assertEqual(codes.count(200), 5)       # 20 addresses, one budget
            # A different customer on another /64 is unaffected.
            self.assertEqual(srv.get("2001:db8:900d:1::1")[0], 200)

    def test_repeat_offender_gets_a_longer_ban(self):
        with LiveServer(max_requests=1, ban_seconds=10, ban_multiplier=6) as srv:
            srv.get("203.0.113.50")
            self.assertEqual(srv.get("203.0.113.50")[1]["Retry-After"], "10")
            # Simulate the first ban running out, then offend again.
            shield = srv.app.shield
            shield.blocklist.unban("203.0.113.50")
            shield.limiter.reset("203.0.113.50")
            srv.get("203.0.113.50")
            self.assertEqual(srv.get("203.0.113.50")[1]["Retry-After"], "60")

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
