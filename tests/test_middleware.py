"""Tests for the Flask integration.

The Flask tests are skipped automatically when Flask isn't installed.
"""

import unittest

from ddos_shield.middleware import client_ip

try:
    import flask
except ImportError:  # pragma: no cover
    flask = None


class ClientIpTests(unittest.TestCase):
    def test_uses_first_forwarded_hop(self):
        headers = {"X-Forwarded-For": "198.51.100.1, 10.0.0.1"}
        self.assertEqual(client_ip(headers, "10.0.0.2"), "198.51.100.1")

    def test_falls_back_to_remote_addr(self):
        self.assertEqual(client_ip({}, "203.0.113.7"), "203.0.113.7")

    def test_unknown_when_nothing_available(self):
        self.assertEqual(client_ip({}, ""), "unknown")


@unittest.skipIf(flask is None, "Flask not installed")
class ProtectTests(unittest.TestCase):
    def make_client(self, **kwargs):
        from ddos_shield.middleware import protect

        app = flask.Flask(__name__)
        protect(app, **kwargs)

        @app.route("/")
        def home():
            return "ok"

        return app.test_client()

    def test_limits_then_bans(self):
        client = self.make_client(max_requests=2, window_seconds=10, ban_seconds=30)
        codes = [client.get("/").status_code for _ in range(4)]
        self.assertEqual(codes, [200, 200, 429, 403])

    def test_retry_after_matches_ban(self):
        client = self.make_client(max_requests=1, window_seconds=10, ban_seconds=30.5)
        client.get("/")
        self.assertEqual(client.get("/").headers["Retry-After"], "31")
        self.assertEqual(client.get("/").headers["Retry-After"], "31")

    def test_banned_retry_after_counts_down(self):
        client = self.make_client(max_requests=1, window_seconds=10, ban_seconds=30)
        client.get("/")
        client.get("/")  # trips the limit -> banned
        blocklist = client.application.extensions["ddos_shield"]["blocklist"]
        ip = next(iter(blocklist._banned))
        blocklist._banned[ip] -= 20  # pretend 20s have passed
        self.assertEqual(client.get("/").headers["Retry-After"], "10")

    def test_monitor_settings_passed_through(self):
        client = self.make_client(spike_threshold=50, sample_seconds=2)
        monitor = client.application.extensions["ddos_shield"]["monitor"]
        self.assertEqual(monitor.spike_threshold, 50)
        self.assertEqual(monitor.sample_seconds, 2)

    def test_exempt_paths(self):
        from ddos_shield.middleware import protect

        app = flask.Flask(__name__)
        protect(app, max_requests=1, window_seconds=10, exempt_paths=["/health"])
        app.add_url_rule("/", "home", lambda: "ok")
        app.add_url_rule("/health", "health", lambda: "ok")
        client = app.test_client()
        client.get("/")
        self.assertEqual(client.get("/").status_code, 429)
        self.assertEqual(client.get("/health").status_code, 200)

    def test_allowlist_option(self):
        client = self.make_client(max_requests=1, window_seconds=10, allowlist=["127.0.0.1"])
        codes = {client.get("/").status_code for _ in range(5)}
        self.assertEqual(codes, {200})


if __name__ == "__main__":
    unittest.main()
