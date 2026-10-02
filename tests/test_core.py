"""Tests for the framework-independent Shield core."""

import unittest

from ddos_shield.shield import Shield


class ShieldTests(unittest.TestCase):
    def test_allow_limit_ban_sequence(self):
        shield = Shield(max_requests=2, window_seconds=10, ban_seconds=30)
        statuses = [shield.check("ip", now=0).status for _ in range(4)]
        self.assertEqual(statuses, [200, 200, 429, 403])

    def test_clients_are_isolated(self):
        shield = Shield(max_requests=1, window_seconds=10, ban_seconds=30)
        shield.check("noisy", now=0)
        self.assertFalse(shield.check("noisy", now=0).allowed)
        self.assertTrue(shield.check("quiet", now=0).allowed)

    def test_retry_after_tracks_ban(self):
        shield = Shield(max_requests=1, window_seconds=10, ban_seconds=30)
        shield.check("ip", now=0)
        self.assertEqual(shield.check("ip", now=0).retry_after, 30)
        self.assertEqual(shield.check("ip", now=12.5).retry_after, 18)

    def test_ban_lifts(self):
        shield = Shield(max_requests=1, window_seconds=10, ban_seconds=30)
        shield.check("ip", now=0)
        shield.check("ip", now=0)  # banned
        self.assertTrue(shield.check("ip", now=31).allowed)


class AllowlistTests(unittest.TestCase):
    def test_allowlisted_ip_never_limited(self):
        shield = Shield(max_requests=1, window_seconds=10, allowlist=["127.0.0.1"])
        self.assertTrue(all(shield.check("127.0.0.1", now=0).allowed for _ in range(50)))

    def test_cidr_range(self):
        shield = Shield(max_requests=1, window_seconds=10, allowlist=["10.0.0.0/8"])
        for _ in range(5):
            self.assertTrue(shield.check("10.20.30.40", now=0).allowed)
        shield.check("11.0.0.1", now=0)
        self.assertFalse(shield.check("11.0.0.1", now=0).allowed)

    def test_ipv6_and_garbage(self):
        shield = Shield(allowlist=["2001:db8::/32"])
        self.assertTrue(shield.is_allowlisted("2001:db8::1"))
        self.assertFalse(shield.is_allowlisted("unknown"))

    def test_invalid_entry_rejected(self):
        with self.assertRaises(ValueError):
            Shield(allowlist=["not-an-ip"])


if __name__ == "__main__":
    unittest.main()
