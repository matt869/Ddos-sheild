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


if __name__ == "__main__":
    unittest.main()
