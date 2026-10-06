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

    def test_repeat_offender_retry_after_grows(self):
        shield = Shield(max_requests=1, window_seconds=10, ban_seconds=30,
                        ban_multiplier=4, max_ban_seconds=3600)
        shield.check("ip", now=0)
        self.assertEqual(shield.check("ip", now=0).retry_after, 30)
        shield.check("ip", now=100)                       # ban over, allowed again
        self.assertEqual(shield.check("ip", now=100).retry_after, 120)
        self.assertEqual(shield.check("ip", now=150).status, 403)

    def test_stats(self):
        shield = Shield(max_requests=2, window_seconds=10, ban_seconds=30,
                        spike_threshold=100, sample_seconds=1, allowlist=["10.0.0.1"])
        for ip in ["a", "a", "a", "a", "b", "10.0.0.1"]:
            shield.check(ip, now=0)
        stats = shield.stats(now=0)
        self.assertEqual(stats["requests"], {"allowed": 3, "allowlisted": 1,
                                             "rate_limited": 1, "blocked": 1})
        self.assertEqual(stats["current_rate"], 6.0)
        self.assertFalse(stats["under_attack"])
        self.assertEqual(stats["active_bans"], 1)
        self.assertEqual(stats["tracked_clients"], 2)


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


class ClientKeyTests(unittest.TestCase):
    def test_rotating_ipv6_attacker_is_one_client(self):
        shield = Shield(max_requests=3, window_seconds=60)
        codes = [shield.check(f"2001:db8:aa:bb::{i:x}", now=0).status for i in range(6)]
        self.assertEqual(codes, [200, 200, 200, 429, 403, 403])
        self.assertIn("2001:db8:aa:bb::/64", shield.blocklist.banned(now=0))

    def test_neighbouring_ipv6_networks_are_separate(self):
        shield = Shield(max_requests=1, window_seconds=60)
        shield.check("2001:db8:aa:1::1", now=0)
        self.assertTrue(shield.check("2001:db8:aa:2::1", now=0).allowed)

    def test_per_address_ipv6(self):
        shield = Shield(max_requests=1, window_seconds=60, ipv6_prefix=128)
        shield.check("2001:db8::1", now=0)
        self.assertTrue(shield.check("2001:db8::2", now=0).allowed)

    def test_ipv4_mapped_is_treated_as_ipv4(self):
        shield = Shield(max_requests=1, window_seconds=60)
        shield.check("::ffff:203.0.113.7", now=0)
        self.assertEqual(shield.check("203.0.113.7", now=0).status, 429)

    def test_keys(self):
        shield = Shield()
        self.assertEqual(shield.client_key("203.0.113.7"), "203.0.113.7")
        self.assertEqual(shield.client_key("2001:db8::1"), "2001:db8::/64")
        self.assertEqual(shield.client_key("unknown"), "unknown")

    def test_invalid_prefix(self):
        with self.assertRaises(ValueError):
            Shield(ipv6_prefix=0)


class CleanupTests(unittest.TestCase):
    def test_stale_clients_are_dropped(self):
        shield = Shield(max_requests=5, window_seconds=10, cleanup_interval=60)
        shield.check("first", now=0)
        for i in range(1000):
            shield.check(f"10.0.{i // 256}.{i % 256}", now=1)
        self.assertEqual(len(shield.limiter._hits), 1001)
        shield.check("later", now=100)  # cleanup runs
        self.assertEqual(set(shield.limiter._hits), {"later"})

    def test_expired_bans_are_swept(self):
        shield = Shield(max_requests=1, ban_seconds=5, cleanup_interval=60)
        shield.check("ip", now=0)
        shield.check("ip", now=0)  # banned
        self.assertEqual(len(shield.blocklist._banned), 1)
        shield.check("other", now=100)
        self.assertEqual(len(shield.blocklist._banned), 0)


class AttackAlertTests(unittest.TestCase):
    def test_fires_once_per_cooldown(self):
        alerts = []
        shield = Shield(max_requests=10_000, spike_threshold=10, sample_seconds=1,
                        on_attack=alerts.append, alert_cooldown=30)
        for _ in range(9):
            shield.check("ip", now=0)
        self.assertEqual(alerts, [])
        for _ in range(50):
            shield.check("ip", now=0)
        self.assertEqual(alerts, [10.0])          # once, despite 50 more hits
        for _ in range(20):
            shield.check("ip", now=31)
        self.assertEqual(len(alerts), 2)          # cooldown passed, spike persists

    def test_negative_cooldown_rejected(self):
        with self.assertRaises(ValueError):
            Shield(alert_cooldown=-1)

    def test_broken_callback_does_not_break_requests(self):
        def boom(rate):
            raise RuntimeError("pager down")

        shield = Shield(spike_threshold=1, sample_seconds=1, on_attack=boom)
        with self.assertLogs("ddos_shield", level="ERROR"):
            self.assertTrue(shield.check("ip", now=0).allowed)


if __name__ == "__main__":
    unittest.main()
