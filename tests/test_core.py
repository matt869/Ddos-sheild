"""Tests for the framework-independent Shield core."""

import tempfile
import unittest
from pathlib import Path

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
                                             "rate_limited": 1, "path_limited": 0,
                                             "blocked": 1, "dry_run_passed": 0})
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


class PathLimitTests(unittest.TestCase):
    def make(self, **kwargs):
        return Shield(max_requests=100, window_seconds=60,
                      path_limits={"/login": (3, 60), "/api/": {"max_requests": 5,
                                                                "window_seconds": 10}},
                      **kwargs)

    def test_login_brute_force_is_stopped(self):
        shield = self.make()
        codes = [shield.check("ip", now=t, path="/login").status for t in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])
        d = shield.check("ip", now=5, path="/login")
        self.assertEqual(d.reason, "rate limit exceeded for this path")
        self.assertEqual(d.retry_after, 55)               # first attempt frees at 60

    def test_rest_of_site_still_works(self):
        shield = self.make()
        for t in range(5):
            shield.check("ip", now=t, path="/login")
        self.assertTrue(shield.check("ip", now=5, path="/").allowed)
        self.assertTrue(shield.check("other", now=5, path="/login").allowed)
        self.assertEqual(shield.blocklist.banned(now=5), {})  # no site-wide ban

    def test_sub_paths_and_lookalikes(self):
        shield = self.make()
        self.assertIsNotNone(shield.path_limiter("/api/users/7"))
        self.assertIsNotNone(shield.path_limiter("/login/sso"))
        self.assertIsNone(shield.path_limiter("/loginhelp"))
        self.assertIsNone(shield.path_limiter("/"))

    def test_path_tricks_cannot_bypass_login_limit(self):
        shield = self.make()
        variants = ["/login", "//login", "/./login", "/x/../login", "/login/",
                    "/../login", "///login//"]
        codes = [shield.check("ip", now=0, path=p).status for p in variants]
        self.assertEqual(codes, [200, 200, 200, 429, 429, 429, 429])

    def test_rule_spelling_is_normalized_too(self):
        shield = Shield(path_limits={"//admin/": (1, 60)})
        self.assertIsNotNone(shield.path_limiter("/admin/users"))

    def test_longest_rule_wins(self):
        shield = Shield(path_limits={"/api": (100, 60), "/api/upload": (1, 60)})
        self.assertEqual(shield.path_limiter("/api/upload/x").max_requests, 1)
        self.assertEqual(shield.path_limiter("/api/list").max_requests, 100)

    def test_bad_rule(self):
        with self.assertRaises(ValueError):
            Shield(path_limits={"/login": {"max_request": 5}})

    def test_counted_in_stats(self):
        shield = self.make()
        for t in range(4):
            shield.check("ip", now=t, path="/login")
        self.assertEqual(shield.stats(now=4)["requests"]["path_limited"], 1)


class DryRunTests(unittest.TestCase):
    def test_everything_passes_but_is_recorded(self):
        shield = Shield(max_requests=2, ban_seconds=30, dry_run=True,
                        path_limits={"/login": (1, 60)})
        with self.assertLogs("ddos_shield", level="INFO") as logs:
            results = [shield.check("ip", now=0).allowed for _ in range(5)]
            shield.check("other", now=0, path="/login")
            shield.check("other", now=0, path="/login")
        self.assertEqual(results, [True] * 5)
        counts = shield.stats(now=0)["requests"]
        self.assertEqual(counts["rate_limited"], 1)       # would have been a 429
        self.assertEqual(counts["blocked"], 2)            # would have been 403s
        self.assertEqual(counts["path_limited"], 1)
        self.assertEqual(counts["dry_run_passed"], 4)
        self.assertIn("ip", shield.blocklist.banned(now=0))
        self.assertTrue(any("would reject ip on - with 429" in m for m in logs.output))
        self.assertTrue(shield.stats(now=0)["dry_run"])

    def test_cannot_combine_with_iptables(self):
        with self.assertRaises(ValueError):
            Shield(dry_run=True, use_iptables=True)


class PersistenceTests(unittest.TestCase):
    def test_bans_survive_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "shield-state.json"
            before = Shield(max_requests=1, ban_seconds=600)
            before.check("203.0.113.66")
            self.assertEqual(before.check("203.0.113.66").status, 429)
            before.save_state(path)
            self.assertFalse(Path(f"{path}.tmp").exists())

            after = Shield(max_requests=1, ban_seconds=600)   # "restarted" process
            self.assertEqual(after.load_state(path), 1)
            decision = after.check("203.0.113.66")
            self.assertEqual(decision.status, 403)
            self.assertGreater(decision.retry_after, 590)
            self.assertTrue(after.check("198.51.100.1").allowed)

    def test_missing_file_is_fine(self):
        self.assertEqual(Shield().load_state("no-such-state.json"), 0)

    def test_unknown_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text('{"version": 99, "bans": {}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                Shield().load_state(path)


class OnBanTests(unittest.TestCase):
    def test_called_with_client_and_duration(self):
        events = []
        shield = Shield(max_requests=1, ban_seconds=30,
                        on_ban=lambda client, secs: events.append((client, secs)))
        shield.check("203.0.113.7", now=0)
        shield.check("203.0.113.7", now=0)
        shield.check("203.0.113.7", now=1)   # already banned: no second event
        self.assertEqual(events, [("203.0.113.7", 30.0)])

    def test_broken_hook_is_contained(self):
        def boom(client, secs):
            raise RuntimeError("slack down")

        shield = Shield(max_requests=1, on_ban=boom)
        shield.check("ip", now=0)
        with self.assertLogs("ddos_shield", level="ERROR"):
            self.assertEqual(shield.check("ip", now=0).status, 429)


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
        with self.assertLogs("ddos_shield", level="WARNING") as logs:
            for _ in range(9):
                shield.check("ip", now=0)
            self.assertEqual(alerts, [])
            for _ in range(50):
                shield.check("ip", now=0)
            self.assertEqual(alerts, [10.0])      # once, despite 50 more hits
            for _ in range(20):
                shield.check("ip", now=31)
            self.assertEqual(len(alerts), 2)      # cooldown passed, spike persists
        self.assertEqual(len(logs.output), 2)     # one log line per alert, too

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
