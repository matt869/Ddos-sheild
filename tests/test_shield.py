"""Unit tests for DDoS Shield core components.

Run with:  python -m pytest    (or)    python -m unittest
Tests inject an explicit clock so they are fast and deterministic.
"""

import unittest

from ddos_shield import BlockList, RateLimiter, TrafficMonitor


class RateLimiterTests(unittest.TestCase):
    def test_allows_up_to_limit_then_blocks(self):
        rl = RateLimiter(max_requests=3, window_seconds=60)
        self.assertEqual([rl.allow("ip", now=0) for _ in range(5)],
                         [True, True, True, False, False])

    def test_window_slides(self):
        rl = RateLimiter(max_requests=2, window_seconds=10)
        self.assertTrue(rl.allow("ip", now=0))
        self.assertTrue(rl.allow("ip", now=1))
        self.assertFalse(rl.allow("ip", now=2))       # over limit
        self.assertTrue(rl.allow("ip", now=11))        # first hit aged out

    def test_remaining_does_not_track_unseen_keys(self):
        rl = RateLimiter(max_requests=5, window_seconds=10)
        self.assertEqual(rl.remaining("never-seen", now=0), 5)
        self.assertEqual(rl.prune(now=0), 0)  # nothing was stored

    def test_remaining_counts_down(self):
        rl = RateLimiter(max_requests=3, window_seconds=10)
        rl.allow("ip", now=0)
        self.assertEqual(rl.remaining("ip", now=1), 2)
        self.assertEqual(rl.remaining("ip", now=20), 3)  # window expired

    def test_retry_after(self):
        rl = RateLimiter(max_requests=2, window_seconds=10)
        self.assertEqual(rl.retry_after("ip", now=0), 0.0)
        rl.allow("ip", now=0)
        rl.allow("ip", now=4)
        self.assertEqual(rl.retry_after("ip", now=6), 4.0)   # hit at 0 frees at 10
        self.assertEqual(rl.retry_after("ip", now=10), 0.0)

    def test_prune_removes_stale_clients(self):
        rl = RateLimiter(max_requests=5, window_seconds=10)
        rl.allow("gone", now=0)
        self.assertEqual(rl.prune(now=100), 1)


class TrafficMonitorTests(unittest.TestCase):
    def test_spike_detection(self):
        tm = TrafficMonitor(spike_threshold=2, sample_seconds=5)
        for _ in range(9):
            tm.record(now=0)
        self.assertFalse(tm.is_under_attack(now=0))
        tm.record(now=0)  # 10 events / 5s = 2.0/s
        self.assertTrue(tm.is_under_attack(now=0))

    def test_rate_decays(self):
        tm = TrafficMonitor(spike_threshold=1, sample_seconds=5)
        for _ in range(10):
            tm.record(now=0)
        self.assertEqual(tm.current_rate(now=100), 0.0)


class BlockListTests(unittest.TestCase):
    def test_ban_expires(self):
        bl = BlockList(ban_seconds=10, use_iptables=False)
        bl.ban("ip", now=0)
        self.assertTrue(bl.is_banned("ip", now=5))
        self.assertFalse(bl.is_banned("ip", now=20))

    def test_time_remaining(self):
        bl = BlockList(ban_seconds=10, use_iptables=False)
        self.assertEqual(bl.time_remaining("ip", now=0), 0.0)
        bl.ban("ip", now=0)
        self.assertEqual(bl.time_remaining("ip", now=4), 6.0)
        self.assertEqual(bl.time_remaining("ip", now=50), 0.0)

    def test_banned_snapshot(self):
        bl = BlockList(ban_seconds=10, use_iptables=False)
        bl.ban("a", now=0)
        bl.ban("b", now=5)
        self.assertEqual(bl.banned(now=8), {"a": 2.0, "b": 7.0})
        self.assertEqual(bl.banned(now=12), {"b": 3.0})

    def test_escalating_bans(self):
        bl = BlockList(ban_seconds=10, ban_multiplier=2, max_ban_seconds=50,
                       offense_memory=1000, use_iptables=False)
        self.assertEqual(bl.ban("ip", now=0), 10)
        self.assertEqual(bl.ban("ip", now=20), 20)
        self.assertEqual(bl.ban("ip", now=60), 40)
        self.assertEqual(bl.ban("ip", now=120), 50)   # capped
        self.assertEqual(bl.offenses("ip", now=120), 4)

    def test_offenses_forgotten_after_memory(self):
        bl = BlockList(ban_seconds=10, ban_multiplier=2, offense_memory=100,
                       use_iptables=False)
        bl.ban("ip", now=0)
        self.assertEqual(bl.ban("ip", now=500), 10)    # clean slate
        bl.sweep(now=1000)
        self.assertEqual(bl.offenses("ip", now=1000), 0)
        self.assertEqual(bl._offenses, {})

    def test_default_bans_do_not_escalate(self):
        bl = BlockList(ban_seconds=10, use_iptables=False)
        self.assertEqual([bl.ban("ip", now=t) for t in (0, 20, 40)], [10, 10, 10])

    def test_invalid_escalation_settings(self):
        with self.assertRaises(ValueError):
            BlockList(ban_multiplier=0.5)
        with self.assertRaises(ValueError):
            BlockList(ban_seconds=60, max_ban_seconds=30)

    def test_try_ban_only_bans_once(self):
        bl = BlockList(ban_seconds=10, ban_multiplier=2, use_iptables=False)
        self.assertEqual(bl.try_ban("ip", now=0), 10)
        self.assertIsNone(bl.try_ban("ip", now=5))      # still banned
        self.assertEqual(bl.offenses("ip", now=5), 1)   # not escalated
        self.assertEqual(bl.try_ban("ip", now=11), 20)  # expired -> new offense

    def test_export_import_round_trip(self):
        old = BlockList(ban_seconds=100, ban_multiplier=2, use_iptables=False)
        old.ban("a", now=0)
        old.ban("b", now=0)
        old.ban("b", now=0)                     # second offense: 200s
        state = old.export_state(now=50, wall=1_000_000)
        self.assertEqual(state["bans"], {"a": 1_000_050.0, "b": 1_000_150.0})

        # New process: different monotonic clock, 20s of wall time later.
        new = BlockList(ban_seconds=100, ban_multiplier=2, use_iptables=False)
        self.assertEqual(new.import_state(state, now=7, wall=1_000_020), 2)
        self.assertEqual(new.time_remaining("a", now=7), 30)
        self.assertEqual(new.time_remaining("b", now=7), 130)
        self.assertEqual(new.offenses("b", now=7), 2)   # escalation remembered

    def test_import_skips_expired(self):
        bl = BlockList(use_iptables=False)
        state = {"bans": {"old": 900.0, "live": 1100.0}, "offenses": {}}
        self.assertEqual(bl.import_state(state, now=0, wall=1000), 1)
        self.assertEqual(list(bl.banned(now=0)), ["live"])

    def test_unban(self):
        bl = BlockList(ban_seconds=10, use_iptables=False)
        bl.ban("ip", now=0)
        bl.unban("ip")
        self.assertFalse(bl.is_banned("ip", now=1))

    def test_sweep(self):
        bl = BlockList(ban_seconds=5, use_iptables=False)
        bl.ban("a", now=0)
        bl.ban("b", now=0)
        self.assertEqual(bl.sweep(now=100), 2)


if __name__ == "__main__":
    unittest.main()
