"""Unit tests for DDoS Shield core components.

Run with:  python -m pytest    (or)    python -m unittest
Tests inject an explicit clock so they are fast and deterministic.
"""

import unittest

from ddos_shield import RateLimiter, TrafficMonitor, BlockList


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
