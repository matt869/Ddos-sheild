"""Thread-safety: many threads hammering one Shield must never over-admit."""

import sys
import threading
import unittest
from collections import Counter

from ddos_shield import Shield

THREADS = 16
PER_THREAD = 500


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        # Switch threads as often as possible so races actually show up.
        self._interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)

    def tearDown(self):
        sys.setswitchinterval(self._interval)
    def hammer(self, shield, pick_ip, path=None):
        results = Counter()
        lock = threading.Lock()
        start = threading.Barrier(THREADS)

        def worker(n):
            local = Counter()
            start.wait()  # release every thread at once for maximum contention
            for i in range(PER_THREAD):
                ip = pick_ip(n, i)
                local[(ip, shield.check(ip, now=0, path=path).status)] += 1
            with lock:
                results.update(local)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results

    def test_each_client_gets_exactly_its_budget(self):
        shield = Shield(max_requests=50, window_seconds=60, spike_threshold=10**9)
        clients = [f"198.51.100.{i}" for i in range(20)]
        results = self.hammer(shield, lambda n, i: clients[(n + i) % len(clients)])
        for ip in clients:
            self.assertEqual(results[(ip, 200)], 50, ip)
            self.assertEqual(results[(ip, 429)], 1, ip)   # exactly one ban event

    def test_counters_add_up(self):
        shield = Shield(max_requests=10, window_seconds=60, spike_threshold=10**9)
        self.hammer(shield, lambda n, i: f"203.0.113.{i % 50}")
        counts = shield.stats(now=0)["requests"]
        self.assertEqual(sum(counts.values()), THREADS * PER_THREAD)
        self.assertEqual(counts["allowed"], 50 * 10)
        self.assertEqual(counts["rate_limited"], 50)

    def test_burst_bans_once_and_does_not_escalate(self):
        for _ in range(10):
            bans = []
            shield = Shield(max_requests=5, ban_multiplier=2, spike_threshold=10**9,
                            on_ban=lambda client, secs, bans=bans: bans.append(secs))
            self.hammer(shield, lambda n, i: "203.0.113.9")
            self.assertEqual(bans, [300.0])
            self.assertEqual(shield.blocklist.offenses("203.0.113.9", now=0), 1)

    def test_path_limit_is_exact_under_contention(self):
        shield = Shield(max_requests=10**6, spike_threshold=10**9,
                        path_limits={"/login": (7, 60)})
        results = self.hammer(shield, lambda n, i: "198.51.100.1", path="/login")
        self.assertEqual(results[("198.51.100.1", 200)], 7)

    def test_attack_alert_fires_once(self):
        alerts = []
        shield = Shield(max_requests=10**6, spike_threshold=100, sample_seconds=1,
                        on_attack=alerts.append, alert_cooldown=60)
        with self.assertLogs("ddos_shield", level="WARNING"):
            self.hammer(shield, lambda n, i: f"198.51.100.{n}")
        self.assertEqual(len(alerts), 1)


if __name__ == "__main__":
    unittest.main()
