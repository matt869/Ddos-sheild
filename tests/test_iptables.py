"""Firewall enforcement, with iptables mocked out (no root or Linux needed).

These pin down the exact commands issued, because a wrong one either leaves an
attacker unblocked or leaves a stale DROP rule that locks out a real user.
"""

import subprocess
import unittest
from unittest import mock

from ddos_shield import BlockList, Shield


def rule(action, ip):
    return ["iptables", action, "INPUT", "-s", ip, "-j", "DROP"]


class IptablesTests(unittest.TestCase):
    def setUp(self):
        which = mock.patch("ddos_shield.blocklist.shutil.which", return_value="/sbin/iptables")
        run = mock.patch("ddos_shield.blocklist.subprocess.run")
        which.start()
        self.run = run.start()
        self.addCleanup(mock.patch.stopall)

    def commands(self):
        return [c.args[0] for c in self.run.call_args_list]

    def test_ban_adds_one_drop_rule(self):
        bl = BlockList(ban_seconds=10, use_iptables=True)
        bl.ban("203.0.113.7", now=0)
        bl.ban("203.0.113.7", now=1)          # re-ban while banned: no duplicate rule
        self.assertEqual(self.commands(), [rule("-A", "203.0.113.7")])
        kwargs = self.run.call_args.kwargs
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 5)

    def test_expiry_removes_the_rule(self):
        bl = BlockList(ban_seconds=10, use_iptables=True)
        bl.ban("203.0.113.7", now=0)
        self.assertFalse(bl.is_banned("203.0.113.7", now=11))
        self.assertEqual(self.commands()[-1], rule("-D", "203.0.113.7"))

    def test_unban_and_sweep_remove_rules(self):
        bl = BlockList(ban_seconds=10, use_iptables=True)
        bl.ban("a", now=0)
        bl.ban("b", now=0)
        bl.unban("a")
        bl.unban("a")                         # already gone: no second delete
        self.assertEqual(bl.sweep(now=100), 1)
        self.assertEqual(self.commands(), [rule("-A", "a"), rule("-A", "b"),
                                           rule("-D", "a"), rule("-D", "b")])

    def test_restored_bans_are_re_added(self):
        bl = BlockList(use_iptables=True)
        bl.import_state({"bans": {"203.0.113.7": 2000.0}}, now=0, wall=1000)
        self.assertEqual(self.commands(), [rule("-A", "203.0.113.7")])

    def test_failure_is_logged_and_ban_still_applies(self):
        self.run.side_effect = subprocess.CalledProcessError(1, "iptables")
        bl = BlockList(ban_seconds=10, use_iptables=True)
        with self.assertLogs("ddos_shield.blocklist", level="WARNING") as logs:
            bl.ban("203.0.113.7", now=0)
        self.assertTrue(bl.is_banned("203.0.113.7", now=1))
        self.assertIn("iptables -A 203.0.113.7 failed", logs.output[0])

    def test_shield_bans_through_the_firewall(self):
        shield = Shield(max_requests=1, use_iptables=True)
        shield.check("203.0.113.7", now=0)
        shield.check("203.0.113.7", now=0)
        self.assertEqual(self.commands(), [rule("-A", "203.0.113.7")])


class MissingIptablesTests(unittest.TestCase):
    def test_disabled_with_warning_when_not_installed(self):
        with mock.patch("ddos_shield.blocklist.shutil.which", return_value=None), \
                mock.patch("ddos_shield.blocklist.subprocess.run") as run, \
                self.assertLogs("ddos_shield.blocklist", level="WARNING") as logs:
            bl = BlockList(use_iptables=True)
            bl.ban("203.0.113.7", now=0)
        self.assertFalse(bl.use_iptables)
        run.assert_not_called()
        self.assertIn("iptables not found", logs.output[0])


class ValidationTests(unittest.TestCase):
    def test_bad_settings_rejected(self):
        bad = [
            lambda: BlockList(ban_seconds=0),
            lambda: BlockList(offense_memory=0),
            lambda: Shield(max_requests=0),
            lambda: Shield(window_seconds=0),
            lambda: Shield(spike_threshold=0),
            lambda: Shield(sample_seconds=0),
            lambda: Shield(cleanup_interval=0),
        ]
        for make in bad:
            with self.assertRaises(ValueError):
                make()


if __name__ == "__main__":
    unittest.main()
