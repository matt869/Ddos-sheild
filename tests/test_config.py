"""Tests for loading Shield settings from config files."""

import tempfile
import unittest
from pathlib import Path

from ddos_shield import Shield
from ddos_shield.config import load_config, parse_config

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

EXAMPLE = Path(__file__).resolve().parent.parent / "config.example.yaml"


class ParseConfigTests(unittest.TestCase):
    def test_flattens_sections(self):
        options = parse_config({
            "rate_limiter": {"max_requests": 5, "window_seconds": 1},
            "blocklist": {"ban_seconds": 10},
            "allowlist": ["127.0.0.1"],
        })
        self.assertEqual(options, {"max_requests": 5, "window_seconds": 1,
                                   "ban_seconds": 10, "allowlist": ["127.0.0.1"]})

    def test_empty_file_means_defaults(self):
        self.assertEqual(parse_config(None), {})

    def test_typo_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            parse_config({"rate_limiter": {"max_request": 5}})
        self.assertIn("max_request", str(ctx.exception))

    def test_unknown_section_rejected(self):
        with self.assertRaises(ValueError):
            parse_config({"firewall": {}})


@unittest.skipIf(yaml is None, "PyYAML not installed")
class LoadConfigTests(unittest.TestCase):
    def test_example_config_builds_a_shield(self):
        shield = Shield(**load_config(EXAMPLE))
        self.assertEqual(shield.limiter.max_requests, 60)
        self.assertEqual(shield.blocklist.ban_seconds, 300)
        self.assertTrue(shield.is_allowlisted("10.1.2.3"))
        self.assertEqual(shield.path_limiter("/login").max_requests, 5)

    def test_load_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            path.write_text("rate_limiter:\n  max_requests: 3\n", encoding="utf-8")
            self.assertEqual(load_config(path), {"max_requests": 3})


if __name__ == "__main__":
    unittest.main()
