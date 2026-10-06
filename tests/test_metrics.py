"""Tests for the Prometheus exporter."""

import re
import unittest

from ddos_shield import Shield
from ddos_shield.metrics import CONTENT_TYPE, prometheus_text

try:
    from prometheus_client.parser import text_string_to_metric_families
except ImportError:  # pragma: no cover
    text_string_to_metric_families = None

# name{labels} value — the shape every sample line must have.
SAMPLE = re.compile(r'^[a-z_]+(\{[a-z_]+="[a-z_]+"\})? -?[0-9.e+]+$')


class PrometheusTests(unittest.TestCase):
    def setUp(self):
        self.shield = Shield(max_requests=1, window_seconds=60, spike_threshold=1000)
        self.shield.check("203.0.113.7")
        self.shield.check("203.0.113.7")    # 429 + ban
        self.shield.check("203.0.113.7")    # 403
        self.text = prometheus_text(self.shield)

    def test_counters(self):
        self.assertIn('ddos_shield_requests_total{outcome="allowed"} 1', self.text)
        self.assertIn('ddos_shield_requests_total{outcome="rate_limited"} 1', self.text)
        self.assertIn('ddos_shield_requests_total{outcome="blocked"} 1', self.text)

    def test_gauges(self):
        self.assertIn("ddos_shield_active_bans 1", self.text)
        self.assertIn("ddos_shield_under_attack 0", self.text)
        self.assertIn("# TYPE ddos_shield_request_rate gauge", self.text)

    def test_every_line_is_valid_exposition_format(self):
        for line in self.text.splitlines():
            if line.startswith("# HELP ") or line.startswith("# TYPE "):
                continue
            self.assertRegex(line, SAMPLE)
        self.assertTrue(self.text.endswith("\n"))

    @unittest.skipIf(text_string_to_metric_families is None, "prometheus_client not installed")
    def test_official_parser_accepts_output(self):
        families = {f.name: f for f in text_string_to_metric_families(self.text)}
        self.assertEqual(families["ddos_shield_requests"].type, "counter")
        self.assertEqual(families["ddos_shield_active_bans"].samples[0].value, 1)

    def test_custom_prefix(self):
        self.assertIn("myapp_active_bans 1", prometheus_text(self.shield, prefix="myapp"))

    def test_content_type(self):
        self.assertTrue(CONTENT_TYPE.startswith("text/plain; version=0.0.4"))


if __name__ == "__main__":
    unittest.main()
