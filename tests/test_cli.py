"""Tests for ``python -m ddos_shield``."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from ddos_shield.__main__ import main

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

EXAMPLE = str(Path(__file__).resolve().parent.parent / "config.example.yaml")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


@unittest.skipIf(yaml is None, "PyYAML not installed")
class CheckConfigTests(unittest.TestCase):
    def test_example_config_is_valid(self):
        code, out, _ = run("check-config", EXAMPLE)
        self.assertEqual(code, 0)
        self.assertIn("60 requests per 60s per client", out)
        self.assertIn("10.0.0.0/8", out)

    def test_typo_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("rate_limiter:\n  max_request: 5\n", encoding="utf-8")
            code, _, err = run("check-config", str(path))
        self.assertEqual(code, 1)
        self.assertIn("max_request", err)

    def test_bad_value_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("rate_limiter:\n  max_requests: 0\n", encoding="utf-8")
            code, _, err = run("check-config", str(path))
        self.assertEqual(code, 1)
        self.assertIn("max_requests must be positive", err)

    def test_missing_file(self):
        code, _, err = run("check-config", "does-not-exist.yaml")
        self.assertEqual(code, 1)
        self.assertIn("invalid", err)


if __name__ == "__main__":
    unittest.main()
