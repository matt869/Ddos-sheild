"""Command line helpers.

    python -m ddos_shield check-config config.yaml
    python -m ddos_shield --version
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .config import load_config
from .shield import Shield


def check_config(path: str) -> int:
    try:
        options = load_config(path)
        shield = Shield(**options)
    except (OSError, ValueError, TypeError, ImportError) as exc:
        print(f"{path}: invalid - {exc}", file=sys.stderr)
        return 1

    print(f"{path}: OK")
    print(f"  rate limit : {shield.limiter.max_requests} requests "
          f"per {shield.limiter.window_seconds:g}s per client")
    print(f"  ban        : {shield.blocklist.ban_seconds:g}s"
          + (" (+ iptables)" if shield.blocklist.use_iptables else ""))
    print(f"  spike alert: {shield.monitor.spike_threshold:g} req/s "
          f"over {shield.monitor.sample_seconds:g}s")
    allowlist = ", ".join(str(net) for net in shield.allowlist) or "(none)"
    print(f"  allowlist  : {allowlist}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ddos_shield")
    parser.add_argument("--version", action="version", version=f"ddos-shield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-config", help="validate a YAML config file")
    check.add_argument("path")

    args = parser.parse_args(argv)
    if args.command == "check-config":
        return check_config(args.path)
    return 2  # pragma: no cover - argparse rejects unknown commands


if __name__ == "__main__":
    sys.exit(main())
