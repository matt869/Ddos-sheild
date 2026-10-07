"""How much overhead does DDoS Shield add per request?

    python examples/benchmark.py

Times ``Shield.check`` (the work every protected request does) under a few
realistic setups and prints checks per second and microseconds per check.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ddos_shield import Shield  # noqa: E402

N = 200_000


def bench(label, shield, ips, path=None):
    count = len(ips)
    start = time.perf_counter()
    for i in range(N):
        shield.check(ips[i % count], path=path)
    elapsed = time.perf_counter() - start
    print(f"{label:<44}{N / elapsed:>12,.0f}/s{elapsed / N * 1e6:>9.2f} us")


def main():
    ipv4 = [f"198.51.{i // 256}.{i % 256}" for i in range(5000)]
    ipv6 = [f"2001:db8:{i:x}::1" for i in range(5000)]
    huge = dict(max_requests=10**9, spike_threshold=10**9)

    print(f"{'scenario':<44}{'checks':>14}{'per check':>12}")
    print("-" * 70)
    bench("defaults, 5,000 IPv4 clients", Shield(**huge), ipv4)
    bench("defaults, 5,000 IPv6 clients", Shield(**huge), ipv6)
    bench("allowlist of 3 networks", Shield(
        allowlist=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], **huge), ipv4)
    bench("path limits, request to /login", Shield(
        path_limits={"/login": (10**9, 60), "/api": (10**9, 60)}, **huge), ipv4, "/login")
    flood = Shield(max_requests=10, window_seconds=60, spike_threshold=10**9)
    bench("one banned client flooding", flood, ["203.0.113.66"])


if __name__ == "__main__":
    main()
