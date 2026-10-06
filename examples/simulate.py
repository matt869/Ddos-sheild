"""Watch DDoS Shield handle a realistic traffic mix — no setup needed.

    python examples/simulate.py

Starts a protected WSGI app on 127.0.0.1 (in this process, on a random free
port) and plays these clients against it at the same time:

  * visitors         - a handful of people browsing at a normal pace
  * returning user   - logs in, mistyping the password once
  * health checker   - your load balancer polling, allowlisted
  * scraper          - one client hammering as fast as it can
  * password guesser - brute-forcing /login
  * IPv6 rotator     - a bot using a fresh IPv6 address for every request

then prints what each one experienced. Clients are told apart by
X-Forwarded-For, as they would be behind a reverse proxy.
"""

import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

# Make the package importable when running this file directly from the repo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ddos_shield.wsgi import ShieldMiddleware  # noqa: E402


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def site(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"welcome"]


alerts = []
bans = []
app = ShieldMiddleware(
    site,
    trust_forwarded_for=True,
    max_requests=20,          # per client...
    window_seconds=10,        # ...per 10 seconds
    ban_seconds=30,
    ban_multiplier=2,         # repeat offenders get longer bans
    path_limits={"/login": (5, 60)},
    spike_threshold=40,       # site-wide req/s that counts as an attack
    sample_seconds=2,
    allowlist=["10.0.0.0/8"],
    on_attack=lambda rate: alerts.append(rate),
    on_ban=lambda client, seconds: bans.append(client),
)

# name, address (or a function of the request number), path, requests, delay
CLIENTS = [
    *[(f"visitor {n}", f"198.51.100.{n}", "/", 8, 0.5) for n in range(1, 6)],
    ("returning user", "198.51.100.77", "/login", 2, 1.0),
    ("health checker", "10.0.0.2", "/", 40, 0.1),
    ("scraper", "203.0.113.66", "/", 400, 0.0),
    ("password guesser", "203.0.113.99", "/login", 60, 0.0),
    ("IPv6 rotator", lambda i: f"2001:db8:bad:1::{i + 1:x}", "/", 200, 0.0),
]
ATTACKERS = {"scraper", "password guesser", "IPv6 rotator"}

results = {}
results_lock = threading.Lock()


def run_client(base_url, name, address, path, requests, delay):
    codes = Counter()
    for i in range(requests):
        ip = address(i) if callable(address) else address
        req = urllib.request.Request(base_url + path, headers={"X-Forwarded-For": ip})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                codes[resp.status] += 1
        except urllib.error.HTTPError as err:
            codes[err.code] += 1
        time.sleep(delay)
    with results_lock:
        results[name] = codes


def main():
    server = make_server("127.0.0.1", 0, app,
                         server_class=ThreadingWSGIServer, handler_class=QuietHandler)
    base_url = f"http://127.0.0.1:{server.server_port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Protected app listening on {base_url}/")
    print("Limits: 20 requests / 10s per client, 5 logins / 60s, "
          "30s ban (doubling), alert above 40 req/s\n")

    start = time.monotonic()
    threads = [threading.Thread(target=run_client, args=(base_url, *c)) for c in CLIENTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    server.shutdown()

    print(f"{'client':<18}{'path':<8}{'sent':>6}{'200 OK':>8}{'429':>6}{'403':>6}")
    print("-" * 52)
    for name, _, path, sent, _ in CLIENTS:
        codes = results[name]
        print(f"{name:<18}{path:<8}{sent:>6}{codes[200]:>8}{codes[429]:>6}{codes[403]:>6}")

    print(f"\nFinished in {elapsed:.1f}s.")
    if alerts:
        print(f"Spike alert fired {len(alerts)}x (peak {max(alerts):.0f} req/s).")
    else:
        print("No spike alert fired.")
    print("Banned:", ", ".join(sorted(set(bans))) or "nobody")

    legit_blocked = sum(
        results[name][429] + results[name][403]
        for name, *_ in CLIENTS if name not in ATTACKERS
    )
    print("Legitimate requests blocked:", legit_blocked)

    # Non-zero exit if protection misbehaved, so CI can run this as a check.
    problems = []
    if legit_blocked:
        problems.append("legitimate traffic was blocked")
    if results["scraper"][200] > 20:
        problems.append("scraper got past the rate limit")
    if results["password guesser"][200] > 5:
        problems.append("password guesser got more than 5 login attempts")
    if results["IPv6 rotator"][200] > 20:
        problems.append("IPv6 rotation dodged the rate limit")
    if not alerts:
        problems.append("no spike alert fired")
    for problem in problems:
        print("UNEXPECTED:", problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
