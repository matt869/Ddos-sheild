"""Watch DDoS Shield handle a realistic traffic mix — no setup needed.

    python examples/simulate.py

Starts a protected WSGI app on 127.0.0.1 (in this process, on a random free
port) and plays three kinds of client against it at the same time:

  * visitors       - a handful of people browsing at a normal pace
  * health checker - your load balancer polling, allowlisted
  * scraper        - one client hammering as fast as it can

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
app = ShieldMiddleware(
    site,
    trust_forwarded_for=True,
    max_requests=20,          # per client...
    window_seconds=10,        # ...per 10 seconds
    ban_seconds=30,
    spike_threshold=40,       # site-wide req/s that counts as an attack
    sample_seconds=2,
    allowlist=["10.0.0.0/8"],
    on_attack=lambda rate: alerts.append((time.monotonic(), rate)),
)

results = {}
results_lock = threading.Lock()


def run_client(url, name, ip, requests, delay):
    codes = Counter()
    for _ in range(requests):
        req = urllib.request.Request(url, headers={"X-Forwarded-For": ip})
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
    url = f"http://127.0.0.1:{server.server_port}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Protected app listening on {url}")
    print("Limit: 20 requests / 10s per client, 30s ban, alert above 40 req/s\n")

    clients = [
        (f"visitor {n}", f"198.51.100.{n}", 8, 0.5) for n in range(1, 6)
    ] + [
        ("health checker", "10.0.0.2", 40, 0.1),
        ("scraper", "203.0.113.66", 400, 0.0),
    ]

    start = time.monotonic()
    threads = [
        threading.Thread(target=run_client, args=(url, *client)) for client in clients
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    server.shutdown()

    print(f"{'client':<16}{'sent':>6}{'200 OK':>8}{'429':>6}{'403':>6}")
    print("-" * 42)
    for name, _, sent, _ in clients:
        codes = results[name]
        print(f"{name:<16}{sent:>6}{codes[200]:>8}{codes[429]:>6}{codes[403]:>6}")

    print(f"\nFinished in {elapsed:.1f}s.")
    if alerts:
        print(f"Spike alert fired {len(alerts)}x (peak {max(r for _, r in alerts):.0f} req/s).")
    else:
        print("No spike alert fired.")

    legit_blocked = sum(
        results[name][429] + results[name][403]
        for name, *_ in clients if name != "scraper"
    )
    print("Legitimate requests blocked:", legit_blocked)


if __name__ == "__main__":
    main()
