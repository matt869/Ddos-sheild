# DDoS Shield 🛡️

[![tests](https://github.com/matt869/Ddos-sheild/actions/workflows/tests.yml/badge.svg)](https://github.com/matt869/Ddos-sheild/actions/workflows/tests.yml)

A lightweight, dependency-light **DDoS protection toolkit** for Python web
services. DDoS Shield helps you detect and absorb abusive traffic — floods,
scrapers, brute-force loops — by rate-limiting requests per client, spotting
sudden traffic spikes, and (optionally) auto-blocking offenders at the firewall.

> This is a **defensive** project. It protects a server you own or operate.
> It does **not** generate, send, or amplify traffic against anyone.

---

## Features

- **Sliding-window rate limiter** — cap requests per IP over a time window.
- **Traffic monitor** — detects abnormal spikes in requests-per-second and
  raises alerts before your service falls over.
- **Auto blocklist** — temporarily bans IPs that cross a threshold, with an
  optional `iptables` hook to drop them at the kernel level.
- **Allowlist** — trusted IPs and CIDR ranges (health checks, your load
  balancer, internal networks) are never limited.
- **Attack alerts** — an `on_attack` callback fires when site-wide traffic
  spikes, with a cooldown so you get one page, not thousands.
- **Bounded memory** — state for clients that have gone quiet is dropped
  automatically, so a long-running server doesn't grow forever.
- **Framework-friendly** — drop-in middleware for Flask, any WSGI app
  (Django, Bottle, Falcon, ...) and any ASGI app (FastAPI, Starlette, Quart).
- **Exempt paths** — health checks and stats pages stay reachable, even for a
  banned client.
- **Live stats** — `shield.stats()` for dashboards, plus a built-in
  Prometheus `/metrics` exporter.
- **Login protection** — stricter per-path limits (e.g. 5 attempts a minute
  on `/login`) that stop password guessing without banning the whole site.
- **Escalating bans** — repeat offenders get longer bans each time.
- **IPv6-aware** — clients are grouped by /64, so a bot rotating through its
  IPv6 block can't get a fresh budget per address.
- **Ban events** — an `on_ban` hook for your logs, SIEM or chat.
- **Dry-run mode** — log and count who *would* be blocked without blocking
  anyone, so you can tune limits on real traffic before enforcing them.
- **Survives restarts** — save and restore bans so a redeploy doesn't hand
  every attacker a clean slate.
- **Fast and thread-safe** — ~5 µs per request on IPv4, stress-tested with
  16 threads hammering one shield.
- **YAML config** — load all settings from a config file.
- **Zero heavy dependencies** — pure standard library at its core.

---

## Install

```bash
git clone https://github.com/matt869/Ddos-sheild.git
cd Ddos-sheild
pip install .            # or: pip install ".[flask]" to include Flask
```

---

## Quick start (Flask)

```python
from flask import Flask
from ddos_shield.middleware import protect

app = Flask(__name__)

# Allow at most 60 requests per 60s per IP; ban for 300s if exceeded.
protect(app, max_requests=60, window_seconds=60, ban_seconds=300)

@app.route("/")
def home():
    return "Hello, protected world!"
```

Run the bundled demo:

```bash
python examples/flask_app.py
```

Then hammer it in another terminal to watch the limiter kick in:

```bash
for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/; done
```

You'll see `200`s turn into `429 Too Many Requests` once the limit trips.

---

## See it handle realistic traffic

```bash
python examples/simulate.py
```

Starts a protected app on `127.0.0.1` and plays real users and three kinds of
attacker against it at once:

```
client            path      sent  200 OK   429   403
----------------------------------------------------
visitor 1         /            8       8     0     0
...
returning user    /login       2       2     0     0
health checker    /           40      40     0     0
scraper           /          400      20     1   379
password guesser  /login      60       5    16    39
IPv6 rotator      /          200      20     1   179

Spike alert fired 1x (peak 40 req/s).
Banned: 2001:db8:bad:1::/64, 203.0.113.66, 203.0.113.99
Legitimate requests blocked: 0
```

It exits non-zero if any attacker gets through or any real user is blocked,
and runs in CI on every push.

---

## Hardening options

```python
shield = Shield(
    max_requests=60, window_seconds=60, ban_seconds=300,
    path_limits={"/login": (5, 60), "/api/upload": (10, 3600)},
    ban_multiplier=4, max_ban_seconds=86_400,   # 5 min, 20 min, 80 min, ... 1 day
    ipv6_prefix=64,                             # default; 128 = per address
    on_ban=lambda client, secs: log.warning("banned %s for %ds", client, secs),
)
```

- **`path_limits`** cover the path and everything below it; the longest match
  wins. Going over one returns 429 for that route only, so a user who mistypes
  a password can still browse.
- **`ban_multiplier`** applies to bans within an hour of the previous one;
  offense history is forgotten after that.
- Paths are normalized before matching, so `//login`, `/./login` or
  `/x/../login` can't sneak past a `/login` rule.

### Rolling out safely

```python
shield = Shield(max_requests=60, window_seconds=60, dry_run=True)
```

Nothing is rejected, but every would-be rejection is logged
(`dry run: would reject 203.0.113.7 on /login with 429 ...`) and counted in
`shield.stats()`. When the numbers look right, drop `dry_run`.

### Keeping bans across restarts

```python
import atexit

shield.load_state("/var/lib/myapp/shield.json")      # on startup
atexit.register(shield.save_state, "/var/lib/myapp/shield.json")
```

Bans and offense history are stored with wall-clock expiry times and written
atomically; expired entries are skipped on load.

---

## Any WSGI app

```python
from ddos_shield.wsgi import ShieldMiddleware

application = ShieldMiddleware(
    application,
    max_requests=60,
    window_seconds=60,
    allowlist=["10.0.0.0/8"],
    on_attack=lambda rate: page_on_call(f"{rate:.0f} req/s"),
)
```

Behind a reverse proxy you control, pass `trust_forwarded_for=True` so clients
are identified by `X-Forwarded-For` instead of the proxy's address. With more
than one proxy in the chain (say a CDN plus a load balancer) pass the count,
e.g. `trust_forwarded_for=2`. Only entries your own proxies appended are
trusted; anything the client wrote into the header is ignored, so forged
addresses can't be used to dodge limits.

---

## FastAPI / any ASGI app

```python
from fastapi import FastAPI
from ddos_shield.asgi import ShieldASGIMiddleware

app = FastAPI()
app.add_middleware(
    ShieldASGIMiddleware,
    max_requests=60,
    window_seconds=60,
    exempt_paths=["/health"],
)
```

Rejected WebSocket handshakes are closed with code 1008. A full demo with
live `/shield/stats` and Prometheus `/metrics` endpoints is in
`examples/fastapi_app.py`.

---

## Prometheus

```python
from ddos_shield.metrics import CONTENT_TYPE, prometheus_text

@app.get("/metrics")
def metrics():
    return Response(prometheus_text(shield), media_type=CONTENT_TYPE)
```

Exposes `ddos_shield_requests_total{outcome=...}`, `ddos_shield_request_rate`,
`ddos_shield_under_attack`, `ddos_shield_active_bans` and
`ddos_shield_tracked_clients`. Add the path to `exempt_paths` so scrapes are
never limited.

---

## Using the pieces directly

### Shield (everything combined)

```python
from ddos_shield import Shield

shield = Shield(max_requests=60, window_seconds=60, ban_seconds=300)

decision = shield.check("203.0.113.7")
if not decision.allowed:
    reject(decision.status, retry_after=decision.retry_after)  # 429 or 403

shield.stats()
# {'requests': {'allowed': 912, 'allowlisted': 40, 'rate_limited': 3, 'blocked': 211},
#  'current_rate': 12.4, 'under_attack': False, 'active_bans': 3, 'tracked_clients': 57}

shield.blocklist.banned()   # {'203.0.113.66': 241.7, ...} seconds left per ban
```

### Rate limiter

```python
from ddos_shield.rate_limiter import RateLimiter

limiter = RateLimiter(max_requests=100, window_seconds=60)

if limiter.allow("203.0.113.7"):
    handle_request()
else:
    reject_with_429()
```

### Traffic monitor

```python
from ddos_shield.monitor import TrafficMonitor

monitor = TrafficMonitor(spike_threshold=500)  # requests/sec

monitor.record()                # call on every request
if monitor.is_under_attack():
    alert_ops_team()
```

### Auto blocklist

```python
from ddos_shield.blocklist import BlockList

blocklist = BlockList(ban_seconds=600, use_iptables=False)
blocklist.ban("203.0.113.7")
if blocklist.is_banned("203.0.113.7"):
    drop_connection()
```

Set `use_iptables=True` (Linux, run as root) to also drop banned IPs at the
firewall via `iptables -A INPUT -s <ip> -j DROP`.

---

## Configuration

Copy `config.example.yaml` to `config.yaml` and tune the thresholds to your
traffic. Start conservative and watch your logs before tightening.

```python
from ddos_shield.config import load_config

protect(app, **load_config("config.yaml"))
```

Unknown keys are rejected, so a typo can't silently leave you on defaults.
Needs PyYAML (`pip install ".[yaml]"`). Check a file before deploying it:

```bash
$ python -m ddos_shield check-config config.yaml
config.yaml: OK
  rate limit : 60 requests per 60s per client
  ban        : 300s
  spike alert: 500 req/s over 5s
  allowlist  : 127.0.0.1/32, 10.0.0.0/8
```

---

## Performance

`python examples/benchmark.py` times `Shield.check`, the work every protected
request does:

```
scenario                                            checks   per check
----------------------------------------------------------------------
defaults, 5,000 IPv4 clients                     206,000/s     4.84 us
defaults, 5,000 IPv6 clients                      69,000/s    14.49 us
allowlist of 3 networks                          150,000/s     6.68 us
```

(Single core, CPython 3.11; your numbers will differ.)

---

## Running tests

```bash
python -m unittest -v
```

Includes end-to-end tests that run a real HTTP server on `127.0.0.1`, and
multi-threaded stress tests that force rapid thread switching to expose races. The
Flask and YAML tests are skipped unless those packages are installed
(`pip install -r requirements.txt`).

---

## Good defensive practice

DDoS Shield is one layer. For real resilience, combine it with:

- An upstream provider that absorbs volumetric attacks (Cloudflare, AWS Shield,
  Google Cloud Armor).
- OS-level connection limits (`iptables` / `nftables` rate rules).
- Autoscaling and generous timeouts on your app servers.
- Monitoring/alerting so a human finds out early.

No single tool stops every attack — defense is layered.

---

## License

MIT — see [LICENSE](LICENSE).
