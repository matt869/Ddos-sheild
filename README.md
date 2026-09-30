# DDoS Shield 🛡️

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
- **Framework-friendly** — drop-in Flask middleware, plus a plain WSGI wrapper
  so it works with anything.
- **Zero heavy dependencies** — pure standard library at its core.

---

## Install

```bash
git clone https://github.com/matt869/Ddos-sheild.git
cd Ddos-sheild
pip install -r requirements.txt   # only needed for the Flask example
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

## Using the pieces directly

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
