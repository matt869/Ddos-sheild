"""Runnable demo of DDoS Shield protecting a FastAPI app.

    pip install fastapi uvicorn
    python examples/fastapi_app.py

Then open http://127.0.0.1:8000/shield/stats while sending a burst:

    for i in $(seq 1 30); do \
      curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/; \
    done
"""

import sys
from pathlib import Path

# Make the package importable when running this file directly from the repo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402
from fastapi import FastAPI, Response  # noqa: E402

from ddos_shield import Shield  # noqa: E402
from ddos_shield.asgi import ShieldASGIMiddleware  # noqa: E402
from ddos_shield.metrics import CONTENT_TYPE, prometheus_text  # noqa: E402

# Low limits so the demo is easy to trigger by hand.
shield = Shield(max_requests=10, window_seconds=10, ban_seconds=30)

app = FastAPI()
# The stats and metrics pages stay reachable even while you're banned.
app.add_middleware(
    ShieldASGIMiddleware, shield=shield, exempt_paths=["/shield/stats", "/metrics"]
)


@app.get("/")
def home():
    return {"message": "Hello, protected world!"}


@app.get("/shield/stats")
def shield_stats():
    # In production put this behind auth or on an internal-only port.
    bans = {ip: round(left, 1) for ip, left in shield.blocklist.banned().items()}
    return {**shield.stats(), "bans": bans}


@app.get("/metrics")
def metrics():
    # Point Prometheus at this. Keep it internal-only in production.
    return Response(prometheus_text(shield), media_type=CONTENT_TYPE)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
