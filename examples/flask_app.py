"""Runnable demo of DDoS Shield protecting a tiny Flask app.

    python examples/flask_app.py

Then, from another terminal, send a burst and watch 200s become 429s:

    for i in $(seq 1 100); do \
      curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/; \
    done
"""

import sys
from pathlib import Path

# Make the package importable when running this file directly from the repo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask  # noqa: E402
from ddos_shield.middleware import protect  # noqa: E402

app = Flask(__name__)

# Low limits so the demo is easy to trigger by hand.
protect(app, max_requests=10, window_seconds=10, ban_seconds=30)


@app.route("/")
def home():
    return "Hello, protected world!\n"


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
