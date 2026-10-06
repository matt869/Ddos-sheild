"""Prometheus metrics, no client library needed.

    from ddos_shield.metrics import prometheus_text, CONTENT_TYPE

    @app.get("/metrics")
    def metrics():
        return Response(prometheus_text(shield), media_type=CONTENT_TYPE)

Serve it on an internal port or behind auth, and add the path to
``exempt_paths`` so scrapes are never rate-limited.
"""

from __future__ import annotations

from typing import List

from .shield import Shield

__all__ = ["prometheus_text", "CONTENT_TYPE"]

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def prometheus_text(shield: Shield, prefix: str = "ddos_shield") -> str:
    """Render ``shield.stats()`` in the Prometheus text exposition format."""
    stats = shield.stats()
    lines: List[str] = []

    def metric(name: str, kind: str, help_text: str) -> str:
        full = f"{prefix}_{name}"
        lines.append(f"# HELP {full} {help_text}")
        lines.append(f"# TYPE {full} {kind}")
        return full

    name = metric("requests_total", "counter", "Requests seen, by outcome.")
    for outcome, count in sorted(stats["requests"].items()):
        lines.append(f'{name}{{outcome="{outcome}"}} {count}')

    gauges = [
        ("request_rate", "Current requests per second across all clients.",
         stats["current_rate"]),
        ("under_attack", "1 while the request rate is above the spike threshold.",
         int(stats["under_attack"])),
        ("active_bans", "Clients currently banned.", stats["active_bans"]),
        ("tracked_clients", "Clients held in rate limiter memory.",
         stats["tracked_clients"]),
    ]
    for gauge, help_text, value in gauges:
        lines.append(f"{metric(gauge, 'gauge', help_text)} {value:g}")

    return "\n".join(lines) + "\n"
