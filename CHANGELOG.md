# Changelog

## 1.3.0

- New `ShieldASGIMiddleware` for FastAPI, Starlette, Quart and other ASGI apps,
  including WebSocket handshakes. Verified against a live uvicorn server.
- `exempt_paths` on every integration keeps health checks and stats pages
  reachable, even for banned clients.
- `Shield.stats()` and `BlockList.banned()` for dashboards and metrics.
- `python -m ddos_shield check-config` validates a config file.
- Type hints ship with the package (`py.typed`); ruff linting runs in CI.
- `alert_cooldown` must not be negative.

## 1.2.0

- New `Shield` core shared by every integration; `protect()` now returns it.
- New framework-agnostic `ShieldMiddleware` for any WSGI app.
- Allowlist of trusted IPs and CIDR ranges that are never limited.
- `on_attack` callback for traffic-spike alerts, rate-limited by `alert_cooldown`.
- Stale per-client state is cleaned up every `cleanup_interval` seconds.
- `load_config()` reads settings from YAML and rejects unknown keys.
- End-to-end tests against a live local HTTP server, and
  `examples/simulate.py`, which also runs in CI.

## 1.1.0

- `Retry-After` on 429 and 403 responses now reflects the actual ban time.
- New `BlockList.time_remaining()`.
- `protect()` accepts `sample_seconds` for the traffic monitor.
- `RateLimiter.remaining()` no longer stores entries for unseen clients.
- Package is installable with `pip install .`; tests run on GitHub Actions.

## 1.0.0

- Initial release: rate limiter, traffic monitor, blocklist, Flask middleware.
