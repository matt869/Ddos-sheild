# Changelog

## 1.5.0

- Security: paths are normalized before matching `path_limits`, closing a
  bypass where `//login`, `/./login` or `/x/../login` skipped a `/login` limit.
- Fix: concurrent requests could ban a client twice in one burst, which with
  `ban_multiplier` doubled a first offender's ban. Bans are now atomic
  (`BlockList.try_ban`).
- Dry-run mode (`dry_run=True`) for safe rollouts.
- `save_state()` / `load_state()` keep bans and offense history across restarts.
- Faster: each address is parsed once and IPv6 keys use integer masking —
  IPv4 checks ~20% faster, IPv6 ~2x faster. `examples/benchmark.py` added.
- Multi-threaded stress tests for the Shield core.

## 1.4.0

- Per-path limits (`path_limits`) for sensitive routes such as `/login`:
  429 for that route only, with an exact `Retry-After`.
- Escalating bans for repeat offenders (`ban_multiplier`, `max_ban_seconds`).
- IPv6 clients are grouped by /64 (`ipv6_prefix`); IPv4-mapped addresses are
  treated as IPv4.
- `on_ban` hook, `RateLimiter.retry_after()` and `BlockList.offenses()`.
- Prometheus exporter in `ddos_shield.metrics`, validated with the official
  parser; the FastAPI example serves `/metrics`.
- The simulation now includes a returning user, a password guesser and an
  IPv6-rotating bot; live-server tests cover the same attacks.

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
