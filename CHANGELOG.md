# Changelog

## 1.1.0

- `Retry-After` on 429 and 403 responses now reflects the actual ban time.
- New `BlockList.time_remaining()`.
- `protect()` accepts `sample_seconds` for the traffic monitor.
- `RateLimiter.remaining()` no longer stores entries for unseen clients.
- Package is installable with `pip install .`; tests run on GitHub Actions.

## 1.0.0

- Initial release: rate limiter, traffic monitor, blocklist, Flask middleware.
