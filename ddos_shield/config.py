"""Load Shield settings from a YAML file (see config.example.yaml).

    from ddos_shield.config import load_config
    from ddos_shield.middleware import protect

    protect(app, **load_config("config.yaml"))

Requires PyYAML (``pip install pyyaml``). Unknown keys are rejected so a typo
can't silently leave you running on defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Union

# section -> keys allowed in it (all map straight onto Shield arguments)
_SECTIONS = {
    "rate_limiter": {"max_requests", "window_seconds"},
    "blocklist": {"ban_seconds", "use_iptables", "ban_multiplier", "max_ban_seconds"},
    "monitor": {"spike_threshold", "sample_seconds", "alert_cooldown"},
    "maintenance": {"cleanup_interval"},
    "clients": {"ipv6_prefix"},
    "mode": {"dry_run"},
}


def parse_config(data: Any) -> Dict[str, Any]:
    """Flatten a parsed config mapping into ``Shield`` keyword arguments."""
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping of sections")

    options: Dict[str, Any] = {}
    for section, values in data.items():
        if section == "path_limits":
            if not isinstance(values, dict):
                raise ValueError("path_limits must map paths to limits")
            options["path_limits"] = values
            continue
        if section == "allowlist":
            if not isinstance(values, list):
                raise ValueError("allowlist must be a list of IPs or CIDR ranges")
            options["allowlist"] = [str(v) for v in values]
            continue
        if section not in _SECTIONS:
            raise ValueError(f"unknown config section: {section!r}")
        if not isinstance(values, dict):
            raise ValueError(f"section {section!r} must be a mapping")
        unknown = set(values) - _SECTIONS[section]
        if unknown:
            raise ValueError(f"unknown keys in {section!r}: {', '.join(sorted(unknown))}")
        options.update(values)
    return options


def load_config(path: Union[str, Path]) -> Dict[str, Any]:
    """Read a YAML config file and return ``Shield`` keyword arguments."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise ImportError("load_config needs PyYAML: pip install pyyaml") from exc

    with open(path, encoding="utf-8") as fh:
        return parse_config(yaml.safe_load(fh))
