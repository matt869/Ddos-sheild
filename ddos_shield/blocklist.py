"""Temporary IP blocklist with optional firewall enforcement.

Banned IPs expire automatically after ``ban_seconds``. When ``use_iptables`` is
enabled (Linux, root), bans are also pushed to the kernel firewall so traffic
is dropped before it reaches your application. iptables failures are logged and
never crash the caller — the in-memory ban still applies.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from typing import Dict

logger = logging.getLogger("ddos_shield.blocklist")


class BlockList:
    def __init__(self, ban_seconds: float = 300.0, use_iptables: bool = False) -> None:
        if ban_seconds <= 0:
            raise ValueError("ban_seconds must be positive")

        self.ban_seconds = float(ban_seconds)
        self.use_iptables = use_iptables and shutil.which("iptables") is not None
        if use_iptables and not self.use_iptables:
            logger.warning("iptables not found on PATH; firewall enforcement disabled")

        self._banned: Dict[str, float] = {}  # ip -> unban time (monotonic)
        self._lock = threading.Lock()

    def ban(self, ip: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            already = ip in self._banned
            self._banned[ip] = now + self.ban_seconds
        if not already and self.use_iptables:
            self._iptables("-A", ip)
        logger.info("Banned %s for %.0fs", ip, self.ban_seconds)

    def is_banned(self, ip: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            expiry = self._banned.get(ip)
            if expiry is None:
                return False
            if expiry <= now:
                del self._banned[ip]
                expired = True
            else:
                return True
        if expired and self.use_iptables:
            self._iptables("-D", ip)
        return False

    def unban(self, ip: str) -> None:
        with self._lock:
            removed = self._banned.pop(ip, None) is not None
        if removed and self.use_iptables:
            self._iptables("-D", ip)

    def sweep(self, now: float | None = None) -> int:
        """Expire and remove stale bans. Returns count removed."""
        now = time.monotonic() if now is None else now
        expired = []
        with self._lock:
            for ip, expiry in list(self._banned.items()):
                if expiry <= now:
                    del self._banned[ip]
                    expired.append(ip)
        if self.use_iptables:
            for ip in expired:
                self._iptables("-D", ip)
        return len(expired)

    def _iptables(self, action: str, ip: str) -> None:
        """Add (-A) or delete (-D) a DROP rule for ``ip``. Best-effort."""
        try:
            subprocess.run(
                ["iptables", action, "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=5,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("iptables %s %s failed: %s", action, ip, exc)
