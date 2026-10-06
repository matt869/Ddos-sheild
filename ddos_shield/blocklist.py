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
from typing import Dict, Optional, Tuple

logger = logging.getLogger("ddos_shield.blocklist")


class BlockList:
    def __init__(
        self,
        ban_seconds: float = 300.0,
        use_iptables: bool = False,
        ban_multiplier: float = 1.0,
        max_ban_seconds: Optional[float] = None,
        offense_memory: float = 3600.0,
    ) -> None:
        """Repeat offenders can be banned for longer each time: the n-th ban
        within ``offense_memory`` seconds of the previous one lasts
        ``ban_seconds * ban_multiplier ** (n - 1)``, capped at ``max_ban_seconds``.
        The default multiplier of 1 gives every ban the same length.
        """
        if ban_seconds <= 0:
            raise ValueError("ban_seconds must be positive")
        if ban_multiplier < 1:
            raise ValueError("ban_multiplier must be at least 1")
        if max_ban_seconds is not None and max_ban_seconds < ban_seconds:
            raise ValueError("max_ban_seconds must be at least ban_seconds")
        if offense_memory <= 0:
            raise ValueError("offense_memory must be positive")

        self.ban_seconds = float(ban_seconds)
        self.ban_multiplier = float(ban_multiplier)
        self.max_ban_seconds = None if max_ban_seconds is None else float(max_ban_seconds)
        self.offense_memory = float(offense_memory)
        self._offenses: Dict[str, Tuple[int, float]] = {}  # ip -> (count, last ban)
        self.use_iptables = use_iptables and shutil.which("iptables") is not None
        if use_iptables and not self.use_iptables:
            logger.warning("iptables not found on PATH; firewall enforcement disabled")

        self._banned: Dict[str, float] = {}  # ip -> unban time (monotonic)
        self._lock = threading.Lock()

    def ban(self, ip: str, now: float | None = None) -> float:
        """Ban ``ip``; returns the ban length in seconds."""
        now = time.monotonic() if now is None else now
        with self._lock:
            count, last = self._offenses.get(ip, (0, now))
            count = count + 1 if now - last < self.offense_memory else 1
            self._offenses[ip] = (count, now)
            duration = self.ban_seconds * self.ban_multiplier ** (count - 1)
            if self.max_ban_seconds is not None:
                duration = min(duration, self.max_ban_seconds)
            already = ip in self._banned
            self._banned[ip] = now + duration
        if not already and self.use_iptables:
            self._iptables("-A", ip)
        logger.info("Banned %s for %.0fs (offense #%d)", ip, duration, count)
        return duration

    def offenses(self, ip: str, now: float | None = None) -> int:
        """How many times ``ip`` has been banned within ``offense_memory``."""
        now = time.monotonic() if now is None else now
        with self._lock:
            count, last = self._offenses.get(ip, (0, now))
        return count if now - last < self.offense_memory else 0

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

    def time_remaining(self, ip: str, now: float | None = None) -> float:
        """Seconds left on ``ip``'s ban, or 0.0 if it isn't banned."""
        now = time.monotonic() if now is None else now
        with self._lock:
            expiry = self._banned.get(ip)
        if expiry is None:
            return 0.0
        return max(0.0, expiry - now)

    def banned(self, now: float | None = None) -> Dict[str, float]:
        """Snapshot of active bans: ``{ip: seconds remaining}``."""
        now = time.monotonic() if now is None else now
        with self._lock:
            return {
                ip: expiry - now
                for ip, expiry in self._banned.items()
                if expiry > now
            }

    def unban(self, ip: str) -> None:
        with self._lock:
            removed = self._banned.pop(ip, None) is not None
        if removed and self.use_iptables:
            self._iptables("-D", ip)

    def sweep(self, now: float | None = None) -> int:
        """Expire and remove stale bans. Returns count removed.

        Also forgets offense history older than ``offense_memory``.
        """
        now = time.monotonic() if now is None else now
        expired = []
        with self._lock:
            for ip, expiry in list(self._banned.items()):
                if expiry <= now:
                    del self._banned[ip]
                    expired.append(ip)
            for ip, (_, last) in list(self._offenses.items()):
                if now - last >= self.offense_memory and ip not in self._banned:
                    del self._offenses[ip]
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
