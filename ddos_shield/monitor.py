"""Traffic monitor.

Tracks the global request rate and flags when it crosses a spike threshold —
an early warning that the service may be under a volumetric attack. This does
not block anything on its own; wire ``is_under_attack()`` to an alert, a
tighter rate limit, or a scale-up action.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque


class TrafficMonitor:
    """Estimate requests/sec over a short sample window and detect spikes."""

    def __init__(self, spike_threshold: float = 500.0, sample_seconds: float = 5.0) -> None:
        if spike_threshold <= 0:
            raise ValueError("spike_threshold must be positive")
        if sample_seconds <= 0:
            raise ValueError("sample_seconds must be positive")

        self.spike_threshold = float(spike_threshold)
        self.sample_seconds = float(sample_seconds)
        self._events: Deque[float] = deque()
        self._lock = threading.Lock()

    def record(self, now: float | None = None) -> None:
        """Register one request."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._events.append(now)
            self._trim(now)

    def current_rate(self, now: float | None = None) -> float:
        """Current requests-per-second averaged over the sample window."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._trim(now)
            return len(self._events) / self.sample_seconds

    def is_under_attack(self, now: float | None = None) -> bool:
        """True if the current rate exceeds the spike threshold."""
        return self.current_rate(now) >= self.spike_threshold

    def _trim(self, now: float) -> None:
        cutoff = now - self.sample_seconds
        events = self._events
        while events and events[0] <= cutoff:
            events.popleft()
