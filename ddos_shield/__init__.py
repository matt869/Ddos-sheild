"""DDoS Shield — a defensive toolkit for protecting Python web services.

Public API:
    RateLimiter     - per-client sliding-window request limiting
    TrafficMonitor  - detect abnormal traffic spikes
    BlockList       - temporary IP bans, with optional iptables enforcement
    protect         - one-call Flask protection (see ddos_shield.middleware)
"""

from .rate_limiter import RateLimiter
from .monitor import TrafficMonitor
from .blocklist import BlockList

__all__ = ["RateLimiter", "TrafficMonitor", "BlockList"]
__version__ = "1.1.0"
