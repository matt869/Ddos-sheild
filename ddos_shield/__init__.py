"""DDoS Shield — a defensive toolkit for protecting Python web services.

Public API:
    RateLimiter     - per-client sliding-window request limiting
    TrafficMonitor  - detect abnormal traffic spikes
    BlockList       - temporary IP bans, with optional iptables enforcement
    Shield          - all three combined into one per-request decision
    protect         - one-call Flask protection (see ddos_shield.middleware)
"""

from .blocklist import BlockList
from .monitor import TrafficMonitor
from .rate_limiter import RateLimiter
from .shield import Decision, Shield

__all__ = ["RateLimiter", "TrafficMonitor", "BlockList", "Shield", "Decision"]
__version__ = "1.5.0"
