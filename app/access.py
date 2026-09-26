from __future__ import annotations

import ipaddress
import os
import time
from typing import Optional


class LoginGuard:
    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}

    def reset(self) -> None:
        self._failures.clear()
        self._blocked_until.clear()

    def locked(self, host: str) -> bool:
        until = self._blocked_until.get(host, 0)
        if until > time.time():
            return True
        if until:
            self._blocked_until.pop(host, None)
            self._failures.pop(host, None)
        return False

    def fail(self, host: str) -> None:
        now = time.time()
        recent = [stamp for stamp in self._failures.get(host, []) if now - stamp < 600]
        recent.append(now)
        self._failures[host] = recent
        if len(recent) >= 5:
            self._blocked_until[host] = now + 900

    def ok(self, host: str) -> None:
        self._failures.pop(host, None)
        self._blocked_until.pop(host, None)


guard = LoginGuard()


def allowlist() -> Optional[list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """None means the allowlist is off. An empty list means the setting was present but useless."""
    raw = os.environ.get("MONITOR_ALLOWLIST", "").strip()
    if not raw:
        return None
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        try:
            if "/" not in item:
                address = ipaddress.ip_address(item)
                item = f"{address}/{address.max_prefixlen}"
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return networks


def allowed(host: str) -> bool:
    networks = allowlist()
    if networks is None:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in networks)
