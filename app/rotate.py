from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

DOWN = {"offline", "timeout", "error"}
REBOOT_COOLDOWN_SEC = 15 * 60
AGENT_FRESH_SEC = 180


def parse_bands(value: Any) -> list[int]:
    bands: list[int] = []
    for part in str(value).replace(";", ",").split(","):
        item = part.strip()
        if not item:
            continue
        band = int(item)
        if not 1 <= band <= 71:
            raise ValueError(item)
        if band not in bands:
            bands.append(band)
    if not bands:
        raise ValueError("empty")
    return bands


def format_bands(bands: list[int]) -> str:
    return ",".join(str(band) for band in bands)


def schedule(now: float, interval_min: int) -> dict[str, float | int]:
    interval = max(1, int(interval_min)) * 60
    slot = int(now // interval)
    phase = now - slot * interval
    return {"slot": slot, "phase": phase, "next_slot_at": (slot + 1) * interval}


def bands_for_slot(slot: int, first: list[int], second: list[int]) -> list[int]:
    return first if int(slot) % 2 == 0 else second


def _stamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _age(now: datetime, value: Optional[str]) -> Optional[float]:
    parsed = _stamp(value)
    if parsed is None:
        return None
    return (now - parsed).total_seconds()


def failure_hidden(
    settings: dict[str, Any],
    now: float,
    agent_last_seen: Optional[str],
    hold_until: Optional[str],
) -> bool:
    moment = datetime.fromtimestamp(now, timezone.utc)
    if (_age(moment, hold_until) or 1) < 0:
        return True
    if not int(settings.get("rotate_enabled") or 0):
        return False
    seen = _age(moment, agent_last_seen)
    if seen is None or seen > AGENT_FRESH_SEC:
        return False
    phase = float(schedule(now, int(settings["rotate_interval_min"]))["phase"])
    return phase < int(settings["rotate_hold_sec"])


def modems_to_reboot(
    proxies: list[dict[str, Any]],
    farm: str,
    names: list[str],
    now: datetime,
    after_min: int,
    last_reboot: dict[str, Optional[str]],
    hold_until: dict[str, Optional[str]],
) -> list[str]:
    if after_min <= 0:
        return []
    limit = after_min * 60
    chosen: list[str] = []
    for name in names:
        if (_age(now, hold_until.get(name)) or 1) < 0:
            continue
        cooled = _age(now, last_reboot.get(name))
        if cooled is not None and cooled < REBOOT_COOLDOWN_SEC:
            continue
        group = [
            proxy for proxy in proxies
            if proxy.get("address") == farm and proxy.get("name") == name and proxy.get("enabled")
        ]
        if not group or any(proxy.get("last_status") not in DOWN for proxy in group):
            continue
        oks = [proxy["last_ok_at"] for proxy in group if proxy.get("last_ok_at")]
        if oks:
            anchor = max(oks)
        else:
            checks = [proxy["last_checked_at"] for proxy in group if proxy.get("last_checked_at")]
            anchor = min(checks) if checks else None
        age = _age(now, anchor)
        if age is not None and age >= limit:
            chosen.append(name)
    return chosen


def decide(
    *,
    now: float,
    settings: dict[str, Any],
    proxies: list[dict[str, Any]],
    farm: str,
    modems: list[str],
    applied_slot: Optional[int],
    applied_force: int,
    last_reboot: dict[str, Optional[str]],
    hold_until: dict[str, Optional[str]],
) -> dict[str, Any]:
    moment = datetime.fromtimestamp(now, timezone.utc)
    enabled = bool(int(settings.get("rotate_enabled") or 0))
    clock = schedule(now, int(settings["rotate_interval_min"]))
    first = parse_bands(settings["rotate_bands_a"])
    second = parse_bands(settings["rotate_bands_b"])
    slot = int(clock["slot"])
    force = int(settings.get("rotate_force") or 0)
    apply = enabled and (applied_slot != slot or int(applied_force) < force)
    return {
        "farm": farm,
        "rotate_enabled": enabled,
        "interval_min": int(settings["rotate_interval_min"]),
        "hold_sec": int(settings["rotate_hold_sec"]),
        "reboot_after_min": int(settings["reboot_after_min"]),
        "slot": slot,
        "force": force,
        "bands": bands_for_slot(slot, first, second),
        "apply_bands": apply,
        "in_hold": enabled and float(clock["phase"]) < int(settings["rotate_hold_sec"]),
        "next_slot_at": clock["next_slot_at"],
        "poll_sec": 20,
        "reboot": modems_to_reboot(
            proxies, farm, modems, moment, int(settings["reboot_after_min"]), last_reboot, hold_until,
        ),
    }
