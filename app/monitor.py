from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from app.checker import check_through_restart, utcnow
from app.db import Database
from app.rotate import failure_hidden

logger = logging.getLogger("proxy_monitor")


class Monitor:
    def __init__(self, database: Database):
        self.db = database
        self.stop = asyncio.Event()
        self.wake = asyncio.Event()
        self.round_lock = asyncio.Lock()
        self.running = False
        self.last_duration_sec: Optional[float] = None
        self.last_finished_at: Optional[str] = None
        self.next_check_at: Optional[float] = None
        self.last_checked_count = 0
        self._round_started = 0.0

    def public_state(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "last_duration_sec": self.last_duration_sec,
            "last_finished_at": self.last_finished_at,
            "next_check_at": self.next_check_at,
            "checked": self.last_checked_count,
        }

    def request_now(self) -> None:
        self.wake.set()

    async def run_forever(self) -> None:
        while not self.stop.is_set():
            await self.run_round()
            if self.stop.is_set():
                return
            interval = int(self.db.get_settings()["interval_sec"])
            remain = max(0.0, interval - (time.monotonic() - self._round_started))
            self.next_check_at = time.time() + remain
            slept = 0.0
            while slept < remain and not self.stop.is_set():
                if self.wake.is_set():
                    self.wake.clear()
                    break
                step = min(0.4, remain - slept)
                await asyncio.sleep(step)
                slept += step
            self.next_check_at = None

    async def run_round(self) -> None:
        if self.round_lock.locked():
            return
        async with self.round_lock:
            self.running = True
            self.next_check_at = None
            self._round_started = time.monotonic()
            try:
                settings = self.db.get_settings()
                proxies = self.db.list_enabled_secrets()
                semaphore = asyncio.Semaphore(int(settings["concurrency"]))
                seen = self.db.latest_agent_seen()

                async def one(proxy: dict[str, Any]) -> None:
                    async with semaphore:
                        if self.stop.is_set():
                            return
                        previous = proxy.get("last_status")
                        result = await check_through_restart(
                            proxy,
                            settings,
                            should_stop=self.stop.is_set,
                        )
                        if result.status in {"offline", "timeout"} and failure_hidden(
                            settings,
                            time.time(),
                            seen,
                            self.db.hold_until(proxy.get("address") or "", proxy.get("name") or ""),
                        ):
                            logger.info(
                                "%s:%s смена диапазона или перезагрузка модема, простой не засчитан",
                                proxy["host"],
                                proxy["port"],
                            )
                            return
                        self.db.save_check(int(proxy["id"]), result)
                        if previous != result.status:
                            suffix = f" ({result.error})" if result.error else ""
                            logger.info(
                                "%s:%s %s -> %s%s",
                                proxy["host"],
                                proxy["port"],
                                previous or "new",
                                result.status,
                                suffix,
                            )

                if proxies:
                    await asyncio.gather(*(one(proxy) for proxy in proxies))
                self.db.prune()
                self.last_checked_count = len(proxies)
                if proxies:
                    logger.info(
                        "круг проверки: %s прокси за %.1f с",
                        len(proxies),
                        time.monotonic() - self._round_started,
                    )
            finally:
                self.running = False
                self.last_duration_sec = round(time.monotonic() - self._round_started, 2)
                self.last_finished_at = utcnow()

    async def check_one(self, proxy_id: int) -> Optional[dict[str, Any]]:
        proxy = self.db.get_secret(proxy_id)
        if proxy is None:
            return None
        settings = self.db.get_settings()
        result = await check_through_restart(proxy, settings)
        if result.status not in {"offline", "timeout"} or not failure_hidden(
            settings,
            time.time(),
            self.db.latest_agent_seen(),
            self.db.hold_until(proxy.get("address") or "", proxy.get("name") or ""),
        ):
            self.db.save_check(proxy_id, result)
        return self.db.get_public(proxy_id)
