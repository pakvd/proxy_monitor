from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger("proxy_monitor")

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
CGNAT = ipaddress.ip_network("100.64.0.0/10")
PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
SECRET_RE = re.compile(r"://[^@/\s]+@")


@dataclass
class CheckResult:
    status: str
    latency_ms: Optional[int]
    exit_ip: Optional[str]
    http_status: Optional[int]
    error: Optional[str]
    checked_at: str


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_proxy_url(proxy: dict[str, Any]) -> str:
    protocol = (proxy.get("protocol") or "http").lower()
    login = proxy.get("login") or ""
    password = proxy.get("password") or ""
    auth = ""
    if login or password:
        auth = f"{quote(str(login), safe='')}:{quote(str(password), safe='')}@"
    return f"{protocol}://{auth}{proxy['host']}:{int(proxy['port'])}"


def public_error(exc: BaseException) -> str:
    text = SECRET_RE.sub("://***@", str(exc))
    text = " ".join(text.split())
    return text[:300]


def extract_ip(body: str) -> Optional[str]:
    text = (body or "").strip()
    if not text:
        return None
    if text.startswith("{") or text.startswith("["):
        try:
            import json

            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for key in ("ip", "query", "origin"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    candidate = value.split(",")[0].strip()
                    found = _valid_ip(candidate) or _valid_ip_search(candidate)
                    if found:
                        return found
    found = _valid_ip(text) or _valid_ip_search(text)
    if found:
        return found
    if ":" in text and " " not in text and len(text) <= 64:
        try:
            ipaddress.ip_address(text)
        except ValueError:
            return None
        return text
    return None


def _valid_ip(value: str) -> Optional[str]:
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(parsed)


def _valid_ip_search(text: str) -> Optional[str]:
    match = IP_RE.search(text)
    if not match:
        return None
    return _valid_ip(match.group(0))


def ip_kind(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    if parsed.version == 4 and parsed in CGNAT:
        return "cgnat"
    if any(parsed.version == network.version and parsed in network for network in PRIVATE_NETS):
        return "private"
    return "public"


def _is_refused(exc: BaseException) -> bool:
    current: Optional[BaseException] = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ConnectionRefusedError):
            return True
        if "refused" in str(current).lower():
            return True
        current = current.__cause__ or current.__context__
    return False


def _result(
    status: str,
    started: float,
    *,
    exit_ip: Optional[str] = None,
    http_status: Optional[int] = None,
    error: Optional[str] = None,
    latency: Optional[int] = None,
) -> CheckResult:
    if latency is None and status in ("online", "slow", "error", "auth"):
        latency = int((time.perf_counter() - started) * 1000)
    return CheckResult(
        status=status,
        latency_ms=latency,
        exit_ip=exit_ip,
        http_status=http_status,
        error=error,
        checked_at=utcnow(),
    )


async def check_proxy(proxy: dict[str, Any], settings: dict[str, Any]) -> CheckResult:
    """Open the proxy the same way a client does and fetch the check URL through it.

    The packet path is: this process -> proxy host:port -> VLAN -> LTE modem -> internet.
    A closed port means the proxy process is down. A timeout after connect usually means
    the modem or its uplink is not passing traffic. 407 means the login is wrong.
    """
    timeout_sec = float(settings["timeout_sec"])
    connect_sec = min(5.0, timeout_sec)
    timeout = httpx.Timeout(timeout_sec, connect=connect_sec)
    proxy_url = build_proxy_url(proxy)
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "proxy-monitor/0.1"},
        ) as client:
            response = await client.get(settings["check_url"])
    except httpx.ConnectTimeout:
        return _result("offline", started, error="таймаут подключения к порту прокси", latency=int((time.perf_counter() - started) * 1000))
    except httpx.ConnectError as exc:
        error = "порт закрыт" if _is_refused(exc) else "нет соединения с прокси"
        return _result("offline", started, error=error, latency=int((time.perf_counter() - started) * 1000))
    except httpx.TimeoutException:
        return _result(
            "timeout",
            started,
            error="прокси не дождался ответа из интернета",
            latency=int((time.perf_counter() - started) * 1000),
        )
    except httpx.ProxyError as exc:
        message = str(exc).lower()
        if "407" in message or "authentication" in message:
            return _result("auth", started, error="неверный логин или пароль", http_status=407)
        return _result("error", started, error=public_error(exc) or "ошибка прокси")
    except httpx.HTTPError as exc:
        return _result("error", started, error=public_error(exc) or "ошибка запроса")

    latency = int((time.perf_counter() - started) * 1000)
    if response.status_code == 407:
        return _result("auth", started, error="неверный логин или пароль", http_status=407, latency=latency)
    if response.status_code >= 400:
        return _result(
            "error",
            started,
            error=f"HTTP {response.status_code}",
            http_status=response.status_code,
            latency=latency,
        )
    exit_ip = extract_ip(response.text)
    if not exit_ip:
        return _result(
            "error",
            started,
            error="ответ без IP-адреса",
            http_status=response.status_code,
            latency=latency,
        )
    status = "slow" if latency >= int(settings["slow_ms"]) else "online"
    return _result(status, started, exit_ip=exit_ip, http_status=response.status_code, latency=latency)


TRANSIENT = frozenset({"offline", "timeout"})


async def check_through_restart(
    proxy: dict[str, Any],
    settings: dict[str, Any],
    *,
    probe=check_proxy,
    sleep=asyncio.sleep,
    should_stop=None,
) -> CheckResult:
    """Retry while the port is down so a scheduled proxy restart is not stored as an outage.

    Auth failures and HTTP answers are final: the process is up. A closed port or a timeout
    is treated as a possible restart and retried until restart_grace_sec elapses.
    """
    grace = int(settings.get("restart_grace_sec") or 0)
    result = await probe(proxy, settings)
    if grace <= 0 or result.status not in TRANSIENT:
        return result
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if should_stop and should_stop():
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await sleep(min(5.0, remaining))
        if should_stop and should_stop():
            return result
        result = await probe(proxy, settings)
        if result.status not in TRANSIENT:
            logger.info(
                "%s:%s ответил после повтора, перезапуск не засчитан",
                proxy.get("host"),
                proxy.get("port"),
            )
            return result
    return result
