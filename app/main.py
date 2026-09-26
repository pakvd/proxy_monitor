from __future__ import annotations

import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.access import allowed, allowlist, guard
from app.config import ROOT, VERSION, autostart, data_dir, monitor_password
from app.db import Database
from app.importer import parse_xlsx, workbook_bytes
from app.monitor import Monitor

logger = logging.getLogger("proxy_monitor")
WEB = ROOT / "web"
COOKIE = "pm_session"
UP = {"online", "slow"}
DOWN = {"offline", "timeout", "error"}


def _token(password: str) -> str:
    return hmac.new(password.encode(), b"proxy-monitor-session-v1", "sha256").hexdigest()


def _authenticated(request: Request) -> bool:
    password = monitor_password()
    if not password:
        return True
    got = request.cookies.get(COOKIE, "")
    expected = _token(password)
    if len(got) != len(expected):
        return False
    return hmac.compare_digest(got, expected)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not monitor_password():
        logger.warning("MONITOR_PASSWORD не задан, панель открыта без входа")
    networks = allowlist()
    if networks is None:
        logger.warning("MONITOR_ALLOWLIST пуст, панель доступна с любого адреса")
    elif not networks:
        logger.error("MONITOR_ALLOWLIST задан, но в нём нет ни одного верного адреса")
    else:
        logger.info("белый список: %s", ", ".join(str(network) for network in networks))
    database = Database(data_dir() / "monitor.db")
    database.init()
    monitor = Monitor(database)
    app.state.db = database
    app.state.monitor = monitor
    task = asyncio.create_task(monitor.run_forever()) if autostart() else None
    yield
    monitor.stop.set()
    monitor.wake.set()
    if task is not None:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Proxy monitor", version=VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    host = request.client.host if request.client else ""
    if path != "/api/health" and not allowed(host):
        logger.warning("закрыт доступ с %s на %s", host or "неизвестный адрес", path)
        return _harden(JSONResponse({"detail": "доступ с этого адреса закрыт"}, status_code=403))
    if path == "/api/login" and request.method == "POST" and guard.locked(host):
        return _harden(JSONResponse({"detail": "слишком много попыток, подождите"}, status_code=429))
    if (
        not monitor_password()
        or path in {"/", "/api/login", "/api/session", "/api/health"}
        or path.startswith("/static/")
    ):
        return _harden(await call_next(request))
    if _authenticated(request):
        return _harden(await call_next(request))
    return _harden(JSONResponse({"detail": "нужен вход"}, status_code=401))


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "version": VERSION}


@app.get("/api/session")
def session(request: Request) -> dict[str, bool]:
    required = bool(monitor_password())
    return {"auth_required": required, "authenticated": (not required) or _authenticated(request)}


@app.post("/api/login")
async def login(request: Request) -> JSONResponse:
    password = monitor_password()
    if not password:
        raise HTTPException(400, "пароль панели не задан")
    host = request.client.host if request.client else ""
    payload = await request.json()
    got = str(payload.get("password", ""))
    if not hmac.compare_digest(_token(got), _token(password)):
        guard.fail(host)
        raise HTTPException(401, "неверный пароль")
    guard.ok(host)
    response = JSONResponse({"ok": True})
    response.set_cookie(
        COOKIE,
        _token(password),
        httponly=True,
        samesite="lax",
        secure=os.environ.get("MONITOR_COOKIE_SECURE", "") == "1",
        max_age=60 * 60 * 24 * 7,
    )
    return response


@app.post("/api/logout")
def logout() -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie(
        COOKIE,
        samesite="lax",
        secure=os.environ.get("MONITOR_COOKIE_SECURE", "") == "1",
    )
    return response


@app.get("/api/overview")
def overview(request: Request) -> dict[str, Any]:
    database: Database = request.app.state.db
    monitor: Monitor = request.app.state.monitor
    proxies = database.list_public()
    enabled = [proxy for proxy in proxies if proxy["enabled"]]

    def count(predicate) -> int:
        return sum(1 for proxy in enabled if predicate(proxy))

    groups: dict[str, dict[str, Any]] = {}
    for proxy in enabled:
        bucket = groups.setdefault(
            proxy["address"],
            {"address": proxy["address"], "total": 0, "up": 0, "down": 0, "auth": 0},
        )
        bucket["total"] += 1
        status = proxy["last_status"]
        if status in UP:
            bucket["up"] += 1
        elif status in DOWN:
            bucket["down"] += 1
        elif status == "auth":
            bucket["auth"] += 1
    pending = count(lambda proxy: not proxy["last_status"])
    down = count(lambda proxy: proxy["last_status"] in DOWN)
    auth = count(lambda proxy: proxy["last_status"] == "auth")
    ip_totals = database.ip_totals()
    return {
        "version": VERSION,
        "proxies": proxies,
        "groups": sorted(groups.values(), key=lambda item: item["address"]),
        "stats": {
            "total": len(proxies),
            "enabled": len(enabled),
            "up": count(lambda proxy: proxy["last_status"] in UP),
            "slow": count(lambda proxy: proxy["last_status"] == "slow"),
            "down": down,
            "auth": auth,
            "changed": count(lambda proxy: proxy["exit_ip_changed"]),
            "pending": pending,
            "disabled": len(proxies) - len(enabled),
            "all_failed": bool(enabled) and pending == 0 and down + auth == len(enabled),
            "unique_ips": ip_totals["unique"],
            "repeated_ips": ip_totals["repeated"],
            "repeat_extra": ip_totals["extra"],
        },
        "settings": database.get_settings(),
        "round": monitor.public_state(),
    }


@app.post("/api/import")
async def import_proxies(
    request: Request,
    file: UploadFile = File(...),
    replace_missing: str = Form("false"),
) -> dict[str, Any]:
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(413, "файл больше 5 МБ")
    try:
        rows, errors = parse_xlsx(raw)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    database: Database = request.app.state.db
    created = 0
    updated = 0
    for row in rows:
        kind = database.upsert_proxy(row)
        if kind == "created":
            created += 1
        else:
            updated += 1
    deleted = 0
    replace = replace_missing.strip().lower() in {"1", "true", "yes", "on"}
    replace_skipped = False
    if replace:
        if errors:
            replace_skipped = True
        elif rows:
            keys = {(row["host"], row["port"], row["login"]) for row in rows}
            deleted = database.delete_missing(keys)
    return {
        "created": created,
        "updated": updated,
        "deleted": deleted,
        "errors": errors,
        "replace_skipped": replace_skipped,
    }


@app.get("/api/template.xlsx")
def template() -> Response:
    return _xlsx(workbook_bytes([], example=True), "proxies-template.xlsx")


@app.get("/api/export.xlsx")
def export_xlsx(request: Request) -> Response:
    rows = request.app.state.db.export_rows()
    return _xlsx(workbook_bytes(rows), "proxies.xlsx")


@app.put("/api/settings")
async def update_settings(request: Request) -> dict[str, Any]:
    payload = await request.json()
    values = _validate_settings(payload)
    return request.app.state.db.update_settings(values)


@app.post("/api/check-now")
def check_now(request: Request) -> dict[str, Any]:
    monitor: Monitor = request.app.state.monitor
    monitor.request_now()
    return {"ok": True, "running": monitor.running}


@app.post("/api/proxies/{proxy_id}/check")
async def check_proxy_now(proxy_id: int, request: Request) -> dict[str, Any]:
    proxy = await request.app.state.monitor.check_one(proxy_id)
    if proxy is None:
        raise HTTPException(404, "прокси не найден")
    return proxy


@app.patch("/api/proxies/{proxy_id}")
async def patch_proxy(proxy_id: int, request: Request) -> dict[str, Any]:
    payload = await request.json()
    if "enabled" not in payload:
        raise HTTPException(400, "нужно поле enabled")
    proxy = request.app.state.db.set_enabled(proxy_id, bool(payload["enabled"]))
    if proxy is None:
        raise HTTPException(404, "прокси не найден")
    return proxy


@app.get("/api/proxies/{proxy_id}/history")
def proxy_history(proxy_id: int, request: Request) -> dict[str, Any]:
    proxy = request.app.state.db.get_public(proxy_id)
    if proxy is None:
        raise HTTPException(404, "прокси не найден")
    return {
        "proxy": proxy,
        "checks": request.app.state.db.history(proxy_id),
        "ips": request.app.state.db.proxy_exit_ips(proxy_id),
    }


@app.delete("/api/proxies/{proxy_id}")
def delete_proxy(proxy_id: int, request: Request) -> dict[str, bool]:
    if not request.app.state.db.delete_proxy(proxy_id):
        raise HTTPException(404, "прокси не найден")
    return {"ok": True}


@app.delete("/api/proxies")
def delete_all(request: Request) -> dict[str, int]:
    return {"deleted": request.app.state.db.delete_all()}


def _validate_settings(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        interval = int(payload["interval_sec"])
        timeout = int(payload["timeout_sec"])
        concurrency = int(payload["concurrency"])
        slow = int(payload["slow_ms"])
        grace = int(payload["restart_grace_sec"])
        check_url = str(payload["check_url"]).strip()
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, "проверьте поля настроек") from exc
    if not 15 <= interval <= 3600:
        raise HTTPException(400, "интервал от 15 до 3600 секунд")
    if not 3 <= timeout <= 60:
        raise HTTPException(400, "таймаут от 3 до 60 секунд")
    if not 1 <= concurrency <= 100:
        raise HTTPException(400, "параллельность от 1 до 100")
    if not 100 <= slow <= 60000:
        raise HTTPException(400, "порог медленного ответа от 100 до 60000 мс")
    if not 0 <= grace <= 120:
        raise HTTPException(400, "ожидание перезапуска от 0 до 120 секунд")
    parsed = urlparse(check_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(400, "URL проверки должен начинаться с http:// или https://")
    return {
        "interval_sec": interval,
        "timeout_sec": timeout,
        "concurrency": concurrency,
        "slow_ms": slow,
        "restart_grace_sec": grace,
        "check_url": check_url,
    }


def _harden(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    if "server" in response.headers:
        del response.headers["server"]
    return response


def _xlsx(payload: bytes, filename: str) -> Response:
    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
