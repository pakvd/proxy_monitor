from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from app.checker import ip_kind
from app.vault import PREFIX, reveal, seal


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


PUBLIC_COLUMNS = """
id, host, port, address, name, protocol, enabled,
last_status, last_latency_ms, last_exit_ip, prev_exit_ip, exit_ip_changed,
last_error, last_http_status, last_checked_at, last_ok_at, fail_streak
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, _connect(self.path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS proxies (
                    id INTEGER PRIMARY KEY,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    login TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    address TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL DEFAULT '',
                    protocol TEXT NOT NULL DEFAULT 'http',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_status TEXT,
                    last_latency_ms INTEGER,
                    last_exit_ip TEXT,
                    prev_exit_ip TEXT,
                    exit_ip_changed INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    last_http_status INTEGER,
                    last_checked_at TEXT,
                    last_ok_at TEXT,
                    fail_streak INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(host, port, login)
                );

                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY,
                    proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
                    checked_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    latency_ms INTEGER,
                    exit_ip TEXT,
                    http_status INTEGER,
                    error TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_checks_proxy
                    ON checks(proxy_id, id DESC);
                CREATE INDEX IF NOT EXISTS idx_checks_time
                    ON checks(checked_at);

                CREATE TABLE IF NOT EXISTS exit_ips (
                    id INTEGER PRIMARY KEY,
                    proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
                    exit_ip TEXT NOT NULL,
                    hits INTEGER NOT NULL DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(proxy_id, exit_ip)
                );

                CREATE INDEX IF NOT EXISTS idx_exit_ips_ip
                    ON exit_ips(exit_ip);

                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    interval_sec INTEGER NOT NULL,
                    timeout_sec INTEGER NOT NULL,
                    concurrency INTEGER NOT NULL,
                    check_url TEXT NOT NULL,
                    slow_ms INTEGER NOT NULL,
                    restart_grace_sec INTEGER NOT NULL DEFAULT 30,
                    rotate_interval_min INTEGER NOT NULL DEFAULT 30,
                    rotate_hold_sec INTEGER NOT NULL DEFAULT 90,
                    rotate_bands_a TEXT NOT NULL DEFAULT '1,7,20',
                    rotate_bands_b TEXT NOT NULL DEFAULT '1,3,20',
                    reboot_after_min INTEGER NOT NULL DEFAULT 30,
                    rotate_force INTEGER NOT NULL DEFAULT 0,
                    rotate_enabled INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS modem_state (
                    farm TEXT NOT NULL,
                    name TEXT NOT NULL,
                    last_seen_at TEXT,
                    last_reboot_at TEXT,
                    hold_until TEXT,
                    PRIMARY KEY (farm, name)
                );
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(settings)")}
            additions = {
                "restart_grace_sec": "INTEGER NOT NULL DEFAULT 30",
                "rotate_interval_min": "INTEGER NOT NULL DEFAULT 30",
                "rotate_hold_sec": "INTEGER NOT NULL DEFAULT 90",
                "rotate_bands_a": "TEXT NOT NULL DEFAULT '1,7,20'",
                "rotate_bands_b": "TEXT NOT NULL DEFAULT '1,3,20'",
                "reboot_after_min": "INTEGER NOT NULL DEFAULT 30",
                "rotate_force": "INTEGER NOT NULL DEFAULT 0",
                "rotate_enabled": "INTEGER NOT NULL DEFAULT 1",
            }
            for name, declaration in additions.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE settings ADD COLUMN {name} {declaration}")
            conn.execute(
                """
                INSERT INTO settings (
                    id, interval_sec, timeout_sec, concurrency, check_url, slow_ms, restart_grace_sec
                )
                VALUES (1, 60, 15, 20, 'http://api.ipify.org', 3000, 30)
                ON CONFLICT(id) DO NOTHING
                """
            )
            _backfill_exit_ips(conn)
            _seal_stored_passwords(conn, self.path.parent)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get_settings(self) -> dict[str, Any]:
        with self._lock, _connect(self.path) as conn:
            row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        return dict(row)

    def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._lock, _connect(self.path) as conn:
            conn.execute(
                """
                UPDATE settings
                SET interval_sec = ?, timeout_sec = ?, concurrency = ?, check_url = ?, slow_ms = ?,
                    restart_grace_sec = ?, rotate_interval_min = ?, rotate_hold_sec = ?,
                    rotate_bands_a = ?, rotate_bands_b = ?, reboot_after_min = ?, rotate_enabled = ?
                WHERE id = 1
                """,
                (
                    int(values["interval_sec"]),
                    int(values["timeout_sec"]),
                    int(values["concurrency"]),
                    str(values["check_url"]),
                    int(values["slow_ms"]),
                    int(values["restart_grace_sec"]),
                    int(values["rotate_interval_min"]),
                    int(values["rotate_hold_sec"]),
                    str(values["rotate_bands_a"]),
                    str(values["rotate_bands_b"]),
                    int(values["reboot_after_min"]),
                    int(values["rotate_enabled"]),
                ),
            )
        return self.get_settings()

    def bump_rotation(self) -> int:
        with self._lock, _connect(self.path) as conn:
            conn.execute("UPDATE settings SET rotate_force = rotate_force + 1 WHERE id = 1")
            row = conn.execute("SELECT rotate_force FROM settings WHERE id = 1").fetchone()
        return int(row["rotate_force"])

    def modem_rows(self, farm: str) -> dict[str, dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                "SELECT * FROM modem_state WHERE farm = ?",
                (farm,),
            ).fetchall()
        return {row["name"]: dict(row) for row in rows}

    def latest_agent_seen(self) -> Optional[str]:
        with self._lock, _connect(self.path) as conn:
            row = conn.execute("SELECT MAX(last_seen_at) AS seen FROM modem_state").fetchone()
        return row["seen"] if row else None

    def agent_farms(self) -> list[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT farm, COUNT(*) AS modems, MAX(last_seen_at) AS last_seen_at
                FROM modem_state
                GROUP BY farm
                ORDER BY farm
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def note_agent(self, farm: str, names: list[str], reboot: list[str], hold_sec: int, hold_names: Optional[list[str]] = None) -> None:
        now = utcnow()
        hold = (datetime.now(timezone.utc) + timedelta(seconds=hold_sec)).isoformat(timespec="seconds")
        paused = set(reboot) | set(hold_names or [])
        with self._lock, _connect(self.path) as conn:
            for name in names:
                conn.execute(
                    """
                    INSERT INTO modem_state (farm, name, last_seen_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(farm, name) DO UPDATE SET last_seen_at = excluded.last_seen_at
                    """,
                    (farm, name, now),
                )
                if name in paused:
                    if name in reboot:
                        conn.execute(
                            """
                            UPDATE modem_state
                            SET last_reboot_at = ?, hold_until = ?
                            WHERE farm = ? AND name = ?
                            """,
                            (now, hold, farm, name),
                        )
                    else:
                        conn.execute(
                            "UPDATE modem_state SET hold_until = ? WHERE farm = ? AND name = ?",
                            (hold, farm, name),
                        )

    def hold_until(self, farm: str, name: str) -> Optional[str]:
        with self._lock, _connect(self.path) as conn:
            row = conn.execute(
                "SELECT hold_until FROM modem_state WHERE farm = ? AND name = ?",
                (farm, name),
            ).fetchone()
        return row["hold_until"] if row else None

    def upsert_proxy(self, row: dict[str, Any]) -> str:
        now = utcnow()
        with self._lock, _connect(self.path) as conn:
            existing = conn.execute(
                "SELECT id FROM proxies WHERE host = ? AND port = ? AND login = ?",
                (row["host"], row["port"], row["login"]),
            ).fetchone()
            if existing:
                if row["password"]:
                    conn.execute(
                        """
                        UPDATE proxies
                        SET password = ?, address = ?, name = ?, protocol = ?, enabled = 1, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            seal(row["password"], self.path.parent),
                            row["address"],
                            row["name"],
                            row["protocol"],
                            now,
                            existing["id"],
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE proxies
                        SET address = ?, name = ?, protocol = ?, enabled = 1, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            row["address"],
                            row["name"],
                            row["protocol"],
                            now,
                            existing["id"],
                        ),
                    )
                return "updated"
            conn.execute(
                """
                INSERT INTO proxies (
                    host, port, login, password, address, name, protocol, enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    row["host"],
                    row["port"],
                    row["login"],
                    seal(row["password"], self.path.parent),
                    row["address"],
                    row["name"],
                    row["protocol"],
                    now,
                    now,
                ),
            )
            return "created"

    def delete_missing(self, keys: set[tuple[str, int, str]]) -> int:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute("SELECT id, host, port, login FROM proxies").fetchall()
            doomed = [r["id"] for r in rows if (r["host"], r["port"], r["login"]) not in keys]
            for proxy_id in doomed:
                conn.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
            return len(doomed)

    def delete_proxy(self, proxy_id: int) -> bool:
        with self._lock, _connect(self.path) as conn:
            cur = conn.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
            return cur.rowcount > 0

    def delete_all(self) -> int:
        with self._lock, _connect(self.path) as conn:
            count = conn.execute("SELECT COUNT(*) AS n FROM proxies").fetchone()["n"]
            conn.execute("DELETE FROM proxies")
            return int(count)

    def set_enabled(self, proxy_id: int, enabled: bool) -> Optional[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            cur = conn.execute(
                "UPDATE proxies SET enabled = ?, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, utcnow(), proxy_id),
            )
            if cur.rowcount == 0:
                return None
        return self.get_public(proxy_id)

    def list_public(self) -> list[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                f"""
                SELECT {PUBLIC_COLUMNS}
                FROM proxies
                ORDER BY address, host, port, login
                """
            ).fetchall()
            counts = _exit_counts(conn)
        return [_with_ip_counts(_decorate(dict(row)), counts) for row in rows]

    def get_public(self, proxy_id: int) -> Optional[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            row = conn.execute(
                f"SELECT {PUBLIC_COLUMNS} FROM proxies WHERE id = ?",
                (proxy_id,),
            ).fetchone()
            counts = _exit_counts(conn)
        if row is None:
            return None
        return _with_ip_counts(_decorate(dict(row)), counts)

    def get_secret(self, proxy_id: int) -> Optional[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            row = conn.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)).fetchone()
        return _reveal_row(row, self.path.parent)

    def list_enabled_secrets(self) -> list[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                "SELECT * FROM proxies WHERE enabled = 1 ORDER BY id"
            ).fetchall()
        return [_reveal_row(row, self.path.parent) for row in rows]

    def export_rows(self) -> list[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT host, port, address, name, protocol
                FROM proxies
                ORDER BY address, host, port
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def save_check(self, proxy_id: int, result: Any) -> None:
        now = result.checked_at
        with self._lock, _connect(self.path) as conn:
            row = conn.execute(
                "SELECT last_exit_ip FROM proxies WHERE id = ?",
                (proxy_id,),
            ).fetchone()
            if row is None:
                return
            old_ip = row["last_exit_ip"] or ""
            new_ip = result.exit_ip or ""
            up = result.status in ("online", "slow")
            conn.execute(
                """
                INSERT INTO checks (proxy_id, checked_at, status, latency_ms, exit_ip, http_status, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proxy_id,
                    now,
                    result.status,
                    result.latency_ms,
                    result.exit_ip,
                    result.http_status,
                    result.error,
                ),
            )
            if new_ip:
                _note_exit_ip(conn, proxy_id, old_ip, new_ip, now)
                changed = 1 if old_ip and old_ip != new_ip else 0
                conn.execute(
                    """
                    UPDATE proxies SET
                        last_status = ?,
                        last_latency_ms = ?,
                        prev_exit_ip = CASE WHEN ? = 1 THEN last_exit_ip ELSE prev_exit_ip END,
                        last_exit_ip = ?,
                        exit_ip_changed = ?,
                        last_error = ?,
                        last_http_status = ?,
                        last_checked_at = ?,
                        last_ok_at = CASE WHEN ? THEN ? ELSE last_ok_at END,
                        fail_streak = CASE WHEN ? THEN 0 ELSE fail_streak + 1 END
                    WHERE id = ?
                    """,
                    (
                        result.status,
                        result.latency_ms,
                        changed,
                        new_ip,
                        changed,
                        result.error,
                        result.http_status,
                        now,
                        1 if up else 0,
                        now,
                        1 if up else 0,
                        proxy_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE proxies SET
                        last_status = ?,
                        last_latency_ms = ?,
                        last_error = ?,
                        last_http_status = ?,
                        last_checked_at = ?,
                        last_ok_at = CASE WHEN ? THEN ? ELSE last_ok_at END,
                        fail_streak = CASE WHEN ? THEN 0 ELSE fail_streak + 1 END
                    WHERE id = ?
                    """,
                    (
                        result.status,
                        result.latency_ms,
                        result.error,
                        result.http_status,
                        now,
                        1 if up else 0,
                        now,
                        1 if up else 0,
                        proxy_id,
                    ),
                )

    def ip_totals(self) -> dict[str, Any]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT exit_ip,
                       SUM(hits) AS hits,
                       COUNT(DISTINCT proxy_id) AS proxies,
                       MIN(first_seen) AS first_seen,
                       MAX(last_seen) AS last_seen
                FROM exit_ips
                GROUP BY exit_ip
                ORDER BY hits DESC, last_seen DESC
                """
            ).fetchall()
        unique = len(rows)
        repeated = [dict(row) for row in rows if int(row["hits"]) > 1]
        extra = sum(int(row["hits"]) - 1 for row in rows)
        return {
            "unique": unique,
            "repeated": len(repeated),
            "extra": extra,
            "repeats": repeated[:40],
        }

    def proxy_exit_ips(self, proxy_id: int, limit: int = 40) -> list[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT exit_ip, hits, first_seen, last_seen
                FROM exit_ips
                WHERE proxy_id = ?
                ORDER BY hits DESC, last_seen DESC
                LIMIT ?
                """,
                (proxy_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def history(self, proxy_id: int, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock, _connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT checked_at, status, latency_ms, exit_ip, http_status, error
                FROM checks
                WHERE proxy_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (proxy_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def prune(self, days: int = 3) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        with self._lock, _connect(self.path) as conn:
            conn.execute("DELETE FROM checks WHERE checked_at < ?", (cutoff,))


def _reveal_row(row: Any, directory: Path) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    revealed = dict(row)
    revealed["password"] = reveal(revealed.get("password") or "", directory)
    return revealed


def _seal_stored_passwords(conn: sqlite3.Connection, directory: Path) -> None:
    rows = conn.execute("SELECT id, password FROM proxies").fetchall()
    for row in rows:
        password = row["password"] or ""
        if password and not password.startswith(PREFIX):
            conn.execute(
                "UPDATE proxies SET password = ? WHERE id = ?",
                (seal(password, directory), row["id"]),
            )


def _decorate(row: dict[str, Any]) -> dict[str, Any]:
    row["enabled"] = bool(row["enabled"])
    row["exit_ip_changed"] = bool(row["exit_ip_changed"])
    row["exit_ip_kind"] = ip_kind(row.get("last_exit_ip"))
    return row


def _exit_counts(conn: sqlite3.Connection) -> dict[int, dict[str, int]]:
    rows = conn.execute(
        """
        SELECT proxy_id,
               COUNT(*) AS unique_ips,
               SUM(CASE WHEN hits > 1 THEN 1 ELSE 0 END) AS repeated_ips
        FROM exit_ips
        GROUP BY proxy_id
        """
    ).fetchall()
    return {
        int(row["proxy_id"]): {
            "unique_ips": int(row["unique_ips"]),
            "repeated_ips": int(row["repeated_ips"] or 0),
        }
        for row in rows
    }


def _with_ip_counts(row: dict[str, Any], counts: dict[int, dict[str, int]]) -> dict[str, Any]:
    stats = counts.get(int(row["id"]), {})
    row["unique_ips"] = stats.get("unique_ips", 0)
    row["repeated_ips"] = stats.get("repeated_ips", 0)
    return row


def _note_exit_ip(conn: sqlite3.Connection, proxy_id: int, old_ip: str, new_ip: str, now: str) -> None:
    if old_ip == new_ip:
        updated = conn.execute(
            "UPDATE exit_ips SET last_seen = ? WHERE proxy_id = ? AND exit_ip = ?",
            (now, proxy_id, new_ip),
        )
        if updated.rowcount:
            return
    existing = conn.execute(
        "SELECT hits FROM exit_ips WHERE proxy_id = ? AND exit_ip = ?",
        (proxy_id, new_ip),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE exit_ips SET hits = hits + 1, last_seen = ? WHERE proxy_id = ? AND exit_ip = ?",
            (now, proxy_id, new_ip),
        )
        return
    conn.execute(
        """
        INSERT INTO exit_ips (proxy_id, exit_ip, hits, first_seen, last_seen)
        VALUES (?, ?, 1, ?, ?)
        """,
        (proxy_id, new_ip, now, now),
    )


def _backfill_exit_ips(conn: sqlite3.Connection) -> None:
    if conn.execute("SELECT COUNT(*) AS n FROM exit_ips").fetchone()["n"]:
        return
    rows = conn.execute(
        """
        SELECT proxy_id, exit_ip, checked_at
        FROM checks
        WHERE exit_ip IS NOT NULL AND exit_ip != ''
        ORDER BY proxy_id, id
        """
    ).fetchall()
    previous: dict[int, str] = {}
    for row in rows:
        proxy_id = int(row["proxy_id"])
        exit_ip = row["exit_ip"]
        seen = row["checked_at"]
        old_ip = previous.get(proxy_id, "")
        _note_exit_ip(conn, proxy_id, old_ip, exit_ip, seen)
        previous[proxy_id] = exit_ip
