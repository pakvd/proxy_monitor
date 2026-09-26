import asyncio
import unittest

from app.checker import CheckResult, build_proxy_url, check_proxy, check_through_restart, extract_ip, ip_kind
from app.db import Database


class ParseTests(unittest.TestCase):
    def test_extract_ip(self):
        self.assertEqual(extract_ip("203.0.113.10\n"), "203.0.113.10")
        self.assertEqual(extract_ip('{"ip":"198.51.100.8"}'), "198.51.100.8")
        self.assertEqual(extract_ip('{"origin":"1.1.1.1, 2.2.2.2"}'), "1.1.1.1")
        self.assertIsNone(extract_ip("<html>login</html>"))

    def test_ip_kind(self):
        self.assertEqual(ip_kind("8.8.8.8"), "public")
        self.assertEqual(ip_kind("203.0.113.50"), "public")
        self.assertEqual(ip_kind("10.1.1.1"), "private")
        self.assertEqual(ip_kind("192.168.0.4"), "private")
        self.assertEqual(ip_kind("100.64.0.5"), "cgnat")
        self.assertEqual(ip_kind("2001:db8::1"), "public")

    def test_proxy_url_encodes_secrets(self):
        url = build_proxy_url({
            "host": "10.0.0.1",
            "port": 3000,
            "login": "a b",
            "password": "p@ss",
            "protocol": "http",
        })
        self.assertEqual(url, "http://a%20b:p%40ss@10.0.0.1:3000")
        self.assertNotIn("p@ss", url)


class DatabaseTests(unittest.TestCase):
    def test_exit_ip_change_and_hidden_password(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            database = Database(Path(tmp) / "monitor.db")
            database.init()
            database.upsert_proxy({
                "host": "203.0.113.10",
                "port": 30001,
                "login": "user",
                "password": "secret",
                "address": "farm-01",
                "name": "",
                "protocol": "http",
            })
            proxy_id = database.list_public()[0]["id"]
            database.save_check(proxy_id, CheckResult("online", 120, "1.1.1.1", 200, None, "2026-09-26T08:00:00+00:00"))
            database.save_check(proxy_id, CheckResult("online", 130, "2.2.2.2", 200, None, "2026-09-26T08:01:00+00:00"))
            proxy = database.get_public(proxy_id)
            self.assertNotIn("password", proxy)
            self.assertTrue(proxy["exit_ip_changed"])
            self.assertEqual(proxy["prev_exit_ip"], "1.1.1.1")
            self.assertEqual(proxy["last_exit_ip"], "2.2.2.2")
            database.save_check(proxy_id, CheckResult("offline", 20, None, None, "порт закрыт", "2026-09-26T08:02:00+00:00"))
            proxy = database.get_public(proxy_id)
            self.assertEqual(proxy["last_exit_ip"], "2.2.2.2")
            self.assertEqual(proxy["fail_streak"], 1)
            self.assertEqual(len(database.history(proxy_id)), 3)
            self.assertEqual(database.get_settings()["restart_grace_sec"], 30)

    def test_existing_database_receives_restart_grace(self):
        import sqlite3
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "monitor.db"
            conn = sqlite3.connect(path)
            conn.execute(
                """
                CREATE TABLE settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    interval_sec INTEGER NOT NULL,
                    timeout_sec INTEGER NOT NULL,
                    concurrency INTEGER NOT NULL,
                    check_url TEXT NOT NULL,
                    slow_ms INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT INTO settings VALUES (1, 60, 15, 20, 'http://api.ipify.org', 3000)"
            )
            conn.commit()
            conn.close()
            database = Database(path)
            database.init()
            self.assertEqual(database.get_settings()["restart_grace_sec"], 30)
            self.assertEqual(database.get_settings()["interval_sec"], 60)

    def test_unique_exit_ips_and_repeats(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            database = Database(Path(tmp) / "monitor.db")
            database.init()
            database.upsert_proxy({
                "host": "203.0.113.10",
                "port": 30001,
                "login": "user",
                "password": "secret",
                "address": "farm-01",
                "name": "",
                "protocol": "http",
            })
            proxy_id = database.list_public()[0]["id"]

            def seen(exit_ip: str, at: str) -> None:
                database.save_check(proxy_id, CheckResult("online", 10, exit_ip, 200, None, at))

            seen("1.1.1.1", "2026-09-26T08:00:00+00:00")
            seen("1.1.1.1", "2026-09-26T08:01:00+00:00")
            seen("2.2.2.2", "2026-09-26T08:02:00+00:00")
            seen("1.1.1.1", "2026-09-26T08:03:00+00:00")
            totals = database.ip_totals()
            self.assertEqual(totals["unique"], 2)
            self.assertEqual(totals["repeated"], 1)
            self.assertEqual(totals["extra"], 1)
            proxy = database.get_public(proxy_id)
            self.assertEqual(proxy["unique_ips"], 2)
            self.assertEqual(proxy["repeated_ips"], 1)
            hits = {row["exit_ip"]: row["hits"] for row in database.proxy_exit_ips(proxy_id)}
            self.assertEqual(hits["1.1.1.1"], 2)
            self.assertEqual(hits["2.2.2.2"], 1)

    def test_password_is_sealed_and_not_replaced_by_blank_import(self):
        import sqlite3
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            database = Database(Path(tmp) / "monitor.db")
            database.init()
            database.upsert_proxy({
                "host": "203.0.113.10",
                "port": 30001,
                "login": "user",
                "password": "secret",
                "address": "farm-01",
                "name": "",
                "protocol": "http",
            })
            proxy_id = database.list_public()[0]["id"]
            self.assertNotIn("login", database.get_public(proxy_id))
            self.assertEqual(database.get_secret(proxy_id)["password"], "secret")
            stored = sqlite3.connect(database.path).execute(
                "SELECT password FROM proxies WHERE id = ?",
                (proxy_id,),
            ).fetchone()[0]
            self.assertTrue(stored.startswith("enc:v1:"))
            self.assertNotIn("secret", stored)
            database.upsert_proxy({
                "host": "203.0.113.10",
                "port": 30001,
                "login": "user",
                "password": "",
                "address": "farm-02",
                "name": "",
                "protocol": "http",
            })
            self.assertEqual(database.get_secret(proxy_id)["password"], "secret")
            self.assertEqual(database.get_public(proxy_id)["address"], "farm-02")


def _settings(url="http://api.ipify.org"):
    return {
        "timeout_sec": 3,
        "slow_ms": 3000,
        "check_url": url,
        "interval_sec": 60,
        "concurrency": 5,
    }


async def _serve(status, body=b'{"ip":"203.0.113.50"}'):
    async def handle(reader, writer):
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        except Exception:
            writer.close()
            return
        if status == 407:
            raw = b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        else:
            raw = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
        writer.write(raw)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


class CheckTests(unittest.TestCase):
    def test_online_through_local_proxy(self):
        async def scenario():
            server, port = await _serve(200)
            try:
                result = await check_proxy({
                    "host": "127.0.0.1",
                    "port": port,
                    "login": "user",
                    "password": "secret",
                    "protocol": "http",
                }, _settings())
                return result
            finally:
                server.close()
                await server.wait_closed()

        result = asyncio.run(scenario())
        self.assertEqual(result.status, "online", result.error)
        self.assertEqual(result.exit_ip, "203.0.113.50")
        self.assertGreaterEqual(result.latency_ms, 0)

    def test_auth_failure(self):
        async def scenario():
            server, port = await _serve(407)
            try:
                return await check_proxy({
                    "host": "127.0.0.1",
                    "port": port,
                    "login": "user",
                    "password": "bad",
                    "protocol": "http",
                }, _settings())
            finally:
                server.close()
                await server.wait_closed()

        result = asyncio.run(scenario())
        self.assertEqual(result.status, "auth", result.error)

    def test_closed_port(self):
        async def scenario():
            return await check_proxy({
                "host": "127.0.0.1",
                "port": 1,
                "login": "",
                "password": "",
                "protocol": "http",
            }, _settings())

        result = asyncio.run(scenario())
        self.assertEqual(result.status, "offline")
        self.assertEqual(result.error, "порт закрыт")


class RestartTests(unittest.TestCase):
    def test_closed_port_during_restart_is_not_stored_if_it_returns(self):
        calls = {"n": 0}

        async def probe(_proxy, _settings):
            calls["n"] += 1
            if calls["n"] == 1:
                return CheckResult("offline", 4, None, None, "порт закрыт", "t")
            return CheckResult("online", 20, "1.1.1.1", 200, None, "t")

        async def scenario():
            return await check_through_restart(
                {"host": "10.0.0.1", "port": 3000},
                {"restart_grace_sec": 30},
                probe=probe,
                sleep=_instant,
            )

        result = asyncio.run(scenario())
        self.assertEqual(result.status, "online")
        self.assertEqual(result.exit_ip, "1.1.1.1")
        self.assertEqual(calls["n"], 2)

    def test_auth_error_is_not_retried(self):
        calls = {"n": 0}

        async def probe(_proxy, _settings):
            calls["n"] += 1
            return CheckResult("auth", 8, None, 407, "неверный логин или пароль", "t")

        async def scenario():
            return await check_through_restart(
                {"host": "10.0.0.1", "port": 3000},
                {"restart_grace_sec": 30},
                probe=probe,
                sleep=_instant,
            )

        result = asyncio.run(scenario())
        self.assertEqual(result.status, "auth")
        self.assertEqual(calls["n"], 1)

    def test_grace_zero_records_the_first_failure(self):
        calls = {"n": 0}

        async def probe(_proxy, _settings):
            calls["n"] += 1
            return CheckResult("offline", 4, None, None, "порт закрыт", "t")

        async def scenario():
            return await check_through_restart(
                {"host": "10.0.0.1", "port": 3000},
                {"restart_grace_sec": 0},
                probe=probe,
                sleep=_instant,
            )

        result = asyncio.run(scenario())
        self.assertEqual(result.status, "offline")
        self.assertEqual(calls["n"], 1)


async def _instant(_seconds):
    return None


if __name__ == "__main__":
    unittest.main()
