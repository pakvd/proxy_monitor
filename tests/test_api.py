import os
import tempfile
import unittest

os.environ.setdefault("MONITOR_AUTOSTART", "0")
os.environ.setdefault("MONITOR_PASSWORD", "")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = self.tmp.name
        os.environ["MONITOR_AUTOSTART"] = "0"
        os.environ["MONITOR_PASSWORD"] = ""
        os.environ["MONITOR_ALLOWLIST"] = ""
        os.environ["MONITOR_HTTPS"] = ""
        os.environ["MONITOR_COOKIE_SECURE"] = ""
        os.environ["MONITOR_AGENT_TOKEN"] = ""
        from app.access import guard
        guard.reset()

    def tearDown(self):
        self.tmp.cleanup()

    def _client(self):
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    def test_import_overview_and_export(self):
        from app.importer import parse_xlsx, workbook_bytes

        payload = workbook_bytes([{
            "host": "203.0.113.10",
            "port": 30001,
            "login": "user",
            "password": "secret",
            "address": "farm-01",
            "name": "vlan12",
            "protocol": "http",
        }])
        with self._client() as client:
            imported = client.post(
                "/api/import",
                files={"file": ("p.xlsx", payload, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
                data={"replace_missing": "false"},
            )
            self.assertEqual(imported.status_code, 200, imported.text)
            self.assertEqual(imported.json()["created"], 1)
            overview = client.get("/api/overview")
            self.assertEqual(overview.status_code, 200)
            proxy = overview.json()["proxies"][0]
            self.assertNotIn("password", proxy)
            self.assertNotIn("login", proxy)
            self.assertNotIn("secret", overview.text)
            self.assertEqual(proxy["address"], "farm-01")
            self.assertEqual(overview.json()["stats"]["pending"], 1)
            exported = client.get("/api/export.xlsx")
            self.assertEqual(exported.status_code, 200)
            self.assertNotIn(b"secret", exported.content)
            rows, errors = parse_xlsx(exported.content)
            self.assertEqual(errors, [])
            self.assertEqual(rows[0]["password"], "")
            self.assertEqual(rows[0]["login"], "")

    def test_password_gate(self):
        os.environ["MONITOR_PASSWORD"] = "panel-secret"
        with self._client() as client:
            denied = client.get("/api/overview")
            self.assertEqual(denied.status_code, 401)
            bad = client.post("/api/login", json={"password": "nope"})
            self.assertEqual(bad.status_code, 401)
            ok = client.post("/api/login", json={"password": "panel-secret"})
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(client.get("/api/overview").status_code, 200)
            self.assertEqual(client.get("/api/health").status_code, 200)

    def test_allowlist_blocks_other_addresses(self):
        from fastapi.testclient import TestClient
        from app.main import app

        os.environ["MONITOR_ALLOWLIST"] = "203.0.113.9"
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
            denied = client.get("/api/overview")
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(denied.headers["x-frame-options"], "DENY")
            self.assertIn("закрыт", denied.json()["detail"])

    def test_login_lockout(self):
        os.environ["MONITOR_PASSWORD"] = "panel-secret"
        with self._client() as client:
            for _ in range(5):
                self.assertEqual(client.post("/api/login", json={"password": "nope"}).status_code, 401)
            locked = client.post("/api/login", json={"password": "panel-secret"})
            self.assertEqual(locked.status_code, 429)

    def test_settings_validation(self):
        with self._client() as client:
            bad = client.put("/api/settings", json={
                "interval_sec": 1,
                "timeout_sec": 15,
                "concurrency": 20,
                "slow_ms": 3000,
                "check_url": "http://api.ipify.org",
            })
            self.assertEqual(bad.status_code, 400)


if __name__ == "__main__":
    unittest.main()
