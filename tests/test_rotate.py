import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.checker import CheckResult
from app.db import Database
from app.rotate import bands_for_slot, decide, failure_hidden, modems_to_reboot, parse_bands, schedule


def _proxy(name, status, ok_at, checked_at):
    return {
        "address": "farm-01",
        "name": name,
        "enabled": 1,
        "last_status": status,
        "last_ok_at": ok_at,
        "last_checked_at": checked_at,
    }


class ModemListTests(unittest.TestCase):
    def test_range_builds_every_modem_on_the_farm(self):
        from agent.farm_agent import expand_modems

        modems = expand_modems({
            "api_user": "admin",
            "api_password": "@x!",
            "modem_from": 1,
            "modem_to": 50,
            "modem_template": "192.168.{n}.1",
        })
        self.assertEqual(len(modems), 50)
        self.assertEqual(modems[0]["name"], "192.168.1.1")
        self.assertEqual(modems[49]["name"], "192.168.50.1")
        self.assertIn("192.168.12.1", modems[11]["api"])
        self.assertEqual(modems[0]["api"], "http://admin:@x!@192.168.1.1")

    def test_reboot_calls_the_same_script_as_the_manual_loop(self):
        from agent.farm_agent import reboot_command

        command = reboot_command(
            "python3",
            "/home/pak/huawei-api/examples/reboot.py",
            "http://admin:@x!@192.168.12.1",
        )
        self.assertEqual(command, [
            "python3",
            "/home/pak/huawei-api/examples/reboot.py",
            "http://admin:@x!@192.168.12.1",
        ])


class ScheduleTests(unittest.TestCase):
    def test_slots_alternate_band_sets(self):
        first = parse_bands("1,7,20")
        second = parse_bands("1, 3, 20")
        self.assertEqual(bands_for_slot(0, first, second), [1, 7, 20])
        self.assertEqual(bands_for_slot(1, first, second), [1, 3, 20])
        clock = schedule(30 * 60 + 10, 30)
        self.assertEqual(clock["slot"], 1)
        self.assertLess(clock["phase"], 90)

    def test_hold_only_while_agent_is_fresh(self):
        settings = {
            "rotate_enabled": 1,
            "rotate_interval_min": 30,
            "rotate_hold_sec": 90,
        }
        start = 30 * 60
        fresh = datetime.fromtimestamp(start, timezone.utc).isoformat(timespec="seconds")
        self.assertTrue(failure_hidden(settings, start + 10, fresh, None))
        self.assertFalse(failure_hidden(settings, start + 10, None, None))
        self.assertFalse(failure_hidden(settings, start + 200, fresh, None))

    def test_reboot_when_every_port_is_down(self):
        now = datetime.now(timezone.utc)
        old = (now - timedelta(minutes=40)).isoformat(timespec="seconds")
        recent = (now - timedelta(minutes=1)).isoformat(timespec="seconds")
        down = [_proxy("vlan12", "timeout", old, recent), _proxy("vlan12", "offline", old, recent)]
        self.assertEqual(modems_to_reboot(down, "farm-01", ["vlan12"], now, 30, {}, {}), ["vlan12"])
        mixed = down + [_proxy("vlan12", "online", recent, recent)]
        self.assertEqual(modems_to_reboot(mixed, "farm-01", ["vlan12"], now, 30, {}, {}), [])
        auth = [_proxy("vlan12", "auth", old, recent)]
        self.assertEqual(modems_to_reboot(auth, "farm-01", ["vlan12"], now, 30, {}, {}), [])
        cooled = { "vlan12": now.isoformat(timespec="seconds") }
        self.assertEqual(modems_to_reboot(down, "farm-01", ["vlan12"], now, 30, cooled, {}), [])


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = self.tmp.name
        os.environ["MONITOR_AUTOSTART"] = "0"
        os.environ["MONITOR_PASSWORD"] = ""
        os.environ["MONITOR_ALLOWLIST"] = "203.0.113.9"
        os.environ["MONITOR_AGENT_TOKEN"] = "agent-secret"
        self.db = Database(Path(self.tmp.name) / "monitor.db")
        self.db.init()

    def tearDown(self):
        self.tmp.cleanup()
        os.environ["MONITOR_ALLOWLIST"] = ""
        os.environ["MONITOR_AGENT_TOKEN"] = ""

    def test_agent_syncs_through_the_panel_allowlist(self):
        from fastapi.testclient import TestClient
        from app.main import app

        self.db.upsert_proxy({
            "host": "203.0.113.10",
            "port": 30001,
            "login": "user",
            "password": "secret",
            "address": "farm-01",
            "name": "vlan12",
            "protocol": "http",
        })
        old = (datetime.now(timezone.utc) - timedelta(minutes=40)).isoformat(timespec="seconds")
        proxy_id = self.db.list_public()[0]["id"]
        self.db.save_check(proxy_id, CheckResult("timeout", None, None, None, "нет ответа", old))
        with TestClient(app) as client:
            blocked = client.get("/api/overview")
            self.assertEqual(blocked.status_code, 403)
            denied = client.post("/api/agent/sync", json={"farm": "farm-01", "modems": ["vlan12"]})
            self.assertEqual(denied.status_code, 401)
            synced = client.post(
                "/api/agent/sync",
                json={"farm": "farm-01", "modems": ["vlan12"], "applied_slot": None, "applied_force": 0},
                headers={"Authorization": "Bearer agent-secret"},
            )
            self.assertEqual(synced.status_code, 200)
            body = synced.json()
            self.assertIn(body["bands"], ([1, 7, 20], [1, 3, 20]))
            self.assertTrue(body["apply_bands"])
            self.assertEqual(body["reboot"], ["vlan12"])
            again = client.post(
                "/api/agent/sync",
                json={"farm": "farm-01", "modems": ["vlan12"], "applied_slot": body["slot"], "applied_force": body["force"]},
                headers={"Authorization": "Bearer agent-secret"},
            )
            self.assertEqual(again.json()["reboot"], [])
            self.assertFalse(again.json()["apply_bands"])

    def test_decide_follows_panel_interval(self):
        settings = self.db.get_settings()
        settings["rotate_enabled"] = 1
        settings["rotate_interval_min"] = 30
        plan = decide(
            now=0,
            settings=settings,
            proxies=[],
            farm="farm-01",
            modems=["vlan12"],
            applied_slot=0,
            applied_force=0,
            last_reboot={},
            hold_until={},
        )
        self.assertEqual(plan["bands"], [1, 7, 20])
        self.assertFalse(plan["apply_bands"])
        later = decide(
            now=30 * 60,
            settings=settings,
            proxies=[],
            farm="farm-01",
            modems=["vlan12"],
            applied_slot=0,
            applied_force=0,
            last_reboot={},
            hold_until={},
        )
        self.assertEqual(later["bands"], [1, 3, 20])
        self.assertTrue(later["apply_bands"])


if __name__ == "__main__":
    unittest.main()
