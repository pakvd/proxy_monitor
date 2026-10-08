"""Служба фермы: берёт интервал с монитора и крутит локальные модемы.

Пароль модема остаётся в agent.json на этом сервере и на монитор не уходит.
"""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional
def band_command(python: str, netmode: str, api: str, bands: list[int]) -> list[str]:
    command = [python, netmode, api, "--mode", "4g"]
    for band in bands:
        command.extend(["--lteband", str(band)])
    return command


def reboot_command(python: str, script: str, api: str) -> list[str]:
    return [python, script, api]


def modem_url(user: str, password: str, host: str) -> str:
    """Тот же адрес, что остаётся после кавычек в bash: http://admin:пароль@192.168.N.1.

    reboot.py и netmode.py разбирают его через urlparse и пароль не раскодируют,
    поэтому символы вроде @ и ! остаются как есть.
    """
    return f"http://{user}:{password}@{host}"


def expand_modems(data: dict[str, Any]) -> list[dict[str, str]]:
    """Один пароль на все модемы фермы. Имя модема — его IP, его же пишут в колонку name."""
    user = str(data.get("api_user", ""))
    password = str(data.get("api_password", ""))
    found: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, api: str) -> None:
        name = name.strip()
        if not name or name in seen:
            return
        seen.add(name)
        found.append({"name": name, "api": api})

    raw = data.get("modems") or []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                host = item.strip()
                if not user:
                    raise SystemExit("для списка IP нужен api_user")
                add(host, modem_url(user, password, host))
            elif isinstance(item, dict):
                host = str(item.get("host") or item.get("ip") or "").strip()
                name = str(item.get("name") or host).strip()
                api = str(item.get("api") or "")
                if not api:
                    if not host or not user:
                        raise SystemExit("у модема нужен api или host вместе с api_user")
                    api = modem_url(user, password, host)
                add(name, api)

    if data.get("modem_from") is not None or data.get("modem_to") is not None:
        if not user:
            raise SystemExit("для диапазона модемов нужен api_user")
        start = int(data["modem_from"])
        stop = int(data["modem_to"])
        if stop < start or stop - start > 99:
            raise SystemExit("диапазон модемов: от меньшего к большему, не больше 100 адресов")
        template = str(data.get("modem_template") or "192.168.{n}.1")
        for number in range(start, stop + 1):
            host = template.format(n=number)
            add(host, modem_url(user, password, host))

    if not found:
        raise SystemExit("в agent.json нужен список modems или диапазон modem_from/modem_to")
    return found


def load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not data.get("monitor") or not data.get("token") or not data.get("farm"):
        raise SystemExit("в agent.json нужны monitor, token и farm")
    data["modems"] = expand_modems(data)
    data.setdefault("netmode", "/home/pak/huawei-api/netmode.py")
    data.setdefault("reboot", "/home/pak/huawei-api/examples/reboot.py")
    data.setdefault("python", sys.executable)
    data.setdefault("insecure", True)
    return data


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"slot": None, "force": 0}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"slot": None, "force": 0}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state))
    temporary.replace(path)


def post_json(url: str, token: str, payload: dict[str, Any], insecure: bool) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url.rstrip("/") + "/api/agent/sync",
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    context = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        return json.loads(response.read().decode())


def switch_one(config: dict[str, Any], modem: dict[str, str], bands: list[int]) -> bool:
    label = modem["name"]
    command = band_command(config["python"], config["netmode"], modem["api"], bands)
    try:
        completed = subprocess.run(command, timeout=60, check=False, capture_output=True, text=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"{label}: смена диапазона не выполнена: {exc}", flush=True)
        return False
    if completed.returncode == 0:
        print(f"{label}: диапазоны {','.join(str(band) for band in bands)}", flush=True)
        return True
    print(f"{label}: netmode завершился с кодом {completed.returncode}", flush=True)
    return False


def apply_bands(config: dict[str, Any], modems: list[dict[str, str]], bands: list[int]) -> list[str]:
    done: list[str] = []
    workers = min(4, max(1, len(modems)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        jobs = {pool.submit(switch_one, config, modem, bands): modem["name"] for modem in modems}
        for job, name in jobs.items():
            if job.result():
                done.append(name)
    return done


def reboot_one(config: dict[str, Any], modem: dict[str, str]) -> bool:
    label = modem["name"]
    command = reboot_command(config["python"], config["reboot"], modem["api"])
    try:
        completed = subprocess.run(command, timeout=60, check=False, capture_output=True, text=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"{label}: перезагрузка не выполнена: {exc}", flush=True)
        return False
    if completed.returncode == 0:
        print(f"{label}: отправлена перезагрузка", flush=True)
        return True
    print(f"{label}: reboot.py завершился с кодом {completed.returncode}", flush=True)
    return False


def reboot_named(config: dict[str, Any], names: list[str]) -> None:
    by_name = {str(modem.get("name", "")): modem for modem in config["modems"]}
    for name in names:
        modem = by_name.get(name)
        if modem is None:
            print(f"нет модема {name or 'без имени'} в agent.json", flush=True)
            continue
        reboot_one(config, modem)


def sync_once(config: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    plan = post_json(
        str(config["monitor"]),
        str(config["token"]),
        {
            "farm": config["farm"],
            "modems": [modem["name"] for modem in config["modems"]],
            "applied_slot": state.get("slot"),
            "applied_force": int(state.get("force") or 0),
        },
        bool(config.get("insecure")),
    )
    bands = [int(band) for band in plan.get("bands") or []]
    if plan.get("apply_bands"):
        if state.get("working_slot") != plan.get("slot") or int(state.get("working_force") or 0) != int(plan.get("force") or 0):
            state["done"] = []
            state["working_slot"] = plan.get("slot")
            state["working_force"] = plan.get("force")
        done = set(state.get("done") or [])
        pending = [modem for modem in config["modems"] if modem["name"] not in done]
        done.update(apply_bands(config, pending, bands))
        state["done"] = sorted(done)
        if len(done) == len(config["modems"]):
            state["slot"] = plan["slot"]
            state["force"] = plan["force"]
    if plan.get("reboot"):
        reboot_named(config, [str(name) for name in plan["reboot"]])
    return plan


def main() -> None:
    path = Path(os.environ.get("AGENT_CONFIG", "/etc/proxy-monitor/agent.json"))
    config = load_config(path)
    state_path = Path(os.environ.get("AGENT_STATE", str(path.with_name("agent-state.json"))))
    state = load_state(state_path)
    print(f"ферма {config['farm']}: {len(config['modems'])} модемов, монитор {config['monitor']}", flush=True)
    while True:
        try:
            plan = sync_once(config, state)
            save_state(state_path, state)
            time.sleep(int(plan.get("poll_sec") or 20))
        except urllib.error.HTTPError as exc:
            print(f"монитор ответил {exc.code}", flush=True)
            time.sleep(20)
        except Exception as exc:
            print(f"нет связи с монитором: {exc}", flush=True)
            time.sleep(20)


if __name__ == "__main__":
    main()
