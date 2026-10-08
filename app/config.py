from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.1.0"


def data_dir() -> Path:
    raw = os.environ.get("DATA_DIR")
    path = Path(raw) if raw else ROOT / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def monitor_password() -> str:
    return os.environ.get("MONITOR_PASSWORD", "")


def agent_token() -> str:
    return os.environ.get("MONITOR_AGENT_TOKEN", "").strip()


def autostart() -> bool:
    return os.environ.get("MONITOR_AUTOSTART", "1") != "0"
