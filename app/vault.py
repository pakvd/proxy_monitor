from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"
_CACHE: dict[str, Fernet] = {}


def seal(password: str, directory: Path) -> str:
    if not password or password.startswith(PREFIX):
        return password
    token = _fernet(directory).encrypt(password.encode()).decode()
    return PREFIX + token


def reveal(stored: str, directory: Path) -> str:
    if not stored:
        return ""
    if not stored.startswith(PREFIX):
        return stored
    try:
        return _fernet(directory).decrypt(stored[len(PREFIX):].encode()).decode()
    except InvalidToken:
        return ""


def _fernet(directory: Path) -> Fernet:
    secret = os.environ.get("MONITOR_SECRET", "").strip()
    cache_key = f"env:{secret}" if secret else f"file:{directory}"
    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached
    if secret:
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    else:
        path = directory / ".proxy-key"
        directory.mkdir(parents=True, exist_ok=True)
        if path.is_file() and path.read_bytes().strip():
            key = path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            path.write_bytes(key)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    fernet = Fernet(key)
    _CACHE[cache_key] = fernet
    return fernet
