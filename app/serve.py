from __future__ import annotations

import os

from app.config import data_dir
from app.tls import ensure_certificate


def main() -> None:
    command = [
        "uvicorn",
        "app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8080",
        "--no-server-header",
    ]
    if os.environ.get("MONITOR_HTTPS", "0") == "1":
        names = [part.strip() for part in os.environ.get("MONITOR_TLS_NAMES", "").split(",") if part.strip()]
        cert, key = ensure_certificate(data_dir() / "certs", names)
        command += ["--ssl-certfile", str(cert), "--ssl-keyfile", str(key)]
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
