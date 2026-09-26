#!/bin/sh
cd "$(dirname "$0")"
if command -v python3.12 >/dev/null 2>&1; then
  PY=python3.12
elif command -v python3.11 >/dev/null 2>&1; then
  PY=python3.11
else
  PY=python3
fi
if [ ! -x .venv/bin/uvicorn ]; then
  "$PY" -m venv .venv
  .venv/bin/pip install -r requirements.txt
fi
exec .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
