#!/usr/bin/env bash
# Run IMBAS locally.
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[*] creating venv…"
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

echo "[*] starting IMBAS on http://127.0.0.1:8000"
exec .venv/bin/uvicorn app:app --app-dir backend --host 127.0.0.1 --port 8000
