#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"
echo "[NIDS] Starting FastAPI Backend on http://127.0.0.1:8000 ..."
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
