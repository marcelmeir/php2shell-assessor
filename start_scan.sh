#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
CONFIG_FILE="${1:-scan_config.toml}"

if [ ! -x ".venv/bin/python" ]; then
  "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run_scan.py "$CONFIG_FILE"
