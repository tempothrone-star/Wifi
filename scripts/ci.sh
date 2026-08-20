#!/usr/bin/env bash
# Offline CI entrypoint (pytest + pyflakes). No wireless hardware required.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pip install -q pytest PyYAML rich pyflakes
python3 -m pytest tests/ -q --tb=short
python3 -m pyflakes handshaker tests bootstrap.py
echo "ci ok"
