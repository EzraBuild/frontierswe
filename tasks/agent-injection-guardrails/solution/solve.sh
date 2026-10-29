#!/bin/bash
# Reference solution: install the reference decision module as the agent's
# planner. The implementation lives next to this script.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

cp "$HERE/planner.py" /app/assistant/planner.py

# Smoke test against the sample scenarios (not the graded ones).
cd /app
python3 samples/run_local.py
echo "reference planner installed"
