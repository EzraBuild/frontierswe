#!/bin/bash
# Verifier entry point. Harbor uploads tests/ to /tests and runs this as root
# in the (now cleaned) agent container. All grading logic is in grade.py.
set -u
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH

mkdir -p /logs/verifier
# Fallback reward: if grade.py crashes before writing, a do-nothing run scores 0.
echo "0.0" > /logs/verifier/reward.txt

/usr/bin/python3 "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/grade.py"
exit 0
