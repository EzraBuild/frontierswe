#!/bin/bash
# Verifier entry point (the grader runs this as root after the agent phase).
# All grading logic lives in verify.py next to this file.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /logs/verifier
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
python3 -I "$HERE/verify.py"
# Belt and braces: never leave the reward file missing.
if [ ! -s /logs/verifier/reward.txt ]; then
  echo "0.0" > /logs/verifier/reward.txt
fi
exit 0
