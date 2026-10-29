#!/bin/bash
# usage: verify_task.sh <task-name> <image-tag>  -- mirrors Harbor: agent phase as 'agent', verifier as root
set -u
NAME="$1"; TAG="$2"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
T="$REPO/tasks/$NAME"
echo "=== task.toml key lines ==="
grep -E "network_mode|^cpus|memory_mb|timeout_sec|difficulty|^name|^category|build_timeout" "$T/task.toml"
echo "=== BUILD ==="
if docker build -t "$TAG" "$T/environment" >/tmp/${TAG}_build.log 2>&1; then echo "build OK"; else echo "BUILD FAIL"; tail -25 /tmp/${TAG}_build.log; exit 1; fi
run_phase () {
  local with_sol="$1"
  docker run --rm --user 0:0 \
    -v "$T/tests":/tests:ro $with_sol \
    "$TAG" bash -c '
      set -e
      mkdir -p /logs/verifier && chmod 777 /logs/verifier
      if [ -d /solution ]; then
        cp -r /solution /tmp/sol && chmod -R +rx /tmp/sol
        chown -R agent /app /tmp/sol 2>/dev/null || true
        su agent -c "cd /app && bash /tmp/sol/solve.sh" >/tmp/solve.out 2>&1 || { echo "SOLVE_FAIL"; tail -40 /tmp/solve.out; }
      fi
      chmod +x /tests/test.sh 2>/dev/null || true
      ( cd /app && bash /tests/test.sh ) >/tmp/grade.out 2>&1 || true
      echo -n "REWARD="; cat /logs/verifier/reward.txt 2>/dev/null || echo "NO_REWARD_FILE"
      echo
    '
}
echo "=== ORACLE (solve.sh as agent, then verifier as root) ==="
run_phase "-v $T/solution:/solution:ro"
echo "=== NOP (verifier only, no solve) ==="
run_phase ""
