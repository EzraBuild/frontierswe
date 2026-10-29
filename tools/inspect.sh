#!/bin/bash
for D in $(find /home/user/fswe-jobs -type d -name "deflate-codec-rs__*"); do
  echo "########## $D ##########"
  echo "--- verifier dir ---"; ls -la "$D/verifier" 2>&1 | head
  echo "--- reward.txt ---"; cat "$D/verifier/reward.txt" 2>&1
  echo "--- reward.json ---"; head -c 700 "$D/verifier/reward.json" 2>&1; echo
  echo "--- build.log tail ---"; tail -5 "$D/verifier/build.log" 2>&1
  echo "--- verifier.log / stdout tail ---"; for f in "$D"/verifier/*.log "$D"/verifier/*stdout* "$D"/verifier/verifier.log; do [ -f "$f" ] && echo "[$f]" && tail -8 "$f"; done
done
