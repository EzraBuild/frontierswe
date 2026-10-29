#!/bin/bash
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
export PATH="$HOME/.local/bin:$PATH"
rm -rf /home/user/fswe-jobs
for NAME in deflate-codec-rs webshop-incident-response; do
  for AG in oracle nop; do
    echo "################## $NAME :: $AG ##################"
    harbor run -p "tasks/$NAME" -a "$AG" -o /home/user/fswe-jobs 2>&1 | grep -iE "Mean:|Exception|Traceback|Error" | grep -ivE "stderr|MinRewardError" | head -6
  done
done
echo "===== REWARD FILES ====="
for f in $(find /home/user/fswe-jobs -name reward.txt | sort); do
  d=$(basename $(dirname $(dirname "$f")))
  printf "%-40s reward.txt=%s\n" "$d" "$(cat "$f")"
done
