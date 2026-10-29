#!/bin/bash
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
export PATH="$HOME/.local/bin:$PATH"
export COLUMNS=200
rm -rf /home/user/fswe-jobs /tmp/hout
mkdir -p /tmp/hout
for NAME in deflate-codec-rs webshop-incident-response; do
  for AG in oracle nop; do
    OUT=/tmp/hout/${NAME}_${AG}.txt
    harbor run -p "tasks/$NAME" -a "$AG" -o /home/user/fswe-jobs >"$OUT" 2>&1
    echo "################## $NAME :: $AG ##################"
    # strip box-drawing, show the Mean progress line and the results-table data row
    grep -aoE "Mean: [0-9.]+" "$OUT" | tail -1
    # also find the job results json mean if present
  done
done
echo "===== job results json (mean_reward) ====="
find /home/user/fswe-jobs -maxdepth 2 -name "*.json" | while read f; do
  python3 -c "import json,sys;d=json.load(open('$f'));m=d.get('mean_reward',d.get('mean'));print('$f'.split('/')[-2], 'mean=',m) if m is not None else None" 2>/dev/null
done
