#!/bin/bash
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
export PATH="$HOME/.local/bin:$PATH"
OUTDIR="$(cd "$(dirname "$0")/.." && pwd)/tools/harbor-out"
rm -rf "$OUTDIR" /home/user/fswe-jobs; mkdir -p "$OUTDIR"
REPORT="$OUTDIR/RESULTS.txt"
: > "$REPORT"
for NAME in deflate-codec-rs webshop-incident-response; do
  for AG in oracle nop; do
    RAW="$OUTDIR/${NAME}_${AG}.log"
    harbor run -p "tasks/$NAME" -a "$AG" -o /home/user/fswe-jobs >"$RAW" 2>&1
    clean=$(sed 's/\x1b\[[0-9;]*m//g' "$RAW" | tr -d '\r')
    echo "################## $NAME :: $AG ##################" | tee -a "$REPORT"
    echo "$clean" | grep -aE 'Trials|Reward|Exception|^│ +[0-9]|Investigation|Inflate' | grep -avE 'Count' | sed 's/  */ /g' | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
  done
done
echo "===== authoritative reward.txt per trial =====" | tee -a "$REPORT"
find /home/user/fswe-jobs -name reward.txt | sort | while read f; do
  d=$(basename $(dirname $(dirname "$f")))
  printf "%-42s %s\n" "$d" "$(cat "$f")" | tee -a "$REPORT"
done
echo "" ; echo "report written to $REPORT"
