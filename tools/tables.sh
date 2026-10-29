#!/bin/bash
for f in /tmp/hout/deflate-codec-rs_oracle.txt /tmp/hout/deflate-codec-rs_nop.txt /tmp/hout/webshop-incident-response_oracle.txt /tmp/hout/webshop-incident-response_nop.txt; do
  echo "########## $(basename "$f") ##########"
  sed 's/\x1b\[[0-9;]*m//g' "$f" | tr -d '\r' | grep -aE 'Trials|Reward|Investigation|Inflate|^│ +[0-9]' | grep -avE 'Count|^$' | sed 's/  */ /g' | tail -5
done
