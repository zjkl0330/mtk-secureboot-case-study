#!/bin/bash
# 持续轮询 fastboot，抓住设备出现的瞬间
export PATH="/f/root/platform-tools:$PATH"
LOG=/f/root/k9pro/Temp/fbpoll.log
: > "$LOG"
END=$((SECONDS+300))
HITS=0
while [ $SECONDS -lt $END ]; do
  OUT=$(timeout 2 fastboot devices 2>&1)
  if [ -n "$OUT" ]; then
    echo "$(date +%H:%M:%S) HIT: $OUT" >> "$LOG"
    HITS=$((HITS+1))
  fi
  sleep 0.3
done
echo "POLL_ENDED hits=$HITS" >> "$LOG"
