#!/bin/bash
# 完整流程：系统 -> fastbootd -> reboot bootloader(2769) -> 立刻抢连 fastboot
export PATH="/f/root/platform-tools:$PATH"
LOG=/f/root/k9pro/Temp/chain.log
: > "$LOG"
log(){ echo "$(date +%H:%M:%S) $*" | tee -a "$LOG"; }

log "=== 阶段0：等待设备回到系统（最长 240s）==="
OK=0
for i in $(seq 1 120); do
  if adb devices 2>/dev/null | grep -q "device$"; then OK=1; log "设备已回系统 (第 ${i} 次探测)"; break; fi
  sleep 2
done
if [ "$OK" -ne 1 ]; then
  log "!! 240s 内 adb 未出现，退出。请手动长按电源 15 秒让手机开机"
  exit 1
fi

log "=== 阶段1：reboot fastboot (fastbootd) ==="
adb reboot fastboot 2>&1 | tee -a "$LOG"
for i in $(seq 1 30); do
  if fastboot devices 2>/dev/null | grep -q .; then log "fastbootd 就绪"; break; fi
  sleep 1
done
timeout 10 fastboot getvar is-userspace 2>&1 | tee -a "$LOG"

log "=== 阶段2：从 fastbootd 跳真 bootloader ==="
timeout 15 fastboot reboot bootloader 2>&1 | tee -a "$LOG"

log "=== 阶段3：立刻抢占真 fastboot（阻塞等待，最长 90s）==="
timeout 90 fastboot getvar all 2>&1 | tee -a "$LOG" | tail -40

log "=== 阶段4：若设备仍在线，读关键变量 ==="
for v in product unlocked secure is-userspace current-slot serialno; do
  echo "--- $v ---" >> "$LOG"
  timeout 10 fastboot getvar $v 2>&1 | tee -a "$LOG"
done

log "=== 结束 ==="
