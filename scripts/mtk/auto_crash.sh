#!/usr/bin/env bash
# 自动接手：等手机回系统 -> 先起 mtkclient 守候 -> adb reboot edl 制造新枚举窗口 -> crash
# 关键：等待阶段完全不碰 COM6（反复开关串口会把 Preloader 卡在旧状态），
#      只有设备已回系统、新窗口即将出现时才启动 mtkclient。
set -u
A="F:/root/platform-tools/adb.exe"
LOG="F:/root/Temp/auto_crash_$(date +%H%M%S).log"

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

say "等待手机回系统（最长 600s），期间不访问 COM6"
found=0
for i in $(seq 1 600); do
  out=$($A devices 2>/dev/null | grep -E 'device$' | grep -v 'List')
  if [ -n "$out" ]; then
    say "第 ${i}s 检测到回系统: $out"
    found=1
    break
  fi
  sleep 1
done

if [ "$found" -ne 1 ]; then
  say "600s 内未回系统，退出（未发送任何 reboot）"
  exit 1
fi

# 先挂 mtkclient：此时手机还在系统模式、没有 COM6，它会循环等待新窗口
say "启动 mtkclient crash 守候（DETECT 自动选串口）"
( cd "F:/root/mtkclient-2.1.4.1" && timeout 150 python -u mtk.py crash --serialport >> "$LOG" 2>&1 ) &
MTK_PID=$!
sleep 1

say "发送 adb reboot edl（制造全新枚举窗口）"
$A reboot edl 2>&1 | tee -a "$LOG"
say "reboot 已发送，等待 mtkclient 捕获新窗口"
wait "$MTK_PID"
say "mtkclient 结束；检查日志中是否出现 0E8D:0003 / Device detected / Kamakiri"
exit 0
