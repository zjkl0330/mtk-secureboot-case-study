#!/usr/bin/env python3
"""守候设备重新枚举并自动执行 mtkclient crash。

关键：等待阶段只用 serial.tools.list_ports 枚举（不打开串口），
避免反复 open/close 把 Preloader 卡在 echo 状态。
一旦检测到目标串口（OPPO Preloader / BROM）出现，立刻启动 mtkclient 抓新鲜握手窗口。
若设备先回系统，则自动 adb reboot edl 制造新枚举，继续由本脚本守候。
"""
import subprocess
import sys
import time
from datetime import datetime

from serial.tools import list_ports

ADB = r'F:\root\platform-tools\adb.exe'
MTK_DIR = r'F:\root\mtkclient-2.1.4.1'
TARGETS = {(0x22D9, 0x0006), (0x0E8D, 0x0003), (0x22D9, 0x0003)}
DURATION = 600


def log(msg):
    print(f'[{datetime.now():%H:%M:%S}] {msg}', flush=True)


def port_hit():
    for p in list_ports.comports():
        if (p.vid, p.pid) in TARGETS:
            return p
    return None


def adb_online():
    try:
        out = subprocess.run([ADB, 'devices'], capture_output=True, text=True,
                             timeout=5).stdout
        return any(l.strip().endswith('device') and not l.startswith('List')
                   for l in out.splitlines())
    except Exception:
        return False


def main():
    log('设备当前离线；守候新枚举（只枚举端口，不打开串口，不干扰设备）')
    deadline = time.time() + DURATION
    sent_reboot = False
    tick = 0
    while time.time() < deadline:
        p = port_hit()
        if p:
            log(f'新端口出现: {p.device} {p.vid:04x}:{p.pid:04x} -> 启动 mtkclient crash')
            try:
                subprocess.run([sys.executable, '-u', 'mtk.py', 'crash', '--serialport'],
                               cwd=MTK_DIR, timeout=150)
            except subprocess.TimeoutExpired:
                log('mtkclient 超时结束')
            log('mtkclient 已退出；检查日志是否出现 0E8D:0003 / Device detected / Kamakiri')
            return 0
        tick += 1
        if not sent_reboot and tick % 10 == 0 and adb_online():
            log('adb 已回系统 -> 发送 adb reboot edl 制造新枚举窗口')
            sent_reboot = True
            try:
                subprocess.run([ADB, 'reboot', 'edl'], timeout=15)
            except Exception as e:
                log(f'reboot 异常: {e}')
        time.sleep(0.2)
    log('600s 超时，未捕获新端口')
    return 1


if __name__ == '__main__':
    sys.exit(main())
