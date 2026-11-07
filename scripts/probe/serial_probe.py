#!/usr/bin/env python3
"""COM6 Preloader 握手对照探测（只读，不写 flash、不改分区）。

目的：区分两种失败
  1) COM6 根本没上线
  2) COM6 上线了，但握手序列不匹配
对照实验：标准 startcmd (A0 0A 50 05) vs 先单独发 0xA0 唤醒再发 startcmd。
mtkclient 的 USB 模式 run_handshake() 对非 BROM 设备会先发一个 0xA0，
但串口模式 run_serial_handshake() 没有这一步；OPPO Preloader 22D9:0006 可能需要它。
"""
import sys
import time
from datetime import datetime

import serial

PORT = 'COM6'
DURATION = 240
START = b'\xa0\x0a\x50\x05'
EXPECT = bytes((~b) & 0xFF for b in START)


def log(msg):
    print(f'[{datetime.now().strftime("%H:%M:%S.%f")[:-3]}] {msg}', flush=True)


def handshake(s, prefix):
    try:
        s.reset_input_buffer()
    except Exception:
        pass
    if prefix:
        s.write(b'\xa0')
        s.flush()
        time.sleep(0.02)
    matched = 0
    rx = []
    for b in START:
        s.write(bytes([b]))
        s.flush()
        v = s.read(1)
        rx.append(v.hex() if v else '--')
        if len(v) == 1 and v[0] == (~b) & 0xFF:
            matched += 1
        else:
            matched = 0
    return matched, rx


def main():
    log(f'等待 {PORT} 上线（最长 {DURATION}s），期望回显 {EXPECT.hex(" ")}')
    end = time.time() + DURATION
    s = None
    while time.time() < end:
        try:
            s = serial.Serial(PORT, 115200, bytesize=8, parity='N', stopbits=1,
                              timeout=0.05, rtscts=False, dsrdtr=False)
            log(f'OPEN OK {PORT}')
            break
        except Exception:
            time.sleep(0.15)
    if s is None:
        log('超时：COM6 从未上线')
        return 2
    try:
        pre = s.read(128)
        log(f'预存字节: {len(pre)}  {pre[:48].hex(" ")}')
        for prefix in (False, True, False, True):
            n, rx = handshake(s, prefix)
            log(f'prefix_A0={str(prefix):5}  匹配={n}/4  回显={" ".join(rx)}')
            time.sleep(0.12)
        log('RESULT: 若 prefix_A0=True 匹配 4/4 而 False 为 0/4，则证实串口握手缺唤醒字节')
    finally:
        s.close()
        log('CLOSE OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
