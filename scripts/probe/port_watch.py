"""监测 COM6 的消失/重现，用来确认设备是否真的完成了一次断电重启。

用法：先启动本脚本，再操作手机。脚本会记录每次状态翻转的时间戳。
"""
import time
import serial.tools.list_ports as lp

PORT = "COM6"
DURATION = 420
OUT = r"F:\root\k9pro\Temp\port_watch.log"


def now():
    return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"


def present():
    try:
        return any(p.device == PORT for p in lp.comports())
    except Exception:
        return False


def log(msg):
    print(msg, flush=True)
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


open(OUT, "w", encoding="utf-8").close()
log(f"{now()} WATCH START (port={PORT}, {DURATION}s)")

state = present()
log(f"{now()} initial present={state}")
flips = 0
end = time.time() + DURATION
while time.time() < end:
    cur = present()
    if cur != state:
        flips += 1
        log(f"{now()} FLIP #{flips}: present {state} -> {cur}")
        state = cur
    time.sleep(0.15)

log(f"{now()} WATCH END flips={flips} final_present={state}")
