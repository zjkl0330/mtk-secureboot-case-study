# -*- coding: utf-8 -*-
"""热等待：设备一出现就立刻抢连，抓住未睡死的窗口
监听 22D9:2769(fastboot) / 0E8D:0003(BROM) / 22D9:0006(Preloader)
"""
import time, sys, datetime
import usb.core, usb.util, usb.backend.libusb1 as lb

DLL = r'F:\root\mtkclient-2.1.4.1\mtkclient\Windows\libusb-1.0.dll'
TARGETS = {
    (0x22D9, 0x2769): "OPPO-fastboot",
    (0x0E8D, 0x0003): "BROM",
    (0x22D9, 0x0006): "OPPO-Preloader",
    (0x0E8D, 0x2769): "MTK-2769",
}
LOGF = r"F:\root\k9pro\Temp\hotwait.log"


def log(msg):
    line = f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]} {msg}"
    print(line, flush=True)
    with open(LOGF, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def backend():
    return lb.get_backend(find_library=lambda x: DLL)


def probe_fastboot(d, tag):
    """对 fastboot 接口立刻发 getvar"""
    log(f"  [{tag}] 尝试 claim + getvar ...")
    try:
        usb.util.claim_interface(d, 0)
        log(f"  [{tag}] claim OK")
    except Exception as e:
        log(f"  [{tag}] claim FAIL {type(e).__name__}: {e}")
    for c in ["getvar:product", "getvar:unlocked", "getvar:secure", "getvar:is-userspace"]:
        try:
            d.write(0x01, c.encode(), timeout=1500)
            hdr = bytes(d.read(0x81, 64, timeout=1500))
            log(f"  [{tag}] {c:22s} -> {hdr[:64]!r}")
        except Exception as e:
            log(f"  [{tag}] {c:22s} -> ERR {type(e).__name__}: {e}")


def probe_brom(d, tag):
    """对 BROM 发握手字节 0xA0"""
    log(f"  [{tag}] 发送 BROM 握手 0xA0 ...")
    try:
        d.ctrl_transfer(0x80, 0x06, 0x0100, 0, 18, timeout=1000)
    except Exception:
        pass
    for attempt in range(3):
        try:
            d.write(0x01, b"\xa0", timeout=1500)
            r = bytes(d.read(0x81, 64, timeout=1500))
            log(f"  [{tag}] 握手响应 {r[:16]!r}")
            return
        except Exception as e:
            log(f"  [{tag}] 握手第{attempt+1}次失败 {type(e).__name__}: {e}")
            time.sleep(0.2)


def main():
    open(LOGF, "w", encoding="utf-8").close()
    b = backend()
    deadline = time.time() + 300
    seen = {}
    log("热等待启动，300 秒")
    while time.time() < deadline:
        try:
            devs = list(usb.core.find(find_all=True, backend=b))
        except Exception as e:
            log(f"枚举异常 {e}")
            time.sleep(0.5)
            continue
        for d in devs:
            key = (d.idVendor, d.idProduct)
            if key not in TARGETS:
                continue
            tag = TARGETS[key]
            n = seen.get(key, 0)
            seen[key] = n + 1
            if n == 0:
                log(f"发现 {tag} VID={hex(key[0])} PID={hex(key[1])}")
            if n < 6:          # 前几次出现都猛试
                if "fastboot" in tag or key[1] == 0x2769:
                    probe_fastboot(d, tag)
                elif key[1] == 0x0003:
                    probe_brom(d, tag)
                else:
                    log(f"  [{tag}] 仅记录（Preloader 串口模式）")
                try:
                    usb.util.dispose_resources(d)
                except Exception:
                    pass
        time.sleep(0.15)
    log("热等待结束")
    log(f"出现统计: {[(TARGETS[k], v) for k, v in seen.items()]}")


if __name__ == "__main__":
    main()
