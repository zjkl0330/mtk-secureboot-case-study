# -*- coding: utf-8 -*-
"""先判断设备是否还活着，必要时做 USB 端口复位再重连"""
import time
import usb.core, usb.util, usb.backend.libusb1 as lb

DLL = r'F:\root\mtkclient-2.1.4.1\mtkclient\Windows\libusb-1.0.dll'
VID, PID = 0x22D9, 0x2769


def find():
    b = lb.get_backend(find_library=lambda x: DLL)
    return usb.core.find(idVendor=VID, idProduct=PID, backend=b), b


def probe(tag=""):
    d, b = find()
    if d is None:
        print(f"[{tag}] 设备不存在")
        return None
    alive = False
    try:
        p = d.product
        s = d.serial_number
        print(f"[{tag}] 存活  product={p} sn={s}")
        alive = True
    except Exception as e:
        print(f"[{tag}] 描述符读取失败: {type(e).__name__}: {e}")
    return d if alive else d


def try_fastboot(d, cmds):
    try:
        usb.util.claim_interface(d, 0)
        print("  claim OK")
    except Exception as e:
        print("  claim ERR:", e)
    for c in cmds:
        try:
            d.write(0x01, c.encode(), timeout=2000)
            hdr = bytes(d.read(0x81, 64, timeout=2500))
            print(f"  {c:22s} -> {hdr[:32]!r}")
        except Exception as e:
            print(f"  {c:22s} -> ERR {type(e).__name__}: {e}")
        time.sleep(0.2)


if __name__ == "__main__":
    print("=== 第一步：探活 ===")
    d = probe("初始")

    if d is not None:
        print("\n=== 第二步：直接尝试 fastboot ===")
        try_fastboot(d, ["getvar:product"])

    print("\n=== 第三步：USB 端口复位 ===")
    try:
        d, _ = find()
        if d is not None:
            d.reset()
            print("reset() 已发出")
    except Exception as e:
        print("reset ERR:", type(e).__name__, e)

    # 等重新枚举
    for i in range(12):
        time.sleep(1)
        d, _ = find()
        if d is not None:
            try:
                p = d.product
                print(f"重枚举 {i+1}s: 回来了 product={p}")
                break
            except Exception:
                continue
    else:
        print("复位后 12 秒内未恢复")

    print("\n=== 第四步：复位后重试 fastboot ===")
    d, _ = find()
    if d is not None:
        try:
            d.set_configuration()
        except Exception:
            pass
        try_fastboot(d, ["getvar:product", "getvar:unlocked", "getvar:secure"])
