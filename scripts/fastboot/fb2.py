# -*- coding: utf-8 -*-
"""fastboot over libusb —— 带完整初始化(claim/clear_halt/flush)"""
import sys, time
import usb.core, usb.util, usb.backend.libusb1 as lb

DLL = r'F:\root\mtkclient-2.1.4.1\mtkclient\Windows\libusb-1.0.dll'
VID, PID = 0x22D9, 0x2769
EP_OUT, EP_IN = 0x01, 0x81


def connect():
    b = lb.get_backend(find_library=lambda x: DLL)
    d = usb.core.find(idVendor=VID, idProduct=PID, backend=b)
    if d is None:
        raise SystemExit("设备未找到")
    print("bcdUSB", hex(d.bcdUSB), "bcdDevice", hex(d.bcdDevice),
          "MaxPacketSize0", d.bMaxPacketSize0)
    try:
        d.set_configuration(1)
        print("set_configuration(1) OK")
    except Exception as e:
        print("set_configuration ERR:", e)
    try:
        usb.util.claim_interface(d, 0)
        print("claim_interface(0) OK")
    except Exception as e:
        print("claim ERR:", e)
    # 清掉可能残留的 stall 状态
    for ep in (EP_OUT, EP_IN):
        try:
            d.clear_halt(ep)
            print(f"clear_halt({hex(ep)}) OK")
        except Exception as e:
            print(f"clear_halt({hex(ep)}) ERR:", e)
    # 把 IN 端点上残留的包读干净
    try:
        while True:
            junk = d.read(EP_IN, 512, timeout=120)
            print("flush junk:", bytes(junk)[:64])
    except Exception:
        pass
    return d


def read_resp(d, timeout=3000):
    hdr = bytes(d.read(EP_IN, 64, timeout=timeout))
    while len(hdr) < 8:
        hdr += bytes(d.read(EP_IN, 64, timeout=timeout))
    status = hdr[:4].decode("ascii", "replace")
    try:
        length = int(hdr[4:8], 16)
    except Exception:
        return status, hdr[8:], hdr
    data = b""
    guard = 0
    while len(data) < length and guard < 64:
        data += bytes(d.read(EP_IN, min(512, length - len(data)), timeout=timeout))
        guard += 1
    return status, data, hdr


def cmd(d, text, timeout=3000):
    payload = text.encode() if isinstance(text, str) else text
    d.write(EP_OUT, payload, timeout=timeout)
    return read_resp(d, timeout)


def main():
    d = connect()
    print("已连接:", d.product, d.serial_number, "\n")
    for c in ["getvar:product", "getvar:version", "getvar:unlocked",
              "getvar:secure", "getvar:is-userspace", "getvar:current-slot",
              "getvar:serialno", "getvar:max-download-size"]:
        try:
            st, data, hdr = cmd(d, c)
            print(f"{c:28s} -> {st:6s} {data!r}")
        except Exception as e:
            print(f"{c:28s} -> ERR {type(e).__name__}: {e}")
            # 失败后尝试恢复端点
            for ep in (EP_OUT, EP_IN):
                try:
                    d.clear_halt(ep)
                except Exception:
                    pass
        time.sleep(0.15)


if __name__ == "__main__":
    main()
