# -*- coding: utf-8 -*-
"""直接用 libusb 说 fastboot 协议，绕过 fastboot.exe 的驱动枚举问题"""
import sys, time, struct
import usb.core, usb.backend.libusb1 as lb

DLL = r'F:\root\mtkclient-2.1.4.1\mtkclient\Windows\libusb-1.0.dll'
VID, PID = 0x22D9, 0x2769
EP_OUT, EP_IN = 0x01, 0x81


def connect():
    b = lb.get_backend(find_library=lambda x: DLL)
    d = usb.core.find(idVendor=VID, idProduct=PID, backend=b)
    if d is None:
        raise SystemExit("设备未找到")
    try:
        d.set_configuration()
    except Exception:
        pass
    return d


def read_resp(d, timeout=3000):
    """fastboot 响应: 4字节状态 + 4字节hex长度 + 数据"""
    buf = b""
    hdr = bytes(d.read(EP_IN, 64, timeout=timeout))
    buf += hdr
    if len(hdr) < 8:
        # 可能被拆分，补读
        while len(buf) < 8:
            buf += bytes(d.read(EP_IN, 64, timeout=timeout))
    status = buf[:4].decode("ascii", "replace")
    try:
        length = int(buf[4:8], 16)
    except Exception:
        return status, buf[8:], buf
    data = b""
    while len(data) < length:
        data += bytes(d.read(EP_IN, min(512, length - len(data)), timeout=timeout))
    return status, data, buf[:8]


def cmd(d, text, timeout=3000):
    payload = text.encode() if isinstance(text, str) else text
    d.write(EP_OUT, payload, timeout=timeout)
    return read_resp(d, timeout)


def main():
    d = connect()
    print("已连接:", d.product, d.serial_number)
    tests = ["getvar:product", "getvar:version", "getvar:unlocked",
             "getvar:secure", "getvar:is-userspace", "getvar:slot-count"]
    for c in tests:
        try:
            st, data, hdr = cmd(d, c)
            print(f"{c:26s} -> {st}  {data!r}")
        except Exception as e:
            print(f"{c:26s} -> ERR {type(e).__name__}: {e}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
