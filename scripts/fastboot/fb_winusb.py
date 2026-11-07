# -*- coding: utf-8 -*-
"""用 Windows 原生 WinUSB API 直接跟设备对话，绕开 libusb 的权限层"""
import ctypes
import ctypes.wintypes as wt
import time

GUID = "{F72FE0D4-CBCB-407D-8814-9ED673D0DD6B}"
INSTANCE = "<DEVICE_SN>"
PATHS = [
    rf"\\?\USB#VID_22D9&PID_2769#{INSTANCE}#{GUID}",
    rf"\\?\usb#vid_22d9&pid_2769#{INSTANCE.lower()}#{GUID.lower()}",
]

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
try:
    winusb = ctypes.WinDLL("winusb", use_last_error=True)
except OSError as e:
    raise SystemExit(f"winusb.dll 加载失败: {e}")

k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
                            wt.DWORD, wt.DWORD, wt.HANDLE]
k32.CloseHandle.argtypes = [wt.HANDLE]

winusb.WinUsb_Initialize.restype = wt.BOOL
winusb.WinUsb_Initialize.argtypes = [wt.HANDLE, ctypes.POINTER(wt.HANDLE)]
winusb.WinUsb_WritePipe.restype = wt.BOOL
winusb.WinUsb_WritePipe.argtypes = [wt.HANDLE, ctypes.c_ubyte, ctypes.c_char_p,
                                    wt.ULONG, ctypes.POINTER(wt.ULONG), wt.LPVOID]
winusb.WinUsb_ReadPipe.restype = wt.BOOL
winusb.WinUsb_ReadPipe.argtypes = [wt.HANDLE, ctypes.c_ubyte, ctypes.c_char_p,
                                   wt.ULONG, ctypes.POINTER(wt.ULONG), wt.LPVOID]


def open_device():
    for p in PATHS:
        err = 0
        h = k32.CreateFileW(p, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if h and h != INVALID_HANDLE_VALUE:
            print("CreateFile OK:", p)
            return h
        err = ctypes.get_last_error()
        print(f"CreateFile 失败 ({err}) : {p}")
    return None


def main():
    h = open_device()
    if not h:
        print("\n==> 无法获得设备句柄，设备确实被独占或已掉线")
        return
    wh = wt.HANDLE()
    if not winusb.WinUsb_Initialize(h, ctypes.byref(wh)):
        print("WinUsb_Initialize 失败:", ctypes.get_last_error())
        k32.CloseHandle(h)
        return
    print("WinUsb_Initialize OK\n")

    for c in [b"getvar:product", b"getvar:unlocked", b"getvar:secure",
              b"getvar:is-userspace", b"getvar:version-bootloader"]:
        written = wt.ULONG(0)
        ok = winusb.WinUsb_WritePipe(wh, 0x01, c, len(c),
                                     ctypes.byref(written), None)
        if not ok:
            print(f"{c.decode():28s} write FAIL err={ctypes.get_last_error()}")
            continue
        buf = ctypes.create_string_buffer(1024)
        got = wt.ULONG(0)
        ok = winusb.WinUsb_ReadPipe(wh, 0x81, buf, 1024, ctypes.byref(got), None)
        if not ok:
            print(f"{c.decode():28s} read FAIL err={ctypes.get_last_error()}")
            continue
        raw = buf.raw[:got.value]
        print(f"{c.decode():28s} -> {raw[:80]!r}")
        time.sleep(0.15)

    k32.CloseHandle(h)


if __name__ == "__main__":
    main()
