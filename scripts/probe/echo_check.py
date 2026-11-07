"""验证 COM6 是否为纯回环（echo loopback）。

真 MTK Preloader 握手：发 0xA0 -> 回 0x5F（取反）
纯回环：发任何字节 -> 原样返回
"""
import time
import serial

PORT = "COM6"
TESTS = [
    b"\x11\x22\x33\x44",
    b"\xde\xad\xbe\xef",
    b"\x00\xff\x55\xaa",
]


def main():
    try:
        s = serial.Serial(PORT, 115200, bytesize=8, parity="N", stopbits=1,
                          timeout=0.15, rtscts=False, dsrdtr=False)
    except Exception as e:
        print("OPEN FAILED:", e)
        return 2

    print("OPEN OK", PORT)
    try:
        s.reset_input_buffer()
        # 1) 标准握手字节，看是否取反
        s.write(b"\xa0")
        s.flush()
        time.sleep(0.05)
        r = s.read(8)
        print(f"send a0        -> recv {r.hex(' ') if r else '(nothing)'}"
              f"   {'TAKEN-INVERT 正常' if r[:1] == b'\x5f' else 'NOT inverted'}")

        # 2) 任意字节，看是否原样
        for t in TESTS:
            s.reset_input_buffer()
            s.write(t)
            s.flush()
            time.sleep(0.05)
            r = s.read(8)
            same = (r == t)
            print(f"send {t.hex(' '):12} -> recv {r.hex(' ') if r else '(nothing)':12} "
                  f"{'<== 原样回显(loopback)' if same else ''}")

        # 3) 发一个长串，看是否逐字节镜像
        s.reset_input_buffer()
        long = bytes(range(0x30, 0x40))
        s.write(long)
        s.flush()
        time.sleep(0.08)
        r = s.read(64)
        print(f"send 16B {long.hex(' ')}")
        print(f"recv {len(r)}B {r.hex(' ') if r else '(nothing)'}")
        print("VERDICT:", "PURE LOOPBACK" if r[:len(long)] == long else "device talks protocol")
    finally:
        s.close()
        print("CLOSE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
