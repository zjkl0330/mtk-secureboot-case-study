"""kelf.py — 轻量 ELF64 / ARM64 内核分析基础库（无 binutils 依赖）。

复用 vmlinux-to-elf 产出的 vmlinux.elf：
  - 手工解析 ELF header / section headers / .symtab
  - 虚拟地址 <-> 文件偏移映射
  - capstone 反汇编（detail=True）
  - 指令操作数立即数提取（含 ARM64 高位负数 & MASK 修正）
"""
import struct
import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, arm64
import paths

MASK64 = 0xFFFFFFFFFFFFFFFF
DEFAULT_ELF = paths.ipath("vmlinux.elf")


class KernelELF:
    def __init__(self, path=DEFAULT_ELF):
        self.path = path
        with open(path, "rb") as f:
            self.d = bytearray(f.read())
        d = self.d
        assert d[:4] == b"\x7fELF", "not an ELF"
        assert d[4] == 2, "need ELF64"
        self.e_entry = struct.unpack_from("<Q", d, 0x18)[0]
        self.e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
        self.e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        self.e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
        self.e_phnum = struct.unpack_from("<H", d, 0x38)[0]
        self.e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
        self.e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
        self.e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]

        # ---- program headers ----
        self.phdrs = []
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            (p_type, p_flags, p_offset, p_vaddr, p_paddr,
             p_filesz, p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", d, o)
            self.phdrs.append(dict(type=p_type, flags=p_flags, off=p_offset,
                                   vaddr=p_vaddr, paddr=p_paddr,
                                   filesz=p_filesz, memsz=p_memsz, align=p_align))

        # ---- section headers ----
        self.secs = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            (name, stype, flags, addr, off, size, link, info,
             align, entsize) = struct.unpack_from("<IIQQQQIIQQ", d, o)
            self.secs.append(dict(nameoff=name, type=stype, flags=flags,
                                  addr=addr, off=off, size=size, link=link,
                                  info=info, align=align, entsize=entsize))
        shstr = self.secs[self.e_shstrndx]["off"]

        def cstr(off):
            e = d.find(b"\x00", off)
            return d[off:e].decode("latin1")

        for s in self.secs:
            s["nm"] = cstr(shstr + s["nameoff"])
        self._cstr = cstr

        # ---- symbol tables（可能多个，全部合并）----
        self.by_name = {}       # name -> [addr,...]
        self.by_addr = {}       # addr -> name
        self.sym_records = []   # (addr, size, info, shndx, name)
        for s in self.secs:
            if s["type"] not in (2, 11) or not s["entsize"]:
                continue
            stroff = self.secs[s["link"]]["off"] if s["link"] < len(self.secs) else 0
            for i in range(s["size"] // s["entsize"]):
                o = s["off"] + i * s["entsize"]
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from("<IBBHQQ", d, o)
                if not st_value or not st_name:
                    continue
                nm = cstr(stroff + st_name)
                if not nm:
                    continue
                self.by_name.setdefault(nm, []).append(st_value)
                self.by_addr.setdefault(st_value, nm)
                self.sym_records.append((st_value, st_size, st_info, st_shndx, nm))

        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True

    # ---------- address translation ----------
    def v2o(self, v):
        for s in self.secs:
            if (s["flags"] & 0x2) and s["addr"] and s["size"] and \
               s["addr"] <= v < s["addr"] + s["size"]:
                o = s["off"] + (v - s["addr"])
                if o < len(self.d):
                    return o
        for p in self.phdrs:
            if p["type"] == 1 and p["vaddr"] and \
               p["vaddr"] <= v < p["vaddr"] + p["filesz"]:
                return p["off"] + (v - p["vaddr"])
        return None

    def read(self, v, n):
        o = self.v2o(v)
        return bytes(self.d[o:o + n]) if o is not None else b""

    def u64(self, v):
        b = self.read(v, 8)
        return struct.unpack("<Q", b)[0] if len(b) == 8 else None

    # ---------- symbols ----------
    def sym(self, name):
        a = self.by_name.get(name)
        return a[0] if a else None

    def find(self, pattern, limit=40):
        rx = re.compile(pattern, re.I)
        out = [(a, n) for n, lst in self.by_name.items() if rx.search(n) for a in lst]
        return sorted(out)[:limit]

    def nearest(self, v, tol=0x1000):
        if v in self.by_addr:
            return self.by_addr[v]
        best = None
        for a, n in self.by_addr.items():
            if a <= v <= a + tol and (best is None or a > best[0]):
                best = (a, n)
        if best is None:
            return None
        a, n = best
        return n if v == a else "%s+0x%x" % (n, v - a)

    # ---------- disassembly ----------
    def insns(self, v, size=0x200):
        o = self.v2o(v)
        if o is None:
            return []
        return list(self.md.disasm(bytes(self.d[o:o + size]), v))

    def func_end(self, v, maxsize=0x4000):
        """找到第一个 ret / b <尾跳>，粗略界定函数结束。"""
        for ins in self.insns(v, maxsize):
            if ins.mnemonic in ("ret", "br", "eret"):
                return ins.address + 4
        return v + maxsize

    def text(self, v, size=0x100, stop_at_ret=True):
        lines = []
        for ins in self.insns(v, size):
            lines.append("  0x%x: %-9s %s" % (ins.address, ins.mnemonic, ins.op_str))
            if stop_at_ret and ins.mnemonic in ("ret", "eret"):
                break
        return "\n".join(lines)

    # ---------- operand helpers ----------
    @staticmethod
    def imm_of(ins):
        """返回指令中第一个立即数（已 MASK 修正）。"""
        for op in ins.operands:
            if op.type == arm64.ARM64_OP_IMM:
                return op.imm & MASK64
        return None

    @staticmethod
    def mem_offset(ins):
        """返回 [xN, #imm] 形式内存操作数的立即数偏移；无则 None。"""
        for op in ins.operands:
            if op.type == arm64.ARM64_OP_MEM:
                return op.mem.disp
        return None

    @staticmethod
    def mem_detail(ins):
        for op in ins.operands:
            if op.type == arm64.ARM64_OP_MEM:
                return (op.mem.base, op.mem.index, op.mem.disp)
        return None


def imm_from_opstr(op_str):
    """从 '#0x1234' / '#-0x20' 里抠立即数，兼容 capstone 文本输出。"""
    m = re.search(r"#(-?0x[0-9a-f]+|#?-?\d+)", op_str)
    if not m:
        return None
    t = m.group(1).lstrip("#")
    try:
        return int(t, 0)
    except ValueError:
        return None
