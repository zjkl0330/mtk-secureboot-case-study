# -*- coding: utf-8 -*-
"""frames.py — 精确栈帧测量 + 栈叠加参数静态推导（修正 _frame.py 只看前 5 条的问题）。"""
import sys, io, re, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from kelf import KernelELF, arm64

k = KernelELF()
BASE = k.phdrs[0]["vaddr"]

FN = ["__arm64_sys_futex", "do_futex", "futex_requeue",
      "futex_wait_requeue_pi", "futex_wait",
      "__arm64_sys_pselect6", "__arm64_sys_select",
      "core_sys_select", "do_select", "__arm64_sys_ppoll",
      "__arm64_sys_futex_time32"]


def measure(name, size=0x2000):
    a = k.sym(name)
    if not a:
        return None
    insns = k.insns(a, size)
    delta = 0
    mind = 0
    steps = []
    for ins in insns:
        s = ins.op_str
        d = None
        if ins.mnemonic in ("stp", "str", "ldp", "ldr") and "sp" in s:
            # pre-index:  [sp, #-N]!
            m = re.search(r"\[sp, #-(0x[0-9a-f]+|\d+)\]!", s)
            if m:
                d = -int(m.group(1), 0)
            else:
                # post-index: [sp], #N
                m = re.search(r"\[sp\], #(0x[0-9a-f]+|\d+)", s)
                if m:
                    d = int(m.group(1), 0)
        elif ins.mnemonic in ("sub", "add") and re.match(r"sp, sp, #", s):
            m = re.search(r"#(0x[0-9a-f]+|\d+)", s)
            if m:
                d = -int(m.group(1), 0) if ins.mnemonic == "sub" else int(m.group(1), 0)
        if d is not None:
            delta += d
            mind = min(mind, delta)
            steps.append((ins.address, ins.mnemonic + " " + s, d, delta))
        if ins.mnemonic in ("ret", "eret"):
            break
    return a, -mind, steps


print("=" * 92)
print("一、精确栈帧（全函数扫描，取 SP 最深点；对比交接文档的只看前 5 条）")
print("=" * 92)
DOC = {"do_futex": 0x60, "core_sys_select": 0x1c0, "__arm64_sys_pselect6": 0xc0}
res = {}
for n in FN:
    r = measure(n)
    if not r:
        print("  %-28s ❌ 无符号" % n)
        continue
    a, f, steps = r
    res[n] = f
    doc = DOC.get(n)
    flag = ("  ⚠️ 交接文档记 0x%x → 差 0x%x" % (doc, f - doc)) if doc and f != doc else ""
    print("  %-28s 0x%-16x 帧=0x%-6x (%d B)%s" % (n, a, f, f, flag))
    for ia, txt, d, cum in steps[:6]:
        print("        0x%x  %-42s %+d  cum=%+d" % (ia, txt, d, cum))

print()
print("=" * 92)
print("二、do_futex 完整反汇编中的 rt_mutex / waiter 相关（size=0x1400）")
print("=" * 92)
a = k.sym("do_futex")
for ins in k.insns(a, 0x1400):
    s = ins.op_str
    ann = ""
    if ins.mnemonic in ("bl", "b") and ins.operands and \
       ins.operands[0].type == arm64.ARM64_OP_IMM:
        t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
        nm = k.nearest(t, 0)
        if nm and any(x in nm for x in ("mutex", "requeue", "wait", "futex", "proxy")):
            ann = "  -> " + nm
    if ann or ("sp, #0x" in s and any(x in s for x in ("x0", "x1", "x2", "x3"))):
        print("  0x%x: %-9s %-42s%s" % (ins.address, ins.mnemonic, s, ann))
    if ins.mnemonic in ("ret", "eret"):
        break

print()
print("=" * 92)
print("三、core_sys_select：stack_fds 定位（SELECT_STACK_ALLOC=256 → 32 words）")
print("=" * 92)
a = k.sym("core_sys_select")
for ins in k.insns(a, 0x400):
    s = ins.op_str
    if ins.mnemonic in ("add", "sub") and ("sp" in s or "x29" in s):
        print("  0x%x: %-9s %s" % (ins.address, ins.mnemonic, s))
    if ins.mnemonic == "bl" and ins.operands and \
       ins.operands[0].type == arm64.ARM64_OP_IMM:
        t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
        print("  0x%x: %-9s %-42s -> %s" % (ins.address, ins.mnemonic, s, k.nearest(t, 0)))
    if ins.mnemonic in ("ret", "eret"):
        break
