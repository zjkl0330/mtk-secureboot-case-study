"""ksymtab.py — 从 vmlinux.bin 静态还原内核 __ksymtab / __ksymtab_gpl。

原理：CONFIG_KALLSYMS_ALL=n 让 /proc/kallsyms 和 .symtab 丢失全部数据符号，
但 CONFIG_MODULES=y 要求所有 EXPORT_SYMBOL(*) 的符号（含数据）在 __ksymtab
里留下 (value_offset, name_offset) 条目。本内核
CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y，故 4.19 的 struct kernel_symbol 为：

    struct kernel_symbol { s32 value_offset; s32 name_offset; };
    value = (unsigned long)&sym->value_offset + value_offset;
    name  = (const char *)&sym->name_offset  + name_offset;

vmlinux.bin[p] 对应 vaddr = BASE + p（.kernel 段 addr == BASE）。
因此在同一文件坐标下：value_off = p + a, name_off = (p+4) + b。

自校验：解出的 name 为函数时，其 value 应命中 .symtab 中同名 FUNC 地址。
"""
import struct
import sys
import paths
from kelf import KernelELF

BASE = 0xffffff8008080000
BIN = paths.ipath("vmlinux.bin")

d = open(BIN, "rb").read()
N = len(d)
k = KernelELF()

# ---- 1) 构建 __ksymtab_strings 合法字符串起点集合 ----
# 字符串区大致范围：从已知 "init_uts_ns"(0x1fa3f45) 到 "kmalloc_caches"(0x1faabc9)
STR_LO, STR_HI = 0x1f00000, 0x2200000
VALID = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
strs = {}
i = STR_LO
while i < min(STR_HI, N):
    j = i
    while j < N and d[j] in VALID:
        j += 1
    if j > i and j < N and d[j] == 0 and 2 <= j - i <= 96:
        strs[i] = d[i:j].decode("ascii")
        i = j + 1
    else:
        i += 1
print("[1] __ksymtab_strings 候选字符串: %d 个，范围 0x%x..0x%x" %
      (len(strs), min(strs) if strs else 0, max(strs) if strs else 0))

# ---- 2) 全镜像扫描 prel32 条目 ----
i32 = struct.Struct("<i").unpack_from
hits = []
for p in range(0, N - 8, 4):
    b = i32(d, p + 4)[0]
    noff = p + 4 + b
    if noff not in strs:
        continue
    a = i32(d, p)[0]
    voff = p + a
    # .kernel 段占 [0, N)，.bss 自 BASE+N 起，大小 0x1000000（NOBITS，不在文件内）
    if not (0 <= voff < N + 0x1000000):
        continue
    va = BASE + voff
    hits.append((strs[noff], va, voff, p, a, b))

print("[2] prel32 条目命中: %d 个" % len(hits))
if not hits:
    print("    !! prel32 未命中，需改试 8+8 绝对格式")
    sys.exit(0)

# ---- 3) 自校验：函数名应与 .symtab 地址吻合 ----
exact = 0
mismatch = []
for name, va, voff, p, a, b in hits:
    got = k.by_addr.get(va)
    if got == name:
        exact += 1
    elif got is not None and len(mismatch) < 8:
        mismatch.append((name, got, hex(va)))
print("[3] 自校验：name==symtab[value] 精确匹配 %d/%d (%.1f%%)" %
      (exact, len(hits), 100.0 * exact / len(hits)))
for m in mismatch:
    print("    差异样例 name=%s symtab=%s value=%s" % m)
if exact < len(hits) * 0.5:
    print("    !! 匹配率过低，格式或坐标有误，结果不可用")
    sys.exit(1)

# ---- 4) 目标符号 ----
TARGETS = [
    "init_task", "init_uts_ns", "init_cred", "empty_zero_page",
    "root_task_group", "system_unbound_wq", "system_wq", "system_long_wq",
    "kmalloc_caches", "selinux_state", "selinux_enforcing",
    "security_hook_heads", "kptr_restrict", "mm_struct", "ashmem_fops",
    "anon_pipe_buf_ops", "pipefifo_fops", "init_fs", "init_files",
    "init_mm", "init_signals", "init_sighand", "init_thread_union",
    "panic_on_oops", "randomize_va_space", "mmap_min_addr",
]
print("\n[4] 目标符号（__ksymtab 还原）")
print("    %-28s %-20s %-14s %s" % ("NAME", "ADDR", "OFF", "SYMTAB-CHECK"))
found = {}
for t in TARGETS:
    rows = [h for h in hits if h[0] == t]
    if not rows:
        print("    %-28s %s" % (t, "-- 未在 __ksymtab 中导出 --"))
        continue
    for name, va, voff, p, a, b in rows[:2]:
        chk = k.by_addr.get(va) or "-"
        print("    %-28s 0x%-18x 0x%-12x %s" % (name, va, va - BASE, chk))
        found[name] = va - BASE

# ---- 5) 所有 [A] 数据符号（value 不在 .symtab 中，或 symtab 标为 OBJECT） ----
print("\n[5] __ksymtab 中非 FUNC 符号（数据，前 80 个）")
seen = set()
cnt = 0
for name, va, voff, p, a, b in sorted(hits, key=lambda x: x[1]):
    if name in seen:
        continue
    seen.add(name)
    rec = next((r for r in k.sym_records if r[0] == va), None)
    if rec and (rec[2] & 0xf) == 2:   # STT_FUNC
        continue
    print("    %-34s 0x%-16x OFF=0x%-12x symtab=%s" %
          (name, va, va - BASE, k.by_addr.get(va) or "-"))
    cnt += 1
    if cnt >= 80:
        break

# ---- 6) 落盘完整表供后续脚本使用 ----
import json
with open(paths.ipath("ksymtab.json"), "w", encoding="utf-8") as f:
    json.dump({name: va - BASE for name, va, *_ in hits}, f, indent=1, sort_keys=True)
print("\n[6] 已写出 ksymtab.json（%d 条）" % len(hits))
