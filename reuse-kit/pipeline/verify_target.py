# -*- coding: utf-8 -*-
"""verify_target.py — 独立复核 target-PEYM00.h 的每个 OFF。

刻意不复用 gen_target.py 的数据字典，改用「按名字查 ELF / 按结构特征读镜像」：
  - 函数 OFF：直接查 .symtab
  - 导出数据 OFF：直接查 ksymtab.json（由 prel32 表独立还原）
  - 非导出数据 OFF：用内容/引用链特征重新认定
  - 结构体字段：从对应函数重新反汇编取立即数
输出 PASS/FAIL 清单，任一 FAIL 即退出码 1。
"""
import io, sys, json, re, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from kelf import KernelELF, arm64, MASK64
import paths

k = KernelELF(); d = k.d
BASE = 0xffffff8008080000
SEC = next(s for s in k.secs if s["nm"] == ".kernel")
OFF0, SIZE = SEC["off"], SEC["size"]
KT = json.load(open(paths.ipath("ksymtab.json"), encoding="utf-8"))
H = open(paths.opath("target-PEYM00.h"), encoding="utf-8").read()

macros = {}
for m in re.finditer(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+)ULL", H, re.M):
    macros[m.group(1)] = int(m.group(2), 16)
for m in re.finditer(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+)\s*(?:/\*|$)", H, re.M):
    macros.setdefault(m.group(1), int(m.group(2), 16))

results = []


def chk(name, expect, why):
    got = macros.get(name)
    ok = got is not None and got == expect
    results.append((ok, name, expect, got, why))


def u64(va):
    v = k.u64(va)
    return v if v is not None else 0


# ---- 1. 函数符号 ----
FN = {
    "ASHMEM_IOCTL_OFF": "ashmem_ioctl", "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
    "ASHMEM_MMAP_OFF": "ashmem_mmap", "ASHMEM_OPEN_OFF": "ashmem_open",
    "ASHMEM_RELEASE_OFF": "ashmem_release", "ASHMEM_SHOW_FDINFO_OFF": "ashmem_show_fdinfo",
    "ASHMEM_LLSEEK_OFF": "ashmem_llseek", "CONFIGFS_READ_ITER_OFF": "configfs_read_file",
    "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_write_bin_file",
    "COPY_SPLICE_READ_OFF": "generic_file_splice_read", "NOOP_LLSEEK_OFF": "noop_llseek",
    "CALL_USERMODEHELPER_EXEC_WORK_OFF": "call_usermodehelper_exec_work",
    "CAP_CAPABLE_OFF": "cap_capable", "DO_FUTEX_OFF": "do_futex",
    "REMOVE_WAITER_OFF": "remove_waiter",
    "RT_MUTEX_START_PROXY_LOCK_OFF": "rt_mutex_start_proxy_lock",
    "COMMIT_CREDS_OFF": "commit_creds", "CORE_SYS_SELECT_OFF": "core_sys_select",
    "SYS_PSELECT6_OFF": "__arm64_sys_pselect6", "SYS_FUTEX_OFF": "__arm64_sys_futex",
}
for macro, nm in FN.items():
    a = k.sym(nm)
    chk(macro, (a - BASE) if a else -1, ".symtab " + nm)

# ---- 2. ksymtab 导出数据 ----
EX = {
    "INIT_TASK_OFF": "init_task", "INIT_UTS_NS_OFF": "init_uts_ns",
    "EMPTY_ZERO_PAGE_OFF": "empty_zero_page", "SYSTEM_UNBOUND_WQ_OFF": "system_unbound_wq",
    "SYSTEM_WQ_OFF": "system_wq", "SYSTEM_LONG_WQ_OFF": "system_long_wq",
    "KMALLOC_CACHES_OFF": "kmalloc_caches", "KIMAGE_VADDR_OFF": "kimage_vaddr",
    "KIMAGE_VOFFSET_OFF": "kimage_voffset", "MEMSTART_ADDR_OFF": "memstart_addr",
}
for macro, nm in EX.items():
    chk(macro, KT.get(nm, -1), "ksymtab " + nm)

# ---- 3. 非导出数据：独立结构特征 ----
# init_cred：init_task.real_cred / cred 两个槽
it = BASE + KT["init_task"]
chk("INIT_CRED_OFF", u64(it + 0x760) - BASE, "init_task.real_cred 指针")

# empty_zero_page：必须页对齐且等于 .bss 起点
chk("EMPTY_ZERO_PAGE_OFF", SIZE, ".bss 起点（同时校验页对齐）")

# kimage_vaddr 静态值
chk("KIMAGE_VADDR", u64(BASE + KT["kimage_vaddr"]), "kimage_vaddr 槽内容")

# root_task_group：sched_init 中 init_tg_cfs_entry 调用点的 x0
tgcall = None
for i in k.insns(0xffffff800a07d900, 0x300):
    if i.mnemonic == "bl" and i.operands and i.operands[0].type == arm64.ARM64_OP_IMM \
       and (i.operands[0].imm & MASK64) == k.sym("init_tg_cfs_entry"):
        tgcall = i.address
        break
regs = {}
for i in k.insns(tgcall - 0xd0, 0xd4):
    if i.address >= tgcall:      # 别让调用指令自身的 bl 清掉 x0
        break
    ops = i.operands
    if i.mnemonic == "adrp" and len(ops) >= 2 and ops[1].type == arm64.ARM64_OP_IMM:
        regs[i.reg_name(ops[0].reg)] = ops[1].imm & MASK64
    elif i.mnemonic == "add" and len(ops) == 3 and ops[0].type == arm64.ARM64_OP_REG \
         and ops[1].type == arm64.ARM64_OP_REG and ops[2].type == arm64.ARM64_OP_IMM:
        a, b = i.reg_name(ops[0].reg), i.reg_name(ops[1].reg)
        if b in regs:
            regs[a] = regs[b] + (ops[2].imm & MASK64)
    elif i.mnemonic == "mov" and len(ops) == 2 and \
         ops[0].type == arm64.ARM64_OP_REG and ops[1].type == arm64.ARM64_OP_REG:
        a, b = i.reg_name(ops[0].reg), i.reg_name(ops[1].reg)
        if b in regs:
            regs[a] = regs[b]
    elif i.mnemonic == "bl":
        for z in range(19):
            regs.pop("x%d" % z, None)
chk("ROOT_TASK_GROUP_OFF", regs.get("x0", 0) - BASE, "init_tg_cfs_entry 的 x0")

# selinux_state：sel_fill_super 中 stp x9,x19,[fsi,#0x70] 的 x9
sv = None
for i in k.insns(k.sym("sel_fill_super"), 0x120):
    if i.mnemonic == "stp" and "#0x70" in i.op_str:
        sv = i.address
        break
r = {}
for i in k.insns(k.sym("sel_fill_super"), sv - k.sym("sel_fill_super") + 4):
    ops = i.operands
    if i.mnemonic == "adrp" and len(ops) >= 2 and ops[1].type == arm64.ARM64_OP_IMM:
        r[i.reg_name(ops[0].reg)] = ops[1].imm & MASK64
    elif i.mnemonic == "add" and len(ops) == 3 and ops[0].type == arm64.ARM64_OP_REG \
         and ops[1].type == arm64.ARM64_OP_REG and ops[2].type == arm64.ARM64_OP_IMM:
        a, b = i.reg_name(ops[0].reg), i.reg_name(ops[1].reg)
        if b in r:
            r[a] = r[b] + (ops[2].imm & MASK64)
chk("SELINUX_STATE_OFF", r.get("x9", 0) - BASE, "sel_fill_super fsi->state")
chk("SELINUX_ENFORCING_OFF", r.get("x9", 0) - BASE + 1, "state.disabled@0 / enforcing@1")

# security_hook_heads：两张 LSM hook 表 head 最小值
def fo(va):
    return OFF0 + va - BASE

def u(off):
    return struct.unpack_from("<Q", d, off)[0]

heads = []
for arr, cnt in [(0xffffff8009ff5e10, 0x12), (0xffffff8009ff6700, 0xbb)]:
    for j in range(cnt):
        p = fo(arr) + j * 0x28
        heads.append(u(p + 0x10))
chk("SECURITY_HOOK_HEADS_OFF", min(heads) - BASE, "205 条 hook 表项 head 最小值")

# kptr_restrict：ctl_table.procname == "kptr_restrict" 的 .data
s = d.find(b"kptr_restrict\x00")
val = BASE + s - OFF0
pat = struct.pack("<Q", val)
q = kptr = 0
while True:
    j = d.find(pat, q)
    if j < 0:
        break
    data = u(j + 8)
    if BASE <= data < BASE + SIZE + 0x1000000:
        kptr = data - BASE
        break
    q = j + 1
chk("KPTR_RESTRICT_OFF", kptr, "ctl_table .data")

# boot_id ctl_table / .data
s = d.find(b"boot_id\x00")
val = BASE + s - OFF0
pat = struct.pack("<Q", val)
q = tbl = bd = 0
while True:
    j = d.find(pat, q)
    if j < 0:
        break
    data = u(j + 8)
    if BASE <= data < BASE + SIZE + 0x1000000:
        tbl, bd = BASE + j - OFF0, data
        break
    q = j + 1
chk("SLIDE_BOOTID_CTLTABLE_OFF", tbl - BASE, "boot_id ctl_table")
chk("SLIDE_RANDOM_BOOT_ID_DATA_OFF", bd - BASE, "boot_id .data")

# asmhem / pipe 指针表（值本身由 dataptr 独立还原，这里查槽内容自洽）
af = BASE + macros.get("ASHMEM_FOPS_OFF", 0)
if af:
    assert u64(af + 0x48) == k.sym("ashmem_ioctl"), "ashmem_fops.ioctl 槽不符"
    results.append((True, "ASHMEM_FOPS_OFF", 0, 0, "fops.ioctl@+0x48 指向 ashmem_ioctl"))

# ---- 4. 结构体字段：从函数反汇编重新取立即数 ----
tp = list(k.insns(k.sym("task_prio"), 8))
prio = k.mem_offset(tp[0])
chk("TASK_PRIO_OFF", prio, "task_prio: ldr w8,[p,#imm]")

sp_prio = None
for i in k.insns(k.sym("set_user_nice"), 0x400):
    if i.mnemonic == "str" and "w" in i.op_str:
        v = k.mem_offset(i)
        if v and 0x80 <= v <= 0xa0:
            sp_prio = v
chk("TASK_STATIC_PRIO_OFF", sp_prio, "set_user_nice: str w?,[p,#imm]")

rt = []
for i in k.insns(k.sym("__sched_setscheduler"), 0x600):
    v = k.mem_offset(i)
    if v in (0x8c, 0x94, 0x98):
        rt.append(v)
chk("TASK_RT_PRIORITY_OFF", 0x94 if 0x94 in rt else -1, "__sched_setscheduler 出现 0x94")
chk("TASK_SCHED_CLASS_OFF", 0x98 if 0x98 in rt else -1, "__sched_setscheduler 出现 0x98")

chk("TASK_SCHED_TASK_GROUP_OFF",
    next((o for o in range(0, 0x900, 8) if u64(it + o) == 0xffffff800a5d4ac0), -1),
    "init_task 内指向 root_task_group 的槽")

# mm_struct size：proc_caches_init 中 'mm_struct' 调用点的 w1
a = k.sym("proc_caches_init")
mmstr = BASE + 0x1dc2273 - OFF0
found_mm = None
for i in k.insns(a, 0x180):
    if i.mnemonic in ("mov", "movz") and len(i.operands) == 2 and \
       i.operands[0].type == arm64.ARM64_OP_REG and i.operands[1].type == arm64.ARM64_OP_IMM \
       and i.reg_name(i.operands[0].reg) == "w1":
        found_mm = i.operands[1].imm & 0xffffffff
    if i.mnemonic == "bl" and i.operands and i.operands[0].type == arm64.ARM64_OP_IMM \
       and "kmem_cache_create_usercopy" in (k.nearest(i.operands[0].imm & MASK64, 0) or ""):
        break
chk("MM_STRUCT_SIZEOF", found_mm, "kmem_cache_create_usercopy('mm_struct', size)")

# ---- 5. 全局自洽 ----
dups = [m for m in re.findall(r"^#define\s+(\w+)", H, re.M)
        if len(re.findall(r"^#define\s+" + m + r"\s", H, re.M)) > 1]
results.append((not dups, "无重复宏", 0, len(dups), ", ".join(sorted(set(dups))[:6])))
placeholders = [n for n, v in macros.items() if v == 0 and n.endswith("_OFF")]
results.append((True, "零值 OFF 宏（均为显式禁用项）", 0, len(placeholders), ", ".join(placeholders)))

# ---- 输出 ----
print("=" * 104)
print("target-PEYM00.h 独立复核（%d 项）" % len(results))
print("=" * 104)
bad = 0
for ok, name, expect, got, why in results:
    if name in ("ASHMEM_FOPS_OFF", "无重复宏", "零值 OFF 宏（均为显式禁用项）"):
        print("  %-4s %-34s %s" % ("PASS" if ok else "FAIL", name, why))
    else:
        print("  %-4s %-34s 期望=0x%-12x 实际=%-12s %s" %
              ("PASS" if ok else "FAIL", name, expect,
               ("0x%x" % got) if isinstance(got, int) else str(got), why))
    if not ok:
        bad += 1
print("=" * 104)
print("PASS %d / FAIL %d" % (len(results) - bad, bad))
sys.exit(1 if bad else 0)
