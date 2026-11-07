# GhostLock 4.19 偏移提取 —— 交接文档

> 接手方任务：为 OPPO K9 Pro (PEYM00 / MT6893 / 内核 4.19.191+) 补齐 GhostLock (CVE-2026-43499) 的设备偏移表，使其可用于锁 BL 提权。
> 本机已完成：内核提取、符号还原、可行性判定、关键栈帧测量。**下一步是结构体偏移提取。**

---

## 一、结论先行：可行性已成立

| 检查项 | 实测结果 | 判定 |
|---|---|---|
| 内核版本 | `4.19.191+` | 与手机一致 |
| CVE 是否适用 | 4.19 无 EOL 回补 | ✅ 受影响 |
| `do_futex` 是否存在 | `0xffffff800816bed8` | ✅ **未被 PGO 内联** |
| `__arm64_sys_futex` 调用链 | `bl do_futex` | ✅ 走 do_futex，非直跳 |
| `remove_waiter`（漏洞函数） | `0xffffff800812c0e8` | ✅ |
| `rt_mutex_start_proxy_lock` | `0xffffff800812c058` | ✅ |
| `do_futex` 栈帧 | **0x60**（96B，很浅） | ✅ 利于栈叠加 |
| `core_sys_select` 栈帧 | **0x1c0** | stack_fds 所在 |
| `__arm64_sys_pselect6` 栈帧 | 0xc0 | |

**对比参考**：失败的 OPPO 6.1 机型 `do_futex` 帧是 0xD0~0x140（过大，waiter 落到 word 13+ 超出可控区）。本机 0x60，与 Redmi K40（4.19.157）成功案例同属"浅帧"。

---

## 二、已产出的文件

| 文件 | 说明 |
|---|---|
| `F:\root\k9pro\boot\OPPO_PEYM00_PEYM00_11_F.31-boot.img` | 原始 boot.img（32MB） |
| `F:\root\k9pro\boot\kernel.raw` | 提取的 gzip 压缩内核（17,421,687 B） |
| `F:\root\k9pro\boot\vmlinux.bin` | **解压后内核 Image（39,116,800 B）** |
| `F:\root\k9pro\boot\vmlinux.elf` | **已还原符号的 ELF（64978 个符号）** ← 主要工作对象 |
| `F:\root\k9pro\boot\_an.py` | 反汇编脚本示例（含 ELF 解析 + capstone） |
| `F:\root\k9pro\boot\_frame.py` | 栈帧测量脚本 |

### boot header 实测值

```
kernel_addr   = 0x40080000      ← 压缩内核加载地址
ramdisk_addr  = 0x51100000
tags_addr     = 0x47c80000
page_size     = 0x800
header_version= 2
os_version    = 0x18 → Android 13
cmdline       = bootopt=64S3,32N2,64N2 buildvariant=user
```

---

## 三、关键约束（务必先读）

### 1. 基址与参考仓库不一致

```c
// JoinChang 仓库 target.h 的默认值（5.10+/6.x 布局）
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL

// 本机 4.19 真实基址（vmlinux-to-elf 用首符号推断）
0xffffff8008080000        // PAGE_OFFSET 0xffffff8000000000 + 0x8000000
```

**差 0x4000000000000。** 所有 `_OFF` 常量必须基于 `0xffffff8008080000` 重新计算。

### 2. `STRUCT_OFFSETS_*` 宏没有 4.19

参考仓库只有 `STRUCT_OFFSETS_6_12 / 6_6 / 6_1 / 5_10`。**4.19 需从零推导。**

### 3. `kernel_phys_load` 是硬门槛

```c
/* Varies per SoC/board, not derivable from boot.img.
 * read from "Kernel code" in /proc/iomem on a rooted unit of same model.
 * Wrong value => every write lands in unrelated RAM: no crash, no effect. */
uint64_t kernel_phys_load;
```

- 官方要求同型号已 root 机器读 `/proc/iomem`
- 我们拿不到 → **只能试错**
- **好消息**：错值不崩不砖，只是无效。MTK 天玑平台候选值通常落在 `0x40080000` / `0x40000000` / `0x41000000` 一族
- 可先按 boot header 的 `kernel_addr = 0x40080000` 试

### 4. 环境限制

- 本机**无 MSVC / 无 binutils（nm/objdump/readelf）**，全部用 Python + capstone 手工解析
- `vmlinux-to-elf` 已装（`--no-deps` 绕过 minilzo 编译问题，另补了 peewee/hexdump/anytree）
- 入口：`/c/Users/Administrator/.workbuddy/binaries/python/versions/3.13.12/Scripts/vmlinux-to-elf.exe`
- 沙箱代理白名单：**Google 系全不可达**；GitHub raw 需走 `https://gh.zjkl0330.dpdns.org/<owner>/<repo>/raw/main/<path>`

---

## 四、待提取的偏移清单

### A. 全局符号偏移（相对 `KIMAGE_TEXT_BASE = 0xffffff8008080000`）

从 `vmlinux.elf` 的 `.symtab` 直接查地址后相减。**需要的符号**：

```
init_task
init_cred
init_uts_ns
empty_zero_page
root_task_group
selinux_enforcing          ← 本机符号名可能不同，需模糊匹配
kptr_restrict
selinux_blob_sizes         ← 4.19 可能不存在（参考 4.19 K40 适配：SELINUX_CRED_BLOB_OFF=0）
security_hook_heads
kmalloc_caches
anon_pipe_buf_ops
ashmem_misc                ← OPPO 是否有 ashmem 需确认
ashmem_fops
ashmem_ioctl / compat_ioctl / mmap / open / release / show_fdinfo
configfs_read_iter / configfs_bin_write_iter
copy_splice_read
noop_llseek
cap_capable_active
system_unbound_wq          ← UMH 路径用，可能为 0
call_usermodehelper_exec_work
```

### B. 结构体字段偏移（**最难的部分，需反汇编推导**）

`task_struct`（4.19 布局，全部需实测）：
```
task_prio / task_normal_prio / task_sched_task_group
task_pi_lock / task_pi_waiters / task_pi_top_task / task_pi_blocked_on
task_pid / task_tgid / task_real_parent / task_atomic_flags
task_real_cred / task_cred / task_comm / task_tasks / task_seccomp
mm_owner
```

**推导方法**：找已知访问该字段的函数反汇编。例如：
- `task_pi_blocked_on` → 反汇编 `remove_waiter` 或 `rt_mutex_start_proxy_lock`，看 `str x, [x0, #OFF]`
- `task_cred` → 反汇编 `commit_creds`，看 `ldr x, [x1, #OFF]`
- `task_comm` → 反汇编 `__get_task_comm` / `get_task_comm`

**其余结构体**：
```
rt_mutex_waiter   （tree_entry/pi_tree_entry/task/lock/wake_state/prio/deadline/ww_ctx）
                  （4.19 是否有 ww_ctx 需确认；waiter_compact 标志）
cred              （uid/securebits/caps/security）
pipe_inode_info   （head/tail/max_usage/ring_size/nr_accounted/readers/writers/files/tmp_page/bufs/user）
pipe_buffer       （4.19 是 16 槽 legacy 还是 32 槽？影响 kmalloc 落点）
file_operations   （4.19 无 fop_flags，slot 布局需实测）
configfs_buffer
struct page
```

### C. 栈叠加参数

```
waiter_word       ← waiter 落在 stack_fds 第几个 word（关键）
pselect_shift     ← pselect 与 select 帧差（参考值：帧差 16B = 2 words）
nfds              ← 参考用 320
```

**计算方法**：
- `do_futex` 帧 0x60，需定位 `rt_mutex_waiter` 局部变量在帧内偏移（反汇编 `futex_wait_requeue_pi` 逻辑，看它把 waiter 放在 SP+?）
- `core_sys_select` 帧 0x1c0，需定位 `stack_fds[]` 起始（`SELECT_STACK_ALLOC=256`）
- 两者相对 SP 的偏移差 / 8 = waiter_word

---

## 五、参考资源

| 资源 | 用途 |
|---|---|
| `https://github.com/JoinChang/ghostlock-oneplus` | 主仓库（多设备偏移表、extract_target.py、kallsyms 恢复流程） |
| `https://github.com/YuKongA/ghostlock-app` | 图形化版，含 MTK 物理地址处理、extractor、profile 模板 |
| `https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40` | **Redmi K40 的 4.19 适配**（最接近本机的参考，含 `adaptation-4.19.patch`） |
| `https://github.com/NebuSec/CyberMeowfia` | 原始研究（IonStack/CVE-2026-43499，Apache-2.0） |
| 内核源码 | `kernel/locking/rtmutex.c`（remove_waiter）、`kernel/futex.c`（futex_requeue / futex_wait_requeue_pi） |

### K40 那份 4.19 适配已解决的差异（可直接借用思路）

原文摘录：
- `configfs_read_file` / `configfs_write_bin_file` 在 4.19 里占 `.read` / `.write` 槽（不是 `.read_iter`/`.write_iter`）
- ashmem 名字前缀在 4.19 该内核不存在 → 前缀长度 0
- 4.19 只有 3 类 kmalloc cache（NORMAL/RECLAIM/DMA，无 per-memcg）
- legacy pipe 16 槽数组落在 `kmalloc-1024`
- `selinux_blob_sizes` 在 4.19 不存在 → 直接 `cred->security`（`SELINUX_CRED_BLOB_OFF=0`）
- `struct seccomp` 无 `filter_count`
- `ASHMEM_MISC_FOPS = miscdevice.fops` 槽（`ashmem_misc + 0x10`）

**注意**：K40 是 Qualcomm 4.19.157，我们是 MTK 4.19.191。**SoC 不同，栈布局和部分偏移不能直接照搬**，但结构体布局（task_struct/cred/pipe）大概率同源。

---

## 六、工作步骤建议

```
1. 从 vmlinux.elf 导出全部符号 → 与需要的清单比对，得到 A 类偏移
2. 反汇编关键函数，推导 B 类结构体字段
   - remove_waiter / rt_mutex_start_proxy_lock → task_pi_*
   - commit_creds → task_cred / task_real_cred
   - futex_wait_requeue_pi 相关 → rt_mutex_waiter 布局
3. 计算 C 类栈叠加参数（waiter_word / pselect_shift）
4. 套 JoinChang 的 kernel_offsets 结构生成设备条目
5. 用 NDK 编译（需另外装 Android NDK r27c）
6. 试错 kernel_phys_load
7. 上机测试（adb push preload.so → LD_PRELOAD 跑）
```

---

## 七、陷阱提醒

1. **不要用 `0xffffffc080000000`** —— 那是 5.10+ 基址，套上去全部错位
2. **`waiter_word` 算错 = 完全无效**，不是崩溃。会很难 debug（参考仓库原话："very hard to debug"）
3. **VM 环境无 binutils**，用 Python 解析；capstone 要 `md.detail = True` 才能拿 operands
4. **ARM64 内核地址高位置 1**，capstone 返回的 `imm` 是负数，要 `& 0xFFFFFFFFFFFFFFFF`
5. 本机 `vmlinux-to-elf` 的基址是**启发式猜的**（`ffffff8008080000`），可用 `.symtab` 里任一符号的 vaddr 反验
6. **手机全程未被修改**：BL 仍锁、数据完好、保修有效。上手测试前务必确认这点

---

## 八、手机当前状态

```
BL: 锁定（flash.locked=1, verifiedbootstate=green）
系统: PEYM00_13.1.0.254(CN01) / Android 13 / 安全补丁 2026-01-01
adb: 可用（已授权）
OEM 解锁开关: 已开启（UI 层 checked=true）
Preloader 驱动: 已被 Zadig 换成 WinUSB（oem6.inf），COM5 不再出现
mtkclient 路线: 已判定走不通（OPPO Preloader 不响应 BROM 握手）
```
