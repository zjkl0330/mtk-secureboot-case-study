# GhostLock 4.19 偏移提取 —— 接手结果

> 2026-11-07｜对象：OPPO K9 Pro `PEYM00` / MT6893 / Linux `4.19.191+`
> 输入：`boot/vmlinux.elf`（64978 符号，42,062,020 B）
> **⚠️ 本文为第一轮结果；2026-11-07 15:0x 已完成「从零补完」，见第十节。**
> **最终交付：`boot/target-PEYM00.h`（239 个 `#define`，49 项独立复核全 PASS）+
> `利用链-4.19-PEYM00.md`（端到端利用链）。本文第三、五、六、七、八节的部分结论已被第十节更正。**
> **17:0x 追加：设备实测确认 KASLR 已开启（slide ≠ 0）、KPTI 被强制打开；第十节 10.5/10.6 已更新。**

---

## 一、结论先行

1. **算出来了**：20 个函数符号偏移、6 个数据符号偏移、全套 `task_struct` / `rt_mutex_waiter` / `cred` / `file_operations` / `pipe_inode_info` 字段、6 个精确栈帧常量。绝大多数来自本机反汇编或镜像内函数指针表，不是照搬 K40。
2. **三处交接文档结论必须纠正**，其中一条直接动摇可行性判定（见第二节）。
3. **仍有硬阻塞**：`init_task` / `init_uts_ns` / `selinux_state` / `security_hook_heads` 等静态拿不到；`waiter_word` 与 `kernel_phys_load` 必须上机试错；手机当前未连 adb。

---

## 二、三处纠正（先看这个）

| # | 交接文档的说法 | 实测 | 后果 |
|---|---|---|---|
| 1 | `do_futex` 栈帧 **0x60**，「很浅、利于栈叠加」，与 K40 成功案例同类 | **0x210**（528 B） | ⚠️ **最严重**。`_frame.py` 只扫前 5 条指令，漏了第 7 条 `sub sp, sp, #0x1b0`。按真实栈几何算出 `waiter word ≈ +19`，落进 `stack_fds` 的内核清零区 → **pselect 栈叠加路径静态判定不可行**（完整推导见第九节） |
| 2 | A 类符号缺失是「本机符号名可能不同，需模糊匹配」 | **不是命名差异**：64978 个符号里 64976 个 `FUNC`、仅 2 个 `OBJECT` → 本内核 `CONFIG_KALLSYMS_ALL=n`，kallsyms 根本不含数据符号 | 模糊匹配无用。改用「引用点 ADRP/ADD + 函数指针表」恢复，已成功 6 项，其余需外部符号源 |
| 3 | 基址 `0xffffff8008080000` 与参考仓库不一致 | 基址**正确**（ELF program header `vaddr` 实测），且 K40 那份 4.19 适配用的**也是这个值**；不一致只针对 JoinChang 的 6.x 默认 `0xffffffc080000000` | 无需重算基址。旁证：`_stext = base+0x800`、Image header `text_offset=0x80000`、magic `ARMd` ✅ |

**另两个不能照搬的差异**：
- `task_struct` 后半段相对 K40 整齐 **−0x80**（10 个字段全部吻合）；但 `MM_OWNER_OFF` 是 **0x338**，K40 是 0x328（**+0x10**），属实测值，别套 −0x80。
- 本机 `pipe_inode_info` 是 **4.19 标准 ring 布局**（size 0x90、`bufs@0x80`、`user@0x88`），**不是** K40 的 legacy 布局。K40 的 `PIPE_NRBUFS/CURBUF/...` 系列字段在本机不存在。

---

## 三、A 类：符号偏移（`OFF = addr − 0xffffff8008080000`）

### 3.1 函数符号（`.symtab` 精确，[A]）

| 宏 | OFF | 本机符号 |
|---|---|---|
| `ASHMEM_IOCTL_OFF` | `0x00f0ccf4` | `ashmem_ioctl` |
| `ASHMEM_COMPAT_IOCTL_OFF` | `0x00f0d634` | `compat_ashmem_ioctl`（4.19 命名） |
| `ASHMEM_MMAP_OFF` / `OPEN` / `RELEASE` / `SHOW_FDINFO` | `0x00f0d680` / `d7ec` / `d86c` / `d980` | 同名 |
| `CONFIGFS_READ_ITER_OFF` | `0x002c6590` | `configfs_read_file` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | `0x002c6a78` | `configfs_write_bin_file` |
| `COPY_SPLICE_READ_OFF` | `0x002511fc` | `generic_file_splice_read`（4.19 替代） |
| `NOOP_LLSEEK_OFF` | `0x002125e4` | `noop_llseek` |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | `0x00057cd8` | 同名 |
| `CAP_CAPABLE_OFF` | `0x003f9114` | `cap_capable`（`cap_capable_active` 本内核无） |
| `DO_FUTEX_OFF` / `REMOVE_WAITER_OFF` / `RT_MUTEX_START_PROXY_LOCK_OFF` | `0x000ebed8` / `0x000ac0e8` / `0x000ac058` | 同名 |
| `COMMIT_CREDS_OFF` / `CORE_SYS_SELECT_OFF` / `SYS_PSELECT6_OFF` / `SYS_FUTEX_OFF` | `0x00065ce4` / `0x0022fc98` / `0x002308b8` / `0x000ef64c` | 同名 |

### 3.2 数据符号（引用点/指针表恢复，[A]）

| 宏 | OFF | 证据 |
|---|---|---|
| `INIT_CRED_OFF` | `0x02199890` | `prepare_kernel_cred`: `adrp x19,0xa219000; add x19,x19,#0x890`；该地址内容含 `0x3fffffffff ×3`（全 caps）与 `memcpy(...,0xa8)` |
| `ASHMEM_FOPS_OFF` | `0x01aae178` | 镜像内 fops 指针表：`llseek@+8`、`read_iter@+0x20`、`ioctl@+0x48`、`show_fdinfo@+0xd8`，与 4.19 槽位逐项吻合 |
| `ASHMEM_MISC_FOPS_OFF` | `0x02461948` | 全镜像**唯一**指向 `ashmem_fops` 的 8 字节槽 = `miscdevice.fops`（`ashmem_misc+0x10`） |
| `ANON_PIPE_BUF_OPS_OFF` | `0x013682c8` | `confirm/release/steal/get` 四连指针表 |
| `KMALLOC_CACHES_OFF` | `0x0217db40` | `__kmalloc` / `kmem_cache_alloc` / `__kmalloc_track_caller` 均以 `[base, idx*8]` 索引；BSS 全 0 符合运行时填充 |
| `PIPEFIFO_FOPS_OFF` | `0x01368310` | `no_llseek@+8`、`pipe_read@+0x20`、`pipe_write@+0x28`、`ioctl@+0x48`、`open@+0x68`、`release@+0x78` |

### 3.3 静态无法恢复（**本轮已全部推翻，见第十节**）

`INIT_TASK` / `INIT_UTS_NS` / `EMPTY_ZERO_PAGE` / `ROOT_TASK_GROUP` / `SELINUX_ENFORCING(selinux_state)` / `SECURITY_HOOK_HEADS` / `KPTR_RESTRICT` / `SYSTEM_UNBOUND_WQ` / `MM_STRUCT_SZ`。
`SELINUX_BLOB_SIZES` 在 4.19 不存在（`SELINUX_CRED_BLOB_OFF=0`）；`struct seccomp` 无 `filter_count`。

> **更正（第十节）**：`CONFIG_KALLSYMS_ALL=n` 只让 kallsyms/`.symtab` 丢数据符号，
> **模块用的 `__ksymtab` 仍然含数据符号**。本轮还原出 12649 条导出符号，
> 再配合调用点参数与 ctl_table，上述 9 项**全部静态恢复**，无一项留空。
> 下列候选地址经复核均为**误认**：`0x21e0bb8`（非 selinux_state）、
> `0x2176980`（`root_task_group` 内的一个字段，非基址）、
> `0x1f75ad8`（含 "TASKSTAT" 的其它数据）、`0x217db70`（实为 `system_wq`）。

---

## 四、B 类：结构体字段

| 结构 | 实测值（[A]，除非标注） | 关键证据 |
|---|---|---|
| `task_struct` | `real_cred 0x760`、`cred 0x768`、`comm 0x770`、`alloc_lock 0x830`、`pi_lock 0x834`、`pi_waiters 0x840`、`pi_blocked_on 0x858`、`real_parent 0x5c8`、`mm 0x508` | `commit_creds`（`add x9,current,#0x768`）、`__get_task_comm`（`add x1,tsk,#0x770`）、`sys_getppid`（`[current,#0x5c8]`）、`remove_waiter` |
| `task_struct` [B] | `pid 0x5b8`、`tgid 0x5bc`、`tasks 0x4b8`、`thread_group 0x668`、`atomic_flags 0x580`、`seccomp 0x810`、`pi_top_task 0x850` | K40 值 −0x80；规律已被 10 个实测字段验证 |
| `mm_struct` | `MM_OWNER_OFF 0x338` | `mm_update_next_owner`: `ldr x8,[mm,#0x338]; cmp x8,current` |
| `rt_mutex_waiter` | `tree_entry 0`、`pi_tree_entry 0x18`、`task 0x30`[B]、`lock 0x38`、`prio 0x40`、`deadline 0x48`、size `0x50`；**无** `wake_state`/`ww_ctx` | `remove_waiter`: `[waiter+0x38]` 与 lock 比较、`[waiter+0x18]!` 传 `rb_erase_cached`、`+0x40/+0x48` 参与 rb-tree prio 比较 |
| `cred` | `uid 4`、`securebits 0x24`、`caps 0x28`、`security 0x78`、size `0xa8` | `commit_creds` / `prepare_kernel_cred` 的 `str xzr,[cred,#0x78]`、`memcpy(...,0xa8)` |
| `file_operations` | `llseek 8`、`read 0x10`、`write 0x18`、`read_iter 0x20`、`write_iter 0x28`、`poll 0x40`、`ioctl 0x48`、`compat_ioctl 0x50`、`mmap 0x58`、`open 0x68`、`release 0x78`、`splice_read 0xc0`、`show_fdinfo 0xd8` | 两张独立 fops 指针表（ashmem / pipefifo）交叉验证 |
| `pipe_inode_info` | size `0x90`、`wait 0x28`、`readers 0x5c`/`writers 0x60`、`bufs 0x80`、`user 0x88`；[C] `head 0x38`/`tail 0x3c`/`max_usage 0x40`/`ring_size 0x44` | `alloc_pipe_info`: `kmem_cache_alloc_trace(...,0x90)`、`__init_waitqueue_head(pipe+0x28)`、`stur 0x100000001,[pipe+0x5c]` |
| `pipe_buffer` | size `0x28`、16 槽 → `kmalloc-1024`（index 10） | `alloc_pipe_info`: `x21*5*8` 计算数组字节数 |

> **未测得**：`TASK_PRIO_OFF` / `TASK_NORMAL_PRIO_OFF` / `TASK_SCHED_TASK_GROUP_OFF`。
> 原因：K40 的 `FAKE_TASK_*_OFF` 是 exploit 内部 spray buffer 布局，**不是** `task_struct` 字段，做 −0x80 平移会得到假值。已从头文件删除，需另找 sched 函数锚定。

---

## 五、C 类：栈叠加

| 函数 | 精确帧 | 备注 |
|---|---|---|
| `__arm64_sys_futex` | `0x70` | |
| `do_futex` | **`0x210`** | `stp ...,[sp,#-0x60]!` + `sub sp,sp,#0x1b0`；交接文档记 0x60 |
| `futex_requeue` | `0x140` | `do_futex` 尾部 `bl futex_requeue` 已验证 |
| `futex_wait_requeue_pi` | 符号不存在 | 被内联进 `do_futex` |
| `__arm64_sys_pselect6` | `0xc0` | |
| `core_sys_select` | `0x1c0` | `stack_fds` 起点 = `sp + 0x50`（`add x19,sp,#0x50`） |
| `do_select` | `0x380` | 交接文档未测 |

**`waiter_word`：二次复核已给出静态推算值 19**（不是运行时试错值，见第九节）。首次接手时判为「静态无法唯一确定」，是因为当时尚未定位 fwrpi 的 `rt_mutex_init_waiter` 落点；补做全镜像调用点反查后已可算。头文件里 `PSELECT_WAITER_WORD_SHIFT` 仍是占位 `0`，另加 `WAITER_WORD_STATIC_ESTIMATE 19` 记录推算值。K40 官方适配同样把 `PSELECT_WAITER_WORD_SHIFT` 标为 `[D] must be confirmed at runtime`。

**`kernel_phys_load = 0x40080000`（首选候选，[D]）**：`P0_PHYS_OFFSET 0x40000000` + Image header `text_offset 0x80000`，且与 boot header `kernel_addr=0x40080000` 一致。备用 `0x40000000` / `0x41000000`。

---

## 六、证据链与产出文件

| 文件 | 作用 |
|---|---|
| `boot/kelf.py` | 手工 ELF64 解析 + capstone 封装（无 binutils） |
| `boot/recon.py` / `_recon` 输出 | 基址验证、符号导出、`symbols.json` |
| `boot/probe.py` | 符号类型普查（发现 `CONFIG_KALLSYMS_ALL=n`） |
| `boot/derive.py` + `_dis_{waiter,task,pipe,globals,misc}.txt` | 5 组函数完整反汇编留档 |
| `boot/dataptr.py` / `_dataptr.txt` | 函数指针表搜索（fops / ops 定位） |
| `boot/gvars.py` / `_gvars.txt` | ADRP/ADD 数据流恢复全局地址 |
| `boot/frames.py` / `_frames.txt` | 全函数精确栈帧测量 |
| `boot/final_probe.py` / `_final.txt` | 候选数据地址内容辨认 |
| `boot/gen_target.py` | 统一计算所有 OFF 并生成头文件 |
| **`boot/offsets-PEYM00.h`** | **交付物** |

参考仓库（经 `gh.zjkl0330.dpdns.org` 取到）：`ccp-p/ghostlock-cve-2026-43499-4.19-k40` 的 `target.h` + `adaptation-4.19.patch`、`JoinChang/ghostlock-oneplus` README 的可行性判据表。

---

## 七、下一步（按序）

1. ~~先复核可行性~~ → **已完成，见第九节**：静态判定不可行。继续投编译/试错成本前，必须先推翻 9.4 的两条运行时前提。
2. 手机连上 adb 后，只读取 `/proc/kallsyms`（若 `kptr_restrict` 未拦）→ 一次补齐 3.3 的全局变量；同时读 `/proc/iomem` 的 `Kernel code` 定死 `kernel_phys_load`。
3. 从 sched / seccomp 相关函数补测 3 个未得的 `task_struct` 字段。
4. 若 9.4 翻盘：NDK 编译（云端 Actions 或本机分批，勿并行大构建）→ 上机用 `PSELECT_SHIFT` 试错 `waiter_word`。

---

## 八、手机状态

**全程只读，未做任何写入**：第一轮 `adb devices` 返回空（设备未连接）；
**第二轮设备已连接 `<DEVICE_SN>`**，只读采集了 `/proc/version`、
`/proc/config.gz`（走 `exec-out` 避免 CRLF 破坏 gzip）、`/proc/meminfo`、`getprop`、
`getenforce`、`id`。SELinux（`u:r:shell:s0`）拒绝 `/proc/kallsyms` 与 `/proc/iomem`。
BL 仍锁、数据完好、保修有效；未推送文件、未运行 exploit、未刷写。

---

## 九、可行性复核（二次，回答「能否提权」）

> 新增脚本：`boot/feasibility.py`（栈几何）、`boot/vulncheck.py`（全镜像 BL 调用点反查）；留档 `_feas.txt` / `_vuln.txt` / `_vuln2.txt`。

### 9.1 先更正上游判据的读法

第二节曾把主仓库表格读成「`do_futex` 帧 0xD0~0x140 是不可行区间」——**这是误读**。原文（`JoinChang/ghostlock-oneplus` README `Stack Layout Feasibility`）判的是：

- `stack_fds` = 256 B = 32 words；`NFDS=320` 下，用户可控 **words 0–14**（in/out/ex 各 5 words），**words 15–29 由内核清零**。
- waiter 的 `task` / `lock` 必须落在可控区：compact waiter（10 words）→ 起始 word **≤7**；nested waiter（14 words）→ **≤3**。
- "Not Feasible" 表里的 `frame 0xD0 → waiter word=-11`、`frame 0x140 → waiter word=-29` 是**两个具体机型的实测结果**，不是区间规则。
- 帧大小只通过改变 waiter 在栈上的深度**间接**影响 waiter word；所以「帧 0x210 更大所以不行」是推测，必须真算。

### 9.2 本机代码形态：四项前提都具备

| 检查 | 证据 | 结论 |
|---|---|---|
| `remove_waiter` 是否操作 `current` | `0x812c11c mrs x20, sp_el0` → `add x21,x20,#0x834`（`current->pi_lock`）→ `bl _raw_spin_lock` → `str xzr,[x20,#0x858]`（`current->pi_blocked_on=NULL`） | ✅ 正是 K40 描述的 bug 形态 |
| proxy-lock 路径存在 | 全镜像 BL 反查：`rt_mutex_start_proxy_lock @0x812c058` **唯一**调用点 `0x816eab4`，位于 `futex_requeue` 内 | ✅ |
| 栈上 `rt_mutex_waiter` | `do_futex` 尾跳冷块 `0x816cf94`：`sub x0,x29,#0xc8` → `bl rt_mutex_init_waiter`；随后 `add x3,sp,#0x70` → `bl futex_wait_setup` | ✅ fwrpi 实体在（仅无符号），waiter 落在栈上 |
| 调用链未被 PGO 破坏 | `0x816f794 bl do_futex`（`__arm64_sys_futex` 内），**没有**绕过 do_futex 直连 fwrpi | ✅ 上游判据 2 通过 |

> 主仓库称 CVE 影响 5.7~7.1，K40 称 4.19 无 backport 故同样受影响；按本机代码形态判断，属受影响一侧。**漏洞前提成立，否决来自利用路径而非漏洞本身。**

### 9.3 栈几何：算出 waiter word = 19

前提：同一内核线程、两个系统调用入口 SP 相同（记为 `S0`）。

| 路径 | 推导 | 绝对地址 |
|---|---|---|
| futex | `sys_futex −0x70` → `do_futex` 的 `stp x29,x30,[sp,#-0x60]!` 得 `x29=S0−0xD0` → `sub sp,#0x1b0` 得局部 `sp=S0−0x280`；waiter = `x29−0xc8` | **S0 − 0x198**（即局部 `sp+0xe8`） |
| pselect | `sys_pselect6 −0xc0` → `core_sys_select sub sp,#0x1c0` 得局部 `sp=S0−0x280`；`stack_fds = sp+0x50` | **S0 − 0x230** |

两条链路的局部 `sp` 恰好同为 `S0−0x280`（`0x70+0x60+0x1b0` = `0xc0+0x1c0` = `0x280`），于是：

```
waiter_word = (waiter − stack_fds) / 8 = (0x230 − 0x198) / 8 = 0x98 / 8 = 19
```

本机 `rt_mutex_waiter` size `0x50` = 10 words（compact），需占 **words 19–28**，全部落在 15–29 的内核清零区。`fd_set` 输入位图只能控制 words 0–14 → 无法伪造 `waiter->task` / `waiter->lock` → PI chain 的 rb-tree rebalance 写不到目标地址。

这个 19 与上游 "Not Feasible" 表里的 `PGO inlines do_futex → waiter word=20`（OnePlus 15 PLK110 / 6.12.69）几乎同值，属同一类失败。

### 9.4 结论

**按静态证据，GhostLock 的 pselect 栈叠加提权路径在这份 4.19.191 内核上不成立。**

另有一层现实阻塞：头文件里 9 个全局符号缺失、`PSELECT_WAITER_WORD_SHIFT` 仍是占位 `0`、`kernel_phys_load` 未定、手机未连 adb —— 目前**编译不出可运行的 exploit**，也无从做上机验证。

不能判死、须运行时证实的两点（静态给不出）：

1. **两路径入口 SP 相等的假设**（同线程、pt_regs 布局一致）。若运行时 `stack_fds` 实际更深，waiter word 会前移。
2. **静态 W 是否被运行时推翻**。9.3 的 `W=19` 建立在「两个系统调用入口 SP 相同」这一静态假设上；上游的 `PSELECT_SHIFT` 本来就是留给真机试错的量，4.19 的 `waiter_word` 官方也标 `[D] must be confirmed at runtime`。

只有这两点翻盘，或改用不走 pselect 覆盖的利用路径（如 K40 的 `LD_PRELOAD` + pipe physrw 首阶段——但该 PoC 自述首阶段 `UNVERIFIED`、未经真机验证），才值得再投编译与试错成本。

### 9.5 路线 3 复核：换「喷栈」方式能否救回来（含一处更正）

> 新增 `boot/route3.py` / `_route3.txt`。**更正 9.4 旧稿**：曾把 `PSELECT_SHIFT` 理解为「把整排格子平移」，这是错的。

**源码级事实**（`JoinChang/ghostlock-oneplus` 的 `src/core/fops.c`）：

```c
int shift = env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14);
int global_word = shift + waiter_word;     // waiter_word 是字段索引
/* pselect_put_global_word: set_idx = global_word / 5，只处理 case 0/1/2 */
```

- `PSELECT_ROUTE_NFDS=320` → 每个 fd_set 5 words，3 组（in/out/ex）共 **15 个可控 word（0–14）**；`set_idx>=3` 直接 `return 0` 并打印 `pselect cannot place`。
- `PSELECT_SHIFT` 是 **fd_set 内的 word 索引偏移**，**不改变内核栈布局**；且被 `env_int_range` 硬 clamp 到 **−14…14**。
- compact 布局 `task=6 / lock=7` → 需 `shift+7 ≤ 14` 即 **shift ≤ 7**（这正是上游 "max feasible waiter word = 7" 的由来）。本机需 `shift=19` → 越界，`task`/`lock` **根本不会被写进 fd_set**。

**换入口的实测**（`route3.py`）：设 `S0` 为系统调用入口 SP，

```
waiter    = S0 − F_futex − 0x128      (x29−0xc8，x29 = S0−F_futex−0x60)
stack_fds = S0 − F_sel   − 0x170      (core_sys_select 局部 sp+0x50)
W = (F_sel + 0x48 − F_futex)/8
```

| 喷栈入口 | 帧 | futex 入口 | 帧 | W | 判定 |
|---|---|---|---|---|---|
| pselect6 | 0xc0 | `__arm64_sys_futex` | 0x70 | **19** | ❌ |
| select | 0x80 | `__arm64_sys_futex` | 0x70 | **11** | ❌ 仍 > 7 |
| ppoll | 0xb0 | `__arm64_sys_futex` | 0x70 | ≥ 更差 | ❌ 走 `do_sys_poll`，非同原语 |

`do_futex` 全镜像 3 个调用点：`0x816f794`(`__arm64_sys_futex`, 0x70)、`0x816fbc8`(**`__arm64_compat_sys_futex`, 同样 0x70**)、`0x80b46d4`(在 `mm_release` 里，帧 0x20，是进程退出的 `futex_exit_release` 路径，**与用户态 fwrpi 无关**)。→ **不存在帧 ≥0x90 的可用 futex 入口**，「换 futex 入口把 waiter 推深」这条路被实测否掉。

**结论**：路线 3 在静态层面同样不成立。要救只有两条：① 上机实测 `W` 远小于 19（推翻 9.3 的 S0 假设）；② 改 exploit 源码换一个能往**更深栈位置**写可控数据的原语（当前 15 个可控 word 是硬上限，等于重写利用链，不是调参）。

---

## 十、从零补完（2026-11-07 第二轮）

> 交付：`boot/target-PEYM00.h`（239 宏）、`boot/offsets-PEYM00.json`、
> `boot/gen_target.py`（重写）、`boot/verify_target.py`（**49 PASS / 0 FAIL**）、
> `利用链-4.19-PEYM00.md`（端到端利用链）。
> 新增取证脚本：`ksymtab.py` / `globals2.py` / `pin_globals.py` / `pin2.py` / `pin3.py` / `fields2.py`，
> 留档 `_ksymtab.txt` / `_globals2.txt` / `_pin*.txt` / `_fields2.txt` / `_verify.txt`。

### 10.1 突破口：`__ksymtab` 而不是 kallsyms

设备 `/proc/config.gz` 实读确认 `CONFIG_KALLSYMS=y`、`CONFIG_KALLSYMS_ALL` **未设**、
`CONFIG_KALLSYMS_BASE_RELATIVE` 未设、`CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y`。
**kallsyms 丢数据符号，但 `CONFIG_MODULES=y` 要求所有 `EXPORT_SYMBOL` 在 `__ksymtab`
留下 `(s32 value_offset, s32 name_offset)`。** 解析 `vmlinux.bin` 得 12649 条，
以 `.symtab` 的 FUNC 名称做自校验：**11899/12649 = 94.1% 精确匹配**
（差异全是 `memcpy`/`__pi_memcpy` 这类别名）。这一条把 3.3 的「静态拿不到」整体推翻。

### 10.2 九项缺口全部补齐

| 宏 | 最终 OFF | 硬证据 |
|---|---|---|
| `INIT_TASK_OFF` | `0x218d6c0` | ksymtab；`comm="swapper"`、`pid=0`、`real_parent=self`、`real_cred=cred=0x…a219890` |
| `INIT_UTS_NS_OFF` | `0x218c828` | ksymtab；内含 `Linux/(none)/4.19.191+/#1 SMP PREEMPT/aarch64` |
| `EMPTY_ZERO_PAGE_OFF` | `0x254e000` | ksymtab；恰为 `.bss` 起点、页对齐（`__page_aligned_bss`） |
| `ROOT_TASK_GROUP_OFF` | `0x2554ac0` | `sched_init` 传给 `init_tg_cfs_entry` 的 `x0`；`init_task+0x340` 指回同址 |
| `SELINUX_STATE_OFF` | `0x2884050` | `sel_fill_super`: `stp x9,x19,[fsi,#0x70]`，`x9=0xa904050`；`avc_has_perm` 的 x0 同址 |
| `SELINUX_ENFORCING_OFF` | `0x2884051` | `sel_write_enforce`: `ldrb w22,[x21,#1]` → `disabled@0 / enforcing@1`（**K40 是 @0**） |
| `SECURITY_HOOK_HEADS_OFF` | `0x1f760e0` | `capability_hooks`(18) + `selinux_hooks`(187) 共 205 条，192 个 head，跨 0x618，偏移全为 8 的倍数 |
| `KPTR_RESTRICT_OFF` | `0x218c340` | `ctl_table @0x2196e30` 的 `.data` 槽，`maxlen=4`，handler `proc_dointvec_minmax_sysadmin` |
| `SYSTEM_UNBOUND_WQ_OFF` | `0x217db88` | ksymtab（旧表填的 `0x217db40` 是 cpumask 位图，错） |
| `MM_STRUCT_SIZEOF` | `0x398` | `proc_caches_init`: `kmem_cache_create_usercopy("mm_struct",0x398,…,useroff 0x160,size 0x170)` |

附带新增：`SYSTEM_WQ 0x217db70`、`SYSTEM_LONG_WQ 0x217db80`、
`KIMAGE_VADDR_OFF 0x132e000`（静态值 `0xffffff8008000000`）、
`KIMAGE_VOFFSET_OFF 0x1f75a88`、`MEMSTART_ADDR_OFF 0x1f75a78`、
`SLIDE_BOOTID_CTLTABLE_OFF 0x2214ac8`、`SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x2926ff4`。

### 10.3 三处旧值必须作废

| 宏 | 旧值 | 正确值 | 原因 |
|---|---|---|---|
| `KMALLOC_CACHES_OFF` | `0x217db40` | **`0x1f75bd0`** | 旧值来自 `__kmalloc` 的 `adrp x10,0xa1fd000; add #0xb40`，但后续 `ldr x9,[x10,w9,sxtw #3]; lsr; tbz` 是 **cpumask 位图测试**，不是 kmalloc 缓存数组；ksymtab 与 `create_kmalloc_caches` 双向确证真值 |
| `P0_PAGE_OFFSET` | `0xffffff8000000000` | **`0xffffffc000000000`** | 旧值是 `VA_START`（`= 0xffffffffffffffff − 2^39 + 1`）；`VA_BITS=39` 下 `PAGE_OFFSET = 0xffffffffffffffff − 2^38 + 1` |
| `MM_STRUCT_SZ` | 「待运行时扫描」 | 拆分：sizeof `0x398` / 扫描步长 `8` | 上游 K40 的 `MM_STRUCT_SZ 8` 是扫描步长，不是结构尺寸 |

另外 `P0_KERNEL_PHYS_LOAD 0x40080000` 从 `[D]` 升为 **[A]**：boot.img header v2
`kernel_addr @0x0c` 实测同值；`header_version=2`。

### 10.4 结构体字段补完

`task_prio()` 的 `ldr w8,[x0,#0x88]; sub w0,w8,#100` 钉死 `prio=0x88`；
`set_user_nice` 的 `str w8,[p,#0x8c]` 钉死 `static_prio=0x8c`；
`__sched_setscheduler` 给出 `rt_priority=0x94`、`sched_class=0x98`。
按 4.19 连续布局 `normal_prio=0x90`。
`init_task+0x340` 指向 `root_task_group` → `sched_task_group=0x340`。
**K40 的 `FAKE_TASK_PRIO_OFF` 等是 spray buffer 布局，做 −0x80 平移是错的**（第一轮已识别，本轮给出真值）。

### 10.5 新增的硬门禁（`/proc/config.gz` 首次实读）

`RANDOMIZE_BASE=y` + `RELOCATABLE=y` → **KASLR 开启**，所有 OFF 必须叠加 slide；
`ARM64_PAN/UAO/SW_TTBR0_PAN=y`；`STRICT_KERNEL_RWX=y`；`MODULE_SIG_FORCE=y`；
`STATIC_USERMODEHELPER=y`（固定 `/system_ext/bin/aee_core_forwarder`，modprobe-path 失效）；
`HARDENED_USERCOPY=y`；`SLAB_FREELIST_HARDENED/RANDOM` 未设（堆喷有利）；
`OPLUS_ROOT_CHECK/EXECVE_BLOCK/MOUNT_BLOCK/SECURE_GUARD=y`。
SELinux 对 `adb shell` 拒 `/proc/kallsyms` 与 `/proc/iomem` → KASLR slide 必须由
exploit 自身读原语产生；本轮曾给方案「用物理别名读 `kimage_voffset`」，但 17:0x 的运行时实测
证明 **KASLR 真的生效**（`kimage_vaddr != KIMAGE_VADDR`，见 `利用链-4.19-PEYM00.md` 阶段 2d），
于是该物理地址本身也被物理重定位，**这一方案不再自足**。

### 10.6 结论不变，但依据全换（17:0x 再更新）

**偏移表已补完且经 49 项独立复核（PASS 49 / FAIL 0）；利用链仍不可用，且断点已换位。**

- ~~断点在 `W=19 > 7`~~ → 16:5x **被阶段 2c 绕过**：`remove_waiter` 对伪造对象只读 `tree_entry`
  （`waiter+0x00..0x18`），multicast 的 `greqs` 覆盖到 `waiter+0x20` ⇒ **一次 8 字节任意写成立**。
- ~~两条链入口 SP 是否相等~~ → 16:1x **静态关闭**（Δ≡0，`boot/_spsame.txt`、`_spsame2.txt`）。
- **新断点：KASLR。** 17:0x 用 `adb bugreport` 取到设备内核日志，`last_kmsg*` 里
  `CPU features: kernel page table isolation forced ON by KASLR`，且本机 `unmap_kernel_at_el0`
  的分支条件确认为 `kimage_vaddr != KIMAGE_VADDR`（原因串 `0x9f045bc = "KASLR"`）
  ⇒ **slide ≠ 0 已定案，KPTI 同时被强制打开**。原「模板 seed 为 0，slide 可能是 0」的乐观分支作废。

所以现在：**有写原语，没有地址**。剩余门槛是 KASLR slide 泄露（纯用户态侧信道，本机未验证）。
完整利用链（阶段 0～7、门禁、失败信号、ring pipe 需重写、SELinux enforcing 在 +1）
见 `利用链-4.19-PEYM00.md`。
