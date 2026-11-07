# GhostLock 4.19 / PEYM00 —— 换模型接手卡

> 2026-11-07 16:07 生成｜用途：用户切换大模型后，新模型**不必重跑**整轮 4.19 静态分析即可接手。
> 本卡只写「结论 + 权威文件 + 已作废结论 + 红线」；推理与证据见 §2 的两份报告。
> **全程离线静态分析 + 设备只读采集；未向设备写入任何字节、未编译/运行 exploit、未解锁。**

---

## 0. 一句话状态

**偏移表已补完**（`target-PEYM00.h`，239 个 `#define`，独立复核 **PASS 49 / FAIL 0**）。
**利用链仍不可用，但瓶颈已换位**：`W=19 > 7` 被「tree_entry 钉子」绕过（阶段 2c：`remove_waiter`
对伪造对象只读 `+0..0x18`，multicast 的 `greqs` 盖到 `+0x20`）⇒ **有一次 8 字节任意写**；
而 **KASLR 已在运行时定案为开启（slide ≠ 0，KPTI 亦被强制打开）** ⇒ **没有可写的地址**。
现在唯一未解项是 slide 泄露，属研究级（详见 §5）。

---

## 1. 不要重做的 9 件事（内部任务 #1～#9 全部 completed）

| 已完成 | 结论 |
|---|---|
| ELF 基址验证 | `KIMAGE_TEXT_BASE = 0xffffff8008080000`（program header vaddr 实测） |
| A 类符号 | 20 个函数 OFF；`.symtab` 64978 符号中 64976 FUNC / 2 OBJECT → `KALLSYMS_ALL=n` |
| A 类数据符号 | **`__ksymtab` 突破口**还原 12649 条，原缺 9 项全部静态恢复 |
| B 类结构体 | `task_struct` / `cred` / `rt_mutex_waiter` / `fops` / `pipe_inode_info` / `pipe_buffer` |
| C 类栈叠加 | 6 个精确帧；`waiter_word = 19`；`PSELECT_SHIFT` 语义已更正 |
| 可行性复核 | 漏洞前提 4/4 成立，但 W=19 > 7；换 `select`/`ppoll`/futex 入口全部实测否掉 |
| 设备只读采集 | `<DEVICE_SN>`：`/proc/version`、`getprop`、`meminfo`、`/proc/config.gz` |
| 从零重算偏移表 | 消除所有占位 0 / `[B][D]` 猜值，239 宏 |
| 重建利用链 | 阶段 0～7，逐阶段门禁、依赖 OFF、预期效果、失败信号 |

---

## 2. 权威文件（按优先级读）

| 文件（相对 `F:\root\k9pro\`） | 地位 |
|---|---|
| `利用链-4.19-PEYM00.md` | **最新结论**。端到端链 + 门禁 + 失败信号 + 仍需上机三项 |
| `boot/target-PEYM00.h` | **唯一有效偏移表**，宏名对齐上游 K40 `target.h`，可直接作 `TARGET_CONFIG_H` |
| `boot/offsets-PEYM00.h` | 与上式**同内容副本**，仅为兼容旧引用，不要当成两份不同表 |
| `boot/offsets-PEYM00.json` | 机器可读 OFF 清单 |
| `boot/_verify.txt` | 49 项逐项复核结果（`PASS 49 / FAIL 0`） |
| `boot/verify_target.py` | 独立复核器，用另一套方法重算每个 OFF |
| `偏移提取-结果.md` | 第一轮证据报告；**第一/三/五/六/七/八节部分结论已被第十节更正** |
| `boot/gen_target.py` | 最终表生成器（FN/EXPORTED/MEASURED 三组来源） |
| `boot/ksymtab.py` + `ksymtab.json` | `__ksymtab` 还原器与结果 |

分析脚本留档：`kelf.py`（ELF 解析 + Capstone）、`frames.py`、`feasibility.py`、`route3.py`、
`vulncheck.py`、`globals2.py`、`pin2.py`、`pin3.py`、`fields2.py`、`dataptr.py`、`gvars.py`，
以及同名 `_*.txt` 输出。设备侧：`boot/device-config.gz` / `.txt`、`device-meminfo.txt`、`device-getprop.txt`。

---

## 3. 硬事实速查

```text
设备   OPPO K9 Pro PEYM00 / MT6893 / Android 13 / 4.19.191+ (2026-04-02 编译)
指纹   OPPO/PEYM00/OP5245:13/TP1A.220905.001/R.233ce9b-1:user/release-keys
状态   BL locked=1, getenforce=Enforcing, user build, MemTotal 11,785,152 kB

VA_BITS 39   VA_START        0xffffff8000000000   KIMAGE_VADDR 0xffffff8008000000
             PAGE_OFFSET     0xffffffc000000000   VMEMMAP_START 0xffffffbe00000000
             DIRECT_MAP_END  0xffffffc400000000
PHYS    P0_KERNEL_PHYS_LOAD 0x40080000   [A] boot header v2 kernel_addr @0x0c

栈帧   sys_futex 0x70 | do_futex 0x210 | futex_requeue 0x140
       sys_pselect6 0xc0 | core_sys_select 0x1c0 | do_select 0x380 | stack_fds sp+0x50
几何   waiter = S0-0x198, stack_fds = S0-0x230 → W = (0x230-0x198)/8 = 19
       可控 words 0..14（15..29 内核清零）；compact waiter 需 task@word6 / lock@word7 → W<=7

waiter compact 0x50:  tree_entry@0 pi_tree_entry@0x18 task@0x30 lock@0x38 prio@0x40 deadline@0x48
                     无 wake_state / ww_ctx
selinux_state 0x2884050，enforcing 在 +1（disabled@0）  ← K40 是 enforcing@0
pipe  4.19 ring：size 0x90, head@0x38, tail@0x3c, max_usage@0x40, ring_size@0x44, bufs@0x80, user@0x88

九项缺口真值（举要）  init_task 0x218d6c0 | init_cred 0x2199890 | kmalloc_caches 0x1f75bd0
       kimage_vaddr 0x132e000 | kimage_voffset 0x1f75a88 | memstart_addr 0x1f75a78
       security_hook_heads 0x1f760e0 | empty_zero_page 0x254e000 | system_wq 0x217db70
```

**`__ksymtab` 还原公式**（4.19 + `HAVE_ARCH_PREL32_RELOCATIONS`，`vmlinux.bin[p] → vaddr = BASE+p`）：

```python
a, b = i32(d,p)[0], i32(d,p+4)[0]
value_off = p + a
name_off  = p + 4 + b
```

字符串窗口必须放宽到 `0x1f00000..0x2200000`、`voff < N + 0x1000000`，否则漏 `.bss`
（`empty_zero_page` 等）。名称自校验 11899/12649 = 94.1%，差异是 `memcpy`/`__pi_memcpy` 类别名。

---

## 4. 已作废的旧结论（新模型最容易被带偏的地方）

| 旧说法 | 出处 | 更正 |
|---|---|---|
| `do_futex` 帧 `0x60`、可行性「已成立」 | `HANDOFF-偏移提取.md` 第 8/18/22 行 | 真值 **0x210**（漏了第二条 `sub sp,sp,#0x1b0`）；可行性判定**已翻转** |
| 「9 项全局符号静态拿不到」 | `偏移提取-结果.md` 3.3 节 | `__ksymtab` 已全部恢复，见该文件第十节 |
| 「手机未连 adb」 | `偏移提取-结果.md` 一/八节 | 第二轮已连 `<DEVICE_SN>` 并只读采集 |
| 「拿不到 boot.img」 | `README-继续.md` | 本地已有 `boot/OPPO_PEYM00_PEYM00_11_F.31-boot.img` |
| `KMALLOC_CACHES_OFF 0x217db40` | 第一版 `offsets-PEYM00.h` | 那是 `__kmalloc` 的 cpumask 位图；真值 `0x1f75bd0` |
| `P0_PAGE_OFFSET 0xffffff8000000000` | 第一版 `offsets-PEYM00.h` | 那是 `VA_START`；真值 `0xffffffc000000000` |
| `do_futex` 帧 0xD0~0x140 是「不可行区间」 | 上游 README 的误读 | 真判据是 **waiter word 是否落在可控 words 0..14**，帧大小只间接起作用 |
| `PSELECT_SHIFT` 是栈平移 | 早期理解 | 它是 **fd_set 内 word 索引偏移**，`env_int_range(−14,14)` 夹死，`pselect_put_global_word` 只收 global word 0..14；**不搬栈** |
| `TASK_PRIO` 等由 K40 `FAKE_TASK_*` 平移得来 | 第一版 `gen_target.py` | 那是 exploit spray buffer 布局，不是 `task_struct` 字段；已按本机反汇编实测 |

> 结论口径：**表补完 ≠ 链子通了**。不要因为 `49 PASS` 就往下投编译成本。

---

## 5. 已关闭的翻盘点 / 唯一未解项（设备 `<DEVICE_SN>`，只读）

1. ~~两路径入口 SP 是否真的相等~~ → **已静态关闭（Δ≡0，证据 `boot/_spsame.txt` / `_spsame2.txt`）**：
   `cpu_switch_to` `mov x9,sp` / `mov sp,x9` + `kernel_exit` `add sp,sp,#0x140`，
   同一 task 入口 sp 恒为 `stack_top-0x140`。`W=19` 是确定值。
2. ~~「模板 kaslr-seed 为 0 ⇒ slide 可能为 0」~~ → **已运行时关闭：KASLR 确实开着**（2026-11-07 17:0x）：
   `adb bugreport` 取到的 `FS/cache/recovery/last_kmsg*` 里有
   `CPU features: kernel page table isolation forced ON by KASLR`；
   本机 `unmap_kernel_at_el0`（`0xffffff8008098418`）的分支条件是
   `cmp kimage_vaddr, KIMAGE_VADDR` + `b.eq skip`，原因串 `0x9f045bc = "KASLR"`
   ⇒ 只有 `kimage_vaddr != KIMAGE_VADDR` 才会打这行。**slide ≠ 0，KPTI 同时被强制打开。**
3. `DIRECT_MAP_BASE` / `VMEMMAP_START`：**用户态观测不到**（整份 bugreport 里 linear map
   地址 `0xffffffc0…` 出现 0 次），且 `memstart_addr` 也随 KASLR 随机化 ⇒ 只能靠 exploit 自己的读原语。
4. **唯一未解项**：KASLR slide 泄露。方案 A（物理读 `kimage_voffset`）有前置循环，
   而且物理基址本身也被 KASLR 重定位；方案 B（纯用户态侧信道）本机未验证；方案 C（K40 `boot_id`）本机不存在。

```bash
# 已验证可读
adb shell cat /proc/version
adb exec-out cat /proc/config.gz > device-config.gz   # 必须 exec-out；shell 会把 \n 改 \r\n 毁掉 gzip
adb shell cat /proc/meminfo
adb shell getprop
adb shell cat /proc/modules            # 可读，但地址被 kptr_restrict 抹成 0
adb bugreport <dir>                    # 唯一能拿到内核日志的路（dumpstate 以 root 跑）
# 以下被 SELinux 拒（u:r:shell:s0），adbd 域与 adb pull 同样被拒，不要反复试：
adb shell cat /proc/kallsyms | /proc/kmsg | /proc/cmdline | /proc/iomem
adb shell cat /proc/device-tree/chosen/kaslr-seed     # 连 stat 都拒
adb root                                              # adbd cannot run as root in production builds
```

`RANDOMIZE_BASE/RELOCATABLE/RANDOMIZE_MODULE_REGION_FULL=y` → 所有静态 OFF 运行时都要叠 slide，
且镜像物理基址也不是 `0x40080000` 了。
`STATIC_USERMODEHELPER=y`（固定 `/system_ext/bin/aee_core_forwarder`）→ modprobe-path 技巧失效。
`MODULE_SIG_FORCE=y` + `OPLUS_ROOT_CHECK/EXECVE_BLOCK/MOUNT_BLOCK/SECURE_GUARD=y` → 提权后仍有加固。

---

## 6. 红线与协作纪律

- **只读**：不推送文件、不刷写、不解锁、不编译或运行 exploit；设备侧只用上表命令。
- **不猜值**：OFF 必须有 ELF / ksymtab / 反汇编 / 调用点参数证据；`[D]` 项显式标注，不用占位 0 冒充。
- **不套 K40 patch**：本机是 4.19 ring pipe、SELinux enforcing `+1`、`configfs` 落在 `.read`/`.write` 槽、
  ashmem 无 `/dev/ashmem` 前缀；Path A 的 pipe physrw 整段需按 ring 布局重写。
- **不自动 git commit**：`F:\root\k9pro` 非 git 仓库，本轮无任何 git 操作；产物均为本地文件。
- 报告必须带证据（反汇编地址、脚本输出、测试计数），不能只说「已切换 / 已完成」。
- 用户偏好：中文、结论先行、表格与编号清单、少回问、主动推进但不擅自扩大范围。

---

## 7. 复现顺序（`F:\root\k9pro\boot\`）

```bash
python ksymtab.py        # 先生成 ksymtab.json（gen_target / verify_target 都依赖它）
python gen_target.py     # 重写 target-PEYM00.h / offsets-PEYM00.h / .json
python verify_target.py  # 期望 PASS 49 / FAIL 0
python frames.py         # 栈帧
python feasibility.py    # W=19
python route3.py         # 换喷栈入口全否
```

依赖：Python 3 + Capstone；`kelf.py` 手工解析 ELF，不需要 binutils / readelf。

---

## 8. 如果继续，第一步做什么

- **优先**：只读实测两条系统调用链入口 SP 是否相等（决定 W 是否被推翻）。
- 若 W 被推翻 → 才进入 NDK 编译 / 上机试错；否则不要投编译成本。
- 若目标是**解 BL** 而非研究漏洞：GhostLock 只给临时 root，且此处静态不可行；
  项目另有 **OPPO 官方深度测试** 与 **PEYM00 专用强解** 两条更稳路线（见 `README-继续.md`）。
- 同一任务内继续追问会带上本会话上下文（官方文档：`重点是保持连续对话，而不是每次都重新开始`）；
  若**新建任务/会话**，把本卡作为附件或贴进首条消息即可。
