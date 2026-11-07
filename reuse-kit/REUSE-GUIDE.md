# 复用操作手册：当这个 4.19 内核出现新公开漏洞时怎么办

> 配套 `reuse-kit/`。本文件是「捡起来就能用」的实际步骤，不是分析论文。
> 阅读对象：将来要基于本机 4.19 内核写新 exploit 的分析者（或未来的你自己）。

---

## 0. 这个包给你什么

- **锁定的偏移表** `offsets/target-PEYM00.h`：239 个 `#define`，其中 49 项被 `verify_target.py` 用另一套方法独立复核 PASS。
- **链路方法论** `chain/利用链-4.19-PEYM00.md`：端到端 0–7 阶段，含三种 write route 的精确量法、KASLR 在设备上的定案过程。
- **可重跑管线** `pipeline/`：`kelf`（ELF 解析）→ `ksymtab`（符号恢复）→ `frames`（栈帧测量）→ `gen_target`（生成偏移表）→ `verify`（独立复核）。

适用对象：OPPO K9 Pro `PEYM00` / MT6893 / 内核 `4.19.191+` / Android 13；同内核的新 OTA 构建，或任何基于同份 4.19 源码的接近版本。

---

## 1. 什么情况下该用这个包

| 情形 | 动作 |
|---|---|
| 出现针对 4.19 futex / LSM / pipe / fileops 类的新 CVE，需要本机偏移来写 exploit | 直接用本表；若内核版本/构建变了，跑闭环重算 |
| OPPO 推送新 OTA，内核版本号或构建时间戳变了 | 重跑 `gen_target` + `verify`；KASLR slide 每次都变，但**静态 OFF 通常稳定**，变了会立刻被断言/复核抓出 |
| 完全换了一台不同机型/不同内核源码 | 本包是模板：改 `gen_target` 的 `MEASURED` 字典与 `verify` 内联的绝对地址，其余框架可借鉴 |

---

## 2. 复用闭环（5 步）

### Step 1 · 取内核镜像
从新 `boot.img` 解出内核 `Image` → 用 [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) 产 `vmlinux.elf`；`gzip -d` 出 `vmlinux.bin`。
放到 `reuse-kit/inputs/`（或设环境变量 `K9_INPUT_DIR` 指向含这些文件的目录，或放回 `../boot`）。

### Step 2 · 取设备指纹（设备只读，不写入）
```
adb exec-out 'gzip -c /proc/config.gz' | gzip -d > device-config.txt
adb shell getprop > device-getprop.txt
adb shell cat /proc/meminfo > device-meminfo.txt
```
> 注意：必须用 `exec-out` 二进制直通，别用 `cat /proc/config.gz`（gzip 流会被 shell 破坏）。

### Step 3 · 还原符号（仅 `CONFIG_KALLSYMS_ALL=n` 时需要）
```
cd reuse-kit/pipeline
python ksymtab.py      # 扫描 vmlinux.bin，产 ksymtab.json（12649 条 prel32 导出符号）
```
本机 `KALLSYMS_ALL` 未设，所以数据符号只能静态挖 `__ksymtab`。若新内核 `=y`，`.symtab` 自带数据符号，可跳过此步（但 `gen_target` 仍读 `ksymtab.json`，届时让 `ksymtab.py` 走 `=y` 分支或直接用 ELF 符号导出）。

### Step 4 · 重算偏移表
```
python gen_target.py   # 覆盖 offsets/target-PEYM00.h / offsets-PEYM00.json
```
内含断言：基址 `0xffffff8008080000`、`KIMAGE_VADDR`、`VA_BITS`、`P0_KERNEL_PHYS_LOAD=0x40080000`、boot header v2 任一不符，**直接 assert 失败**（说明镜像不是本内核，别硬用）。

### Step 5 · 独立复核（必须绿灯）
```
python verify_target.py
# 期望输出：PASS 49 / FAIL 0 ，退出码 0
```
`verify` 刻意不复用 `gen_target` 的数据字典，改用「按名查 ELF / 按结构特征读镜像 / 从函数反汇编取立即数」另一套方法交叉验证。任一 FAIL 即说明偏移有诈，先查再上。

---

## 3. 新漏洞要改什么（框架不动，原语要换）

**已经锁死、不用动的部分：**
- 地址空间与 `CFG_*` 编译门禁（`offsets/target-PEYM00.h` 顶部）。
- 结构体字段：`task_struct` / `cred` / `pipe_inode_info` / `file_operations` / `rt_mutex_waiter` / `struct page`。
- 关键全局：`init_task` / `init_cred` / `init_uts_ns` / `selinux_state` / `security_hook_heads` / `kmalloc_caches` / `ashmem_fops` / `ashmem_misc.fops`。
- cred 升级骨架：`physrw → patch ashmem_misc.fops → 任意读写 → commit_creds(init_cred)`（本链路阶段 5/6/7 已验证可行）。

**必须按新 CVE 重做的三件事：**
1. **注入/写原语**落在哪个结构体、哪个字段、可控字节范围（参考 `chain/` 阶段 2 对 `select_stack` / `tcp_zerocopy` / `multicast_waiter` 三种 route 的精确量法；本机结论：multicast 的 `greqs` 覆盖到 `waiter+0x20`，`remove_waiter` 只读 `tree_entry(+0..0x18)`，可打一次 8 字节任意写钉子，但**地址未知**）。
2. **读原语怎么拿 KASLR slide**：本机定案 `slide≠0` 且 `kallsyms` 被 SELinux 挡（`u:r:shell:s0` 读不到），只能靠**物理读 `kimage_voffset`**（需先有任意读）或 `boot_id` `/proc` 泄露；`kernelsnitch` 给的是 `mm_struct`（linear map）**推不出 slide**（见 `../评估-kernelsnitch.md`）。
3. 把新原语接入上面的 cred 升级骨架，替换掉 GhostLock 的 futex UAF 部分。

---

## 4. 已经替你踩过的坑（别再踩）

- `P0_PAGE_OFFSET` 旧表写成 `0xffffff8000000000`，那是 `VA_START` 不是 `PAGE_OFFSET`；正确值是 `0xffffffc000000000`（`VA_BITS=39` 公式）。
- pipe **不是** K40 的 legacy 布局，是 4.19 标准 RING（`size 0x90`，`head@0x38`/`tail@0x3c`/`bufs@0x80`/`user@0x88`）；legacy 适配必须关。
- `task_struct` 相对 K40 4.19 后半段整差 `-0x80`（10 个字段交叉验证）。
- `do_futex` 帧**不是**交接文档写的 `0x60`，全函数扫描是 `0x210`；栈叠加必须按真实帧，否则 waiter word 算错。
- KASLR 在本机实测确实开着（`unmap_kernel_at_el0` 分支条件 + KPTI `forced ON`，证据在 `last_kmsg*`），**所有静态 OFF 运行时必须叠加 slide**。
- `init_cred` 不能靠 `FAKE_TASK_*` 平移，必须从 `prepare_kernel_cred` 的 ADRP/ADD + `init_task.real_cred` 反推（`gen_target` 的 `MEASURED` 字典已固化）。
- `SELINUX_ENFORCING` 在本机是 `state+1`（不是 K40 的 `state+0`）。

---

## 5. 限制与边界

- `gen_target` / `verify` 内联了本内核的绝对 `vaddr` 与断言，是「为这个内核量身」的模板；换不同内核源码要改 `MEASURED` 字典与 `verify` 的绝对地址。
- `frames.py`、`ksymtab.py` 是诊断/扫描脚本，产出的中间结论已固化进 `gen_target` 与 `verify`，日常复用只需跑最后两步。
- 本包只解决**离线偏移提取与复核**，不含任何运行时 exploit，不触碰设备；运行 exploit 仍需另走设备侧只读/授权流程。
- 五条提权路线（GhostLock / fastboot / edl+mtkclient / 真 BROM / 换工具）在本机均已判死，详见 `../路线总账.md`；本包的价值在于「下一次」，不是「这一次的未竟之功」。
