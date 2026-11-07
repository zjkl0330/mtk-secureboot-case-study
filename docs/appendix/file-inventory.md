# 附录 · 原始文件清单与取舍理由

> 原始工作目录共 **92 个顶层文件 + 8 个子目录**，总计约 **250 MB**（含厂商二进制与内核镜像）。
>
> 本仓库只收录**可公开、有学习价值、且不含第三方版权内容**的部分（约 1.4 MB）。本文件说明每个文件的去向与原因。

---

## 一、收录原则

| 收录 | 理由 |
|---|---|
| ✅ 自己撰写的分析文档 | 核心智力产出 |
| ✅ 自己编写的脚本 | 可复用工具 |
| ✅ 实测日志与反汇编输出 | 结论的证据支撑 |
| ✅ 逆向得出的偏移表 | 研究产出，非厂商原始文件 |

| 排除 | 理由 |
|---|---|
| ❌ 厂商固件与分区镜像 | 版权归属厂商，且体积大 |
| ❌ DA / PreLoader / LK 二进制 | 同上，且可能被视为破解材料 |
| ❌ `bugreport` 压缩包 | 含 IMEI、账号、使用日志等隐私 |
| ❌ 第三方工具（exe / msi / zip） | 非本人作品，且涉商业授权 |
| ❌ 补丁类脚本 | 用途是绕过校验，不提供代码，仅文字描述原理 |
| ❌ 屏幕截图 | 可能含主机名、路径等环境信息，且无独立价值 |

---

## 二、文档（8 份 → `docs/`）

| 原文件 | 新位置 | 说明 |
|---|---|---|
| `README-继续.md` | `docs/00-device-baseline.md` | 设备基线、驱动排查记录、当时的技术路线假设 |
| `路线总账.md` | `docs/02-route-inventory.md` | 七条路线的总判定与证据索引 |
| `评估-破端口preloader.md` | `docs/03-preloader-da.md` | 破端口 LK、boot1 补丁的完整拆解与实测 |
| `评估-kernelsnitch.md` | `docs/04-kernelsnitch.md` | KASLR 侧信道能否推出 slide 的可行性评估 |
| `偏移提取-结果.md` | `docs/05-offset-extraction.md` | 239 宏偏移表的第一轮证据报告 |
| `利用链-4.19-PEYM00.md` | `docs/06-exploit-chain-419.md` | GhostLock 端到端 0–7 阶段，含判死论证 |
| `HANDOFF-偏移提取.md` | `docs/appendix/handoff-offset-extraction.md` | 协作交接记录（可跳过） |
| `HANDOFF-换模型.md` | `docs/appendix/handoff-model-switch.md` | 协作交接记录（可跳过） |

> 新增：`docs/01-attack-surface.md`、`docs/07-methodology-lessons.md`、本文件。

---

## 三、脚本（→ `scripts/`）

### 收录

| 原文件 | 新位置 | 用途 |
|---|---|---|
| `serial_probe.py` | `scripts/probe/` | 串口握手对照探测（带/不带唤醒字节） |
| `echo_check.py` | `scripts/probe/` | ★ 回环判定：任意字节镜像测试 |
| `port_watch.py` | `scripts/probe/` | 监测 COM 口消失/重现，确认是否真断电重连 |
| `hot_wait.py` | `scripts/fastboot/` | 毫秒级抢连 libusb fastboot 接口 |
| `fb.py` `fb2.py` | `scripts/fastboot/` | 直接构造 fastboot 协议包（绕过 fastboot.exe） |
| `fb_reset.py` | `scripts/fastboot/` | USB 端口复位尝试 |
| `fb_winusb.py` | `scripts/fastboot/` | 原生 WinUSB API 通信尝试 |
| `chain.sh` | `scripts/fastboot/` | ★ 完整链路：adb reboot fastboot → 跳 bootloader → 90 秒抢占 |
| `fb_poll.sh` | `scripts/fastboot/` | 持续轮询 fastboot devices |
| `run_payload.py` | `scripts/mtk/` | 抓 COM 口后自动跑 `mtk.py payload` |
| `auto_crash.sh` | `scripts/mtk/` | 轮询 adb，回系统即触发 crash |
| `watch_port_and_crash.py` | `scripts/mtk/` | 端口出现即触发 crash（不打开串口，避免假死） |

### 未收录

| 原文件 | 原因 |
|---|---|
| `path_preloader.py` | **补丁工具**（修改 preloader 使 DA 校验失效）。不提供代码，原理见 `docs/03-preloader-da.md` |
| `_sn*.py` `_pw*.py` `_shot2.py` `_top.py` | 早期设备信息/截图脚本，产出的是截图，无独立价值 |
| `_reg.py` `_svc*.py` `_usb.py` `_mon.py` `_query.py` | 早期驱动/注册表排查，结论已并入 `docs/00` |
| `_fix*.py` `_inst.py` `_dep.py` `_perm.py` `_back.py` `_fg.py` `_pre*.py` `_switch.py` `_min2.py` | 一次性环境修复脚本，与最终结论无关 |

> 30 个 `.png` 均为 PowerShell / 设备管理器的窗口截图，**全部排除**。

---

## 四、证据（→ `evidence/`）

### `evidence/logs/`（实测日志，已脱敏）

| 文件 | 内容 |
|---|---|
| `chain.log` | fastbootd → bootloader → 90 秒抢占全过程（决定性证据） |
| `hotwait.log` | libusb 抢连 `22D9:2769` 时的 `Access denied` 记录 |
| `fbpoll.log` | `fastboot devices` 轮询（结果为空） |
| `payload_trace.log` | `adb reboot edl` → 3 秒抓到 COM6 → 启动 payload |
| `payload_run.log` | payload 超时记录（含"缓冲区被吞"的实证） |
| `port_watch.log` | COM 口消失/重现监测 |
| `baseline.txt` | 设备初始基线 |
| `device-getprop.txt` | 完整 `getprop` 输出（79 KB，已脱敏） |
| `device-meminfo.txt` | 内存布局（用于 `VA_BITS` 推算） |
| `device-config.txt` | `/proc/config.gz` 解出的内核配置（`KALLSYMS_ALL` 等） |

### `evidence/disasm/`（反汇编与静态分析输出，37 份）

| 文件组 | 内容 |
|---|---|
| `_dis_waiter.txt` `_dis_task.txt` `_dis_pipe.txt` `_dis_misc.txt` `_dis_globals.txt` | 关键结构体与指针表反汇编 |
| `_feas.txt` | 栈叠加可行性（得出可控上限 W≤7、缺口 96B） |
| `_fields2.txt` `_pin*.txt` | `task_struct` / 全局符号字段固定 |
| `_routes419*.txt` `_mcast_*.txt` `_rb_probe.txt` | 三条 write 原语逐层量化 |
| `_spsame*.txt` | 入口 sp 恒定性的证明 |
| `_frames.txt` `_frame.py` | 全函数栈帧测量（修正 `do_futex` 帧为 `0x210`） |
| `_dtb_parse.txt` `_kaslr_check.txt` | DTB 模板与 KASLR 分支核验 |
| `_mtk_handshake.txt` | ★ mtkclient 握手失败 ×34 的原始输出 |
| `_vuln*.txt` `_globals2.txt` `_gvars.txt` `_final.txt` `_verify.txt` `_ksymtab.txt` `_msf_len.txt` | 漏洞代码形态匹配、符号还原等 |

---

## 五、复用包（→ `reuse-kit/`，原样收录）

| 文件 | 说明 |
|---|---|
| `offsets/target-PEYM00.h` | 239 个 `#define`，49 项独立复核 PASS |
| `offsets/offsets-PEYM00.h` `offsets-PEYM00.json` | 同源的可读/机器格式 |
| `pipeline/{kelf,ksymtab,frames,gen_target,verify_target,paths}.py` | 可重跑的提取管线 |
| `REUSE-GUIDE.md` | 新 CVE 复用的 5 步手册 |
| `README.md` `evidence/EVIDENCE.md` | 包说明与原始证据索引 |

> 注意：`pipeline` 需要 `vmlinux.elf/.bin` 等输入才能运行，本仓库**不提供**这些厂商文件。管线代码本身可读、可移植。

---

## 六、完整排除清单（按目录）

| 目录 | 内容 | 大小 | 排除原因 |
|---|---|---|---|
| `boot/` | `vmlinux.elf`(41M) `vmlinux.bin`(38M) `kernel-decompressed.bin`(38M) `kernel.raw`(17M) `OPPO_PEYM00_..._boot.img`(32M) | ~166M | 厂商内核与固件 |
| `boot/lk/` | `lk_11.img` `lk_11_fastbooot.img` | 10M | 厂商 bootloader |
| `boot/bugreport/` | `bugreport-*.zip` | 13M | 含 IMEI、账号、日志等隐私 |
| `da/` | `boot1-*.bin` `preloader_official.bin` `lk_*.img` | 19M | 厂商分区镜像 |
| `breakport/` | `preloader.img` `sda.img` `sdb.img` | 8.7M | 破端口镜像（破解材料） |
| `ota/` | `payload_dumper.py` `resp.html` | 40K | 第三方脚本 + OTA 响应（含直链与个人信息） |
| `tools/` | `zadig.exe` `UsbDk_*.msi` `DA_BR_MT6893.bin` `ofp_qc_decrypt.py` | — | 第三方工具 + 厂商 DA |
| `_unlock/` | `使用方法.txt` `lk/` | — | 第三方破解包说明 |
| `backup/` `ghostlock/` `logs/` | 空目录 | 0 | — |
| 顶层 `*.png` | 30 张截图 | ~2M | 无独立价值，可能含环境信息 |

---

## 七、脱敏处理

| 项 | 处理 |
|---|---|
| 设备序列号（原值已抹除） | 全文替换为 `<DEVICE_SN>`（12 个文件） |
| IMEI / 手机号 / 账号 | 原始文件中未出现在所收录内容里 |
| MAC 地址 | 扫描确认不存在 |
| 主机名 / 用户名 | 保留 `Administrator` 等通用路径（无识别性） |
