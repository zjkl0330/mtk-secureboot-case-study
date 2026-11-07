# MTK Preloader / DA 加密 静态判定 — PEYM00

> 2026-11-07｜对象：OPPO K9 Pro `PEYM00` / MT6893 / Android 13 / UFS 存储
> 目的：判定「免内核漏洞、免官解」的 preloader 破端口方案在本机是否可行。
> **纯本地静态分析；未上机、未刷写任何分区。**

---

## 零、一句话结论

**DA 加密不是障碍，本地这套方案已经绕过去了 —— 它不是破解 DA，是改 preloader。**

本地存在一份**群友在 OPPO K9 Pro 上实测通过**的 preloader 材料，
机制已经逆清（只改 4 个头部字节 + 把 preloader 从 `0x1000` 挪到 `0x2000`）。

作用不是 root，而是让设备启动后**进入 fastboot 模式**，从而能执行 `flashing unlock` 解锁 BL。
解锁 BL 之后，root（Magisk / KernelSU / APatch）才变成常规操作。

**唯一未解的门：锁 BL 状态下 fastboot 到底允不允许刷 `preloader` 分区。** 这一步只能实测。

---

> ### ⚠️ 2026-11-07 17:4x 上机实测结论（推翻上文两处乐观判断）
>
> 三条命令已跑完，结论**比预期糟**：
>
> | 实测项 | 结果 |
> |---|---|
> | `ro.boot.flash.locked` | **`1`** —— bootloader 锁定（配合 `verifiedbootstate=green`、`veritymode=enforcing`） |
> | `adb reboot-bootloader` → `fastboot devices` | 设备**确实进了 bootloader**（USB PID `2765 → 2769`，WinUSB 已绑定），但 **fastboot 完全看不到设备**，`getvar` 一直 `< waiting >` |
> | `adb reboot edl` → mtkclient | 设备进了 **`MediaTek PreLoader USB VCOM (COM6)`（PID `0006`）**，但 mtkclient **`Handshake failed` ×34**，重试无果 |
>
> 因此：
> 1. **fastboot 刷 preloader 这条路封死** —— 锁 BL 且 bootloader 不暴露可用 fastboot 接口。
> 2. **「DA 加密不是障碍」需要修正** —— DA 文件本身确实是明文（v5、hash 通过），但**设备端 preloader 拒绝未认证的 DA 下载**。文件格式与传输握手是两件事，之前混为一谈了。
> 3. 真正要破的是 **PreLoader 的 SLA/DAA 握手认证**，这正是「破端口」三个字的本义 —— 而它现在成了鸡生蛋：刷破解 preloader 需要先握手，握手需要破解 preloader。
>
> 详见第三·五节。

---

## 一、DA 到底是什么状态

### 1.1 `DA_BR_MT6893.bin`

| 项 | 值 |
|---|---|
| 大小 | 823362 (`0xc9042`) |
| 头 | `MTK_DOWNLOAD_AGENT\0\0\0` + `MTK_AllInOne_DA_v3.3001.2022/02/16.16:55_579361` |
| 格式 | DA **v5**（`Tools/da_parser.py` 可解析） |
| 熵 | 7.041（**不是加密特征**；加密应为 7.9+） |

`mtkclient/Tools/da_parser.py` 实测解析结果：

```
Loader: MTK_DA_V5.bin
hwcode: 0x2601        <- 天玑系列特征码
hw_sub_code: 0x8A00
hw_version: 0xCA00
Hash check 3 found.
Offset: 0x39e4  Length: 0xe660  Addr: 0x2007000
```

- `hwcode 0x2601` 段 **hash 校验通过**（`Hash check 3 found.`）
- 全文件 44 处 `Hash check`、6 处 `HASH ERROR`，**6 处全部落在别的芯片段**
  （`0x6571 / 0x6573 / 0x6575 / 0x6577 / 0x6583` —— MT657x 老平台）
- MT6893 那一段是干净的

`mtkclient/Library/DA/xflash/extension/xflash.py:896` 与 `legacy.py:306` 都有：

```python
if self.config.hwcode in [0x2601, 0x6572]:
```

⇒ `0x2601` 是 mtkclient 专门分支处理的天玑 hwcode。

**结论：DA 本身明文、结构可解析、目标芯片段完整。不是「DA 加密挡路」。**

### 1.2 真正的门是什么

MTK 的下载链有三道闸，按顺序：

| 闸 | 作用 | 本机状态 |
|---|---|---|
| **DAA**（Download Agent Authentication） | BROM 校验 DA 的厂商签名 | 未知（需 BROM 通讯才知道） |
| **SLA**（Serial Link Authorization） | 握手后要求挑战应答，需厂商私钥 | DA 内有 `SLA`×9、`sla`×12 字符串，说明流程存在 |
| **Secure Boot / 防回滚** | preloader / lk 的签名与版本 | `CONFIG` 层面与 UFS 层均有 |

要过这三道，通常是「用厂商 auth 文件」或「找 BROM 漏洞」。**而本地这套方案走的是第三条路：
根本不进 BROM，而是先改掉设备自己的 preloader。**

---

## 二、破端口方案的实际机制（已逆清）

### 2.1 手上有什么

| 文件 | 大小 | 是什么 |
|---|---|---|
| `天玑1200-破锁端口.zip` → `天机1200-破端口安卓12-13版本/preloader.img` | 472908 | **A12/13 通用版**，与 `breakport/preloader.img` md5 一致 (`3d6881c1cbf68880`) |
| 同上 → `天玑1200-破端口安卓12版本/preloader.img` | 452608 | A12 专用（说明书说 A13 用会卡开机） |
| 同上 → `sda.img` / `sdb.img` | 各 4194304 | `UFS_BOOT` 容器，`MMM` 在 **0x1000** |
| `oppok9pro-11.1-刷机匣刷入-backup.zip` → `boot1-back.bin` | 4194304 | **本机 UFS boot 分区原始备份**（救砖用） |
| `安卓13不允许刷入-…-ubl-刷机匣格式.zip` → `boot1-fastboot刷机匣.bin` | 4194304 | fastboot 版，**文件名明确禁止用于 Android 13** |

### 2.2 破端口改了什么 —— 逐字节 diff

对比 `boot1-back.bin` 与 `boot1-fastboot.bin`：

**整个 4 MB 只有 4 个字节不同：**

```
+0x20d   back=0x10  ->  fb=0x20
+0x212   back=0x08  ->  fb=0x10
+0x21d   back=0x10  ->  fb=0x20
+0x222   back=0x08  ->  fb=0x10
```

**加上 preloader 主体整体后移 `0x1000`：**

```
boot1-back.bin      : MMM\x01 @ 0x1000
boot1-fastboot.bin  : MMM\x01 @ 0x2000
back[0x1000:] vs fb[0x2000:]  公共前缀 0x3fe000 （占 99.9%）
```

这 4 个偏移正是 `path_preloader.py`（作者 `Dev. Max_Goblin - 4pda`）读取的那几个：

```python
code_offset  = data[0x20d] * 256
code_offset2 = data[0x211]
code_offset3 = data[0x212]
code_offset1 = data[0x21d]
code_offset4 = data[0x221]
code_offset5 = data[0x222]
...
f.seek(0x2000); f.write(data_raw)
```

**⇒ 代码一个字节都没改，改的是「preloader 在 UFS boot 分区里的落点」和 4 个描述该落点的偏移。**

### 2.3 为什么这能开 fastboot

`UFS_BOOT` 头（`0x000`）+ `BRLYT`（Bootloader Layout 表，`0x200`）描述分区内各段的布局。
把 preloader 挪一个 4 KB 页、同步改 4 个偏移字节后：

- BROM / LK 对 preloader 的定位与校验覆盖面发生变化
- 结果是设备启动后**停在 fastboot 模式**（而不是正常开机）

据 `群文件说明.txt` 原文：

> 这些均为 **Preloader 方案的解锁文件，意在开启 fastboot 模式从而解锁 bl**
> 请注意，更新系统的话请务必还原原来的 preloader 分区

⇒ **目标是「能进 fastboot 并解锁 BL」，不是拿 root。** 解锁后 root 才顺理成章。

### 2.4 实测背书

`使用方法.txt` 的测试机型列表**第一行就是 `OPPO K9PRO`**：

```
通过测试机型:
OPPO K9PRO
OPPO Reno6 Pro / Reno7 Pro / Reno8
Realme GT Neo / Neo 闪速版 / Neo 2T
```

刷入方式（原文）：

```
破解刷入:
fastboot模式      fastboot flash preloader preloader.img
fastbootd模式     fastboot flash sdb sdb.img
                  fastboot flash sda sda.img
sp线刷            使用preloader.img替换preloader.bin
```

并明确警告：

> **请勿使用 unlocktool 直接刷入**，不然即使破解端口成功你也不能退出端口正常开机

---

## 三、必须注意的三个风险

### 3.1 版本匹配 —— 这个坑最容易踩

`AAA看不懂提示词的点我.txt` 解释命名规则：

> 前面的是提示词：比如 **安卓11/13不允许刷入**
> 后面的是适用的型号与版本

所以 `安卓13不允许刷入-oppok9pro-A11.1-12.1-ubl-刷机匣格式.zip` 的字面意思就是
**这个包不能刷到跑 Android 13 的设备上**。我们的机器是 Android 13
（`TP1A.220905.001`），那个包**不能用**。

要用的只有 `天机1200-破端口安卓12-13版本/preloader.img`（即 `breakport/preloader.img`）。

### 3.2 `breakport/` 这套与当前固件未必同源

实测三份材料互不相同：

| 对比 | 结果 |
|---|---|
| `breakport/preloader.img` vs `boot1-back.bin[0x1000:]` | 差异 **420158 / 472908** 字节 |
| `breakport/preloader.img` vs 官方 `OPPOK9Pro_preloader_k6893v1_64_k419.bin` | 差异约 90% |
| `boot1-back.bin[0x1000:]` vs 官方 k419 preloader | 长度差 0x110，逐字节差 **89.9%** |

⇒ 三份是**同平台、同版本号（`MTK_BLOADER_INFO_v51` / `V116` / `k6893v1_64`）、
不同编译批次**的产物。同平台能跑，但不保证与当前 F.31 固件逐字节对应。

`boot1-back.bin` 的价值就在这里：它是**本机 UFS boot 分区的完整 4 MB 备份**，是最靠谱的退路。

### 3.3 刷坏 = 硬砖，需要 EDL / 测试点

preloader 是启动链第一环，刷错型号或刷入不完整文件都会黑砖。
`群文件说明.txt` 列了三种典型黑砖原因：

1. 刷错型号的 preloader
2. 刷入大小不完整的 `preloader_k6xxx_v1_64`（指刷机匣里约 600 KB 的文件）
3. 把分区表里的 `BOOT-1` 当成 boot 刷（**`BOOT-1`/`BOOT-2` 分别是 `preloader_a`/`preloader_b`**）

救砖路径：`boot1-back.bin` 通过 EDL / mtkclient 写回。而 EDL 又要过 DAA/SLA —— 回到 §1.2。

---

## 三·五、上机实测记录（2026-11-07 17:4x，全程只读）

设备 `<DEVICE_SN>`，Android 13 / `PEYM00` / 内核 4.19.191+。
本节所有操作**均为重启 + 读取**，未刷写任何分区、未安装任何 APK、未解锁。

### 3.5.1 锁状态（`getprop`，零风险）

```text
ro.bootmode           = normal
ro.boot.verifiedbootstate = green      # AVB 校验通过，boot 分区完整
ro.boot.flash.locked  = 1             # ← bootloader 锁定
ro.boot.veritymode    = enforcing
```

### 3.5.2 进 bootloader：进了，但 fastboot 不响应

| 步骤 | 结果 |
|---|---|
| `adb reboot-bootloader` | 成功。USB PID `22D9:2765 → 22D9:2769`，设备从 adb 消失 |
| Windows 驱动 | ✅ 已正确绑定：`CompatibleIds = USB\MS_COMP_WINUSB`、`Service = WINUSB`、`Status = OK` |
| `fastboot devices` | ❌ **空**（等了 3 轮 × 3 次） |
| `fastboot -s <DEVICE_SN> getvar all` | ❌ `< waiting for <DEVICE_SN>>` 直到超时 |
| `fastboot devices -l` / `getvar` verbose | ❌ 同样空，无任何错误信息 |
| 退出方式 | 约 2～3 分钟后**自己重启回系统**（未做任何操作） |

排除了四个常见原因：

| 疑似原因 | 实测 |
|---|---|
| adb server 抢占句柄 | 已 `adb kill-server` 后重试，仍空 |
| 非管理员权限 | 当前 shell 为 `WIN-2P14QIL2QA1\Administrator`，`IsAdmin = True` |
| USB 3.0 兼容性 | 设备实际挂在 `05E3:0610` 这个 **USB 2.0 hub** 的 `HSP1` 端口，非 USB 3.0 直连 |
| fastboot 版本旧 | `fastboot version 37.0.1-15733141`（最新 platform-tools） |

**结论**：锁 BL 状态下，这台机器的 bootloader **不向主机暴露可用的 fastboot 接口**。
`flashing unlock` / `flash preloader` 这条路走不通。

### 3.5.3 进 EDL：PreLoader 起来了，但拒绝握手

`adb reboot edl` **有效**：

```text
设备枚举为：MediaTek PreLoader USB VCOM_V2023 (Android) (COM6)
VID_22D9 & PID_0006
```

注意是 **PID `0006`（PreLoader VCOM）**，不是 `0003`（BROM）。

按「mtkclient 先启动、再让设备进模式」的顺序重试：

```bash
# 后台: python mtk.py printgpt
# 前台: adb reboot edl
```

结果：

```text
Preloader - Status: Waiting for PreLoader VCOM, please reconnect mobile/iot device to brom mode
Port - Handshake failed after retries
Preloader - [LIB]: Status: Handshake failed, retrying...
（重复 34 次，全部失败）
```

日志全文：`boot/_mtk_handshake.txt`（230 行）。

**这是一个非常重要的正结果 + 负结果组合**：

| 项 | 结论 |
|---|---|
| EDL/PreLoader 入口能不能进 | ✅ **能**，`adb reboot edl` 一条命令就够，不需要拆机短接 |
| mtkclient 能不能连 | ❌ 端口能打开，**DA 下载握手被拒** |
| 拒绝原因 | PreLoader 的 **SLA/DAA 认证保护** —— 即「破端口」要破的那个东西 |

### 3.5.4 对 §1.2 的修正

上一版把「DA 文件是明文」直接推成「DA 不是障碍」，**这是错的**。要分开看：

| 层 | 状态 |
|---|---|
| DA **文件本身**的格式/加密 | ✅ 明文 v5，`hwcode 0x2601` 段 hash 通过 —— 静态结论仍成立 |
| 设备端 PreLoader **接不接受**这颗 DA | ❌ **拒绝**，握手阶段就断 |

「破端口 preloader」的作用因此更清楚了：它不是解密 DA，而是**把 preloader 里的认证检查拆掉**，
让它在握手阶段直接放行。这也解释了为什么必须先把它刷进 `preloader` 分区，
而**刷它本身又需要一次成功的握手** —— 鸡生蛋。

### 3.5.5 剩下唯一没试的入口：真 BROM

现在的死锁能不能破，取决于 **BROM（PID `0003`）是否也要求同样的认证**。
`adb reboot edl` 只到 PreLoader 层，到不了 BROM。

进 BROM 只有硬件路径（mtkclient 自己的提示）：

```text
For brom mode, press and hold vol up, vol dwn, or all hw buttons and connect usb.
For preloader mode, don't press any hw button and connect usb.
```

即：**关机状态下按住音量上+下（或全部硬件键）再插 USB**。
MT6893 若 BROM 也带 SLA，则需 BROM 级漏洞（`kamakiri` 一类），那是另一个研究课题。

---

## 四、现在的精确状态（17:4x 实测后更新）

| 环节 | 状态 |
|---|---|
| DA **文件**格式/加密 | ✅ 明文 v5，目标段 hash 通过（静态结论） |
| 设备端 PreLoader **接不接受** DA | ❌ **实测拒绝：`Handshake failed` ×34** |
| 破端口 preloader 存在且适配 K9 Pro | ✅ 说明书实测机型第一行 |
| 改了什么 | ✅ 已逆清（4 字节 header + 0x1000 位移） |
| 救砖备份 | ✅ `boot1-back.bin`（4 MB 完整分区） |
| bootloader 是否锁 | ❌ **锁着**（`ro.boot.flash.locked = 1`） |
| **锁 BL 下 fastboot 能否刷 preloader** | ❌ **实测否**：bootloader 进了（PID 2769），但 fastboot 完全看不到设备 |
| `adb reboot edl` 能否进 PreLoader | ✅ **能**，一条命令，PC 识别为 `PreLoader USB VCOM (COM6)` |
| 进 BROM（PID `0003`） | ❌ 未验证，需硬件操作 |
| 刷入后能否 `flashing unlock` | ❌ 未验证（前置未通） |
| 与当前 F.31 固件的兼容性 | ⚠️ 同平台不同批次，未知 |

**这条路的价值不变**：完全绕开内核漏洞，不需要 GhostLock、不需要 slide、
不需要那 96 / 16 字节的栈空间。拿到 BL 解锁后，root 是常规工程问题。

**但它的入口比预想的窄**：fastboot 那条已经实测封死，只剩 BROM 一条，而 BROM 有待验证。

---

## 五、下一步（按成本排序，17:4x 修订）

| 步 | 动作 | 代价 | 风险 | 状态 |
|---|---|---|---|---|
| ~~1~~ | ~~`adb reboot bootloader` + `fastboot getvar all`~~ | — | — | ❌ **已做，fastboot 不通** |
| ~~2~~ | ~~`fastboot getvar partition-type:preloader`~~ | — | — | ❌ 前置不通，无法执行 |
| ~~3~~ | ~~`adb reboot edl` + mtkclient~~ | — | — | ⚠️ **已做，握手被拒** |
| **4** | **关机 → 按住音量上+下 → 插 USB**，看是否出现 `VID_0E8D&PID_0003`（真 BROM） | 需你动手 | 无（只是进模式） | ⬜ **唯一未试** |
| 5 | 若 BROM 也不要求认证 → mtkclient `printgpt` 只读验证 → 再谈刷 preloader | 只读 | 无 | 待 4 |
| 6 | 若 BROM 同样要 SLA → 需 BROM 漏洞（`kamakiri` 一类），属新研究课题 | 高 | — | — |

**第 4 步是现在唯一还开着的门，而且只需要你按两个键。**

判定标准很明确：

- 出现 `VID_0E8D & PID_0003`（或 `MediaTek USB Port`）→ **真 BROM，这条路活了**
- 出现 `VID_22D9 & PID_0006`（`PreLoader USB VCOM`）→ 还是 PreLoader 层，按键没生效
- 什么都没出现 → 这台机器的 BROM 入口被关，需要短接测试点（拆机）

---

---

## 六、产物

```
F:\root\k9pro\da\
  preloader_official.bin      478456  公开包里的 K9Pro k419 preloader
  boot1-back.bin             4194304  本机 UFS boot 分区原始备份（救砖）
  boot1-fastboot.bin         4194304  fastboot 版（禁用于 Android 13）
  lk_11.img                  5242880  LK 原版
  lk_11_fastbooot.img        5243968  LK fastboot 版（多 0x440 字节）
F:\root\k9pro\breakport\
  preloader.img               472908  A12/13 通用破端口 preloader
  sda.img / sdb.img          4194304  各一份，MMM@0x1000
F:\root\k9pro\boot\
  _mtk_handshake.txt              230  mtkclient 握手失败全文（34 次重试）
```

---

## 七、这次实测到底改了什么判断

| 之前的判断 | 17:4x 实测后 |
|---|---|
| DA 明文 ⇒ DA 不是障碍 | ❌ 混淆了两件事：文件格式 vs 传输认证。**认证才是门** |
| 先试 fastboot 能不能刷 | ❌ 已试：锁 BL + bootloader 无 fastboot 接口 = 封死 |
| 瓶颈是「第一刀怎么切进去」，成本最低 | ⚠️ 第一刀比预想窄：fastboot 已死，只剩 BROM |
| EDL 需要拆机短接 | ✅ **不用**，`adb reboot edl` 一条命令进 PreLoader（但握手被拒） |

**一句话**：`adb reboot edl` 证明了「不用拆机就能把设备拽进下载模式」，
但 PreLoader 层的 SLA/DAA 认证把它拦在握手第一步。
下一步只需要确认 **BROM 层（PID `0003`）是否也要求同样的认证** —— 那是整条路唯一还开着的门。
