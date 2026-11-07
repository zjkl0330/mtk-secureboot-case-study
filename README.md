# MTK Secure Boot 封锁链路案例研究

> 一台 OPPO K9 Pro（`PEYM00` / 联发科 MT6893 天玑 1200）的 Bootloader 解锁尝试完整复盘。
>
> **结果：失败。五条技术路线全部实测封闭。**
>
> 这个仓库记录的不是「怎么解锁」，而是**怎么系统地证明一条路走不通**，以及在失败中留下的可复用资产。

---

## 为什么值得读

绝大多数「解锁教程」只讲成功路径。这个仓库相反：它把**每一条失败路径的封死原因、验证方法、原始证据**都留了下来。

适合以下场景阅读：

- 想了解 **MTK 启动链**（BROM → PreLoader → LK → fastboot）各层到底保护了什么
- 想学**如何给一个不确定的技术假设做证伪实验**，而不是靠猜
- 遇到过「`fastboot devices` 看不到设备」「握手一直失败」「串口有端口但没反应」这类问题
- 想了解 **Android 内核漏洞利用**（4.19 / futex PI）为什么会在 KASLR 这一步卡死
- 想学**偏移表提取与交叉复核**的工程方法

---

## 一句话结论

> MTK 的 Secure Boot 是一条**三层独立加固的链**（BROM / PreLoader / LK+fastboot）。破解任一层都需要「已经能写」——而「能写」又要求先突破该层。所有民间方案（破端口 preloader、解锁版 LK、boot1 补丁）都卡在同一个**鸡生蛋闭环**上。

在这台设备上，这个闭环没有被打开。

---

## 目标设备

| 项 | 值 |
|---|---|
| 型号 | OPPO K9 Pro `PEYM00` / `OP5245` |
| SoC | 联发科 MT6893（天玑 1200），DA 协议 V5（XFLASH） |
| 出厂系统 | ColorOS 13 / Android 13，`PEYM00_13.1.0.254(CN01)` |
| 测试系统 | 降级至 ColorOS 12 / Android 12，`PEYM00_11_C.13` |
| 内核 | `4.19.191+`，构建于 2026-04-02 |
| 锁状态 | `ro.boot.flash.locked = 1`，`verifiedbootstate = green` |
| OEM 解锁许可 | `sys.oem_unlock_allowed = 1`（**开着**，缺的是能执行 unlock 的环境） |
| 设备序列号 | `<DEVICE_SN>`（已脱敏） |

---

## 五条路线与最终判定

| # | 路线 | 判定 | 封死原因 |
|---|---|---|---|
| 1 | 真 fastboot + `flashing unlock` | ❌ 实测 | `reboot bootloader` 被 ColorOS 拦截；`fastboot` 90 秒内从未枚举到设备 |
| 2 | fastbootd 解锁 | ❌ 实测 | userspace 实现，`flashing unlock` → `Unrecognized command`；`oem unlock` → `Unable to open fastboot HAL` |
| 3 | MTK PreLoader + DA（mtkclient / 刷机匣） | ❌ 实测 | 端口能枚举，但**是纯回环**（发什么回什么），MTK 协议栈根本不在；DA 校验 `0x7024` 连发生的资格都没有 |
| 4 | 短接/按键进 BROM + kamakiri | ❌ 实测 | `0E8D:0003` 从未出现；preloader 完好就永不回落 BROM |
| 5 | 内核漏洞 GhostLock（CVE-2026-43499） | ❌ 静态判死 | 三条写原语在 4.19 全部擦边；KASLR slide 与写原语互为前置，死锁 |

另有两条非技术路线（OPPO 官方深度测试、第三方付费服务），未在本项目中验证。

---

## 三个最硬的实测发现

### 1. `22D9:0006` 是一个「假串口」

设备按键或 `adb reboot edl` 后会枚举出 `MediaTek PreLoader USB VCOM`，看起来可以用。实测：

```
send a0           -> recv a0            ← 真 MTK 握手应回 5f（取反）
send 11 22 33 44  -> recv 11 22 33 44   ← 原样
send de ad be ef  -> recv de ad be ef   ← 原样
send 16B 30..3f   -> recv 同一 16 字节  ← 完全镜像
VERDICT: PURE LOOPBACK
```

**结论：这个接口只做了 USB 枚举，没有运行 MTK 的下载协议。** 发什么回什么，任何握手、DA 传输、payload 注入都不可能成功——与代码是否正确无关。

> 这也是本仓库最有通用价值的一条经验：**传输层能打开 ≠ 协议层存在**。判断依据不是「有没有端口」，而是「回的字节对不对」。

### 2. `22D9:2769` 是重启瞬态，不是一个模式

它的接口描述符确实是标准 Android fastboot（`Class_FF / SubClass_42 / Prot_01`，GUID `{F72FE0D4-...}`），容易被误判成「OPPO 私有 fastboot 模式」。但实测：

- `fastboot reboot bootloader` 返回 `OKAY`
- 之后 90 秒 `fastboot getvar all` 全程 `< waiting for any device >`
- 同期 `adb devices` 8 秒内恢复 `device`（已回 ColorOS）

**它是重启过程中 USB 栈重新枚举的零点几秒残影，设备从不停在 bootloader。** `fastboot.exe` 抓不到它不是驱动问题，是窗口不存在。

### 3. 刷机匣失败的真正原因不是机型不支持

工具日志第 5 行：

```
DA1=/DA/Common/MT6893_DA1_PATCHED.bin, DA2=/DA/Common/MT6893_DA2_PATCHED.bin
```

它一直加载的是**签名段被改坏的 PATCHED DA**（与原版前 64 字节相同，但体积少 4272 字节）。所以 `ConfigureDa失败` 是必然结果。配置里那条使用 OPPO 官方签名 DA 的条目从未真正执行过——不过即便执行，也会因为上面第 1 条（通道是回环）而失败。

---

## 仓库结构

```
.
├── README.md                      本文件
├── docs/
│   ├── 01-attack-surface.md       MTK 启动链与三层保护（技术背景）
│   ├── 02-route-inventory.md      七条路线总账
│   ├── 03-preloader-da.md         PreLoader / DA / 破端口方案评估与实测
│   ├── 04-kernelsnitch.md         KASLR 侧信道可行性评估
│   ├── 05-offset-extraction.md    4.19 内核偏移提取结果
│   ├── 06-exploit-chain-419.md    GhostLock 利用链端到端分析（为何判死）
│   ├── 07-methodology-lessons.md  ★ 方法论与踩坑教训
│   ├── 00-device-baseline.md      设备基线采集
│   └── appendix/
│       ├── file-inventory.md      原始文件清单与取舍理由
│       ├── handoff-offset-extraction.md
│       └── handoff-model-switch.md
├── scripts/
│   ├── probe/                     串口回环检测、端口监测（★ 最实用）
│   ├── fastboot/                  fastboot 协议直连、抢占窗口
│   ├── mtk/                       preloader 抢连与 payload 尝试
│   └── recon/                     早期设备侦察脚本
├── evidence/
│   ├── logs/                      实测日志（已脱敏）
│   └── disasm/                    内核反汇编分析输出
└── reuse-kit/                     ★ 可复用资产：239 宏偏移表 + 提取管线
```

---

## 最值得直接用的两个东西

### 1. 串口回环检测器（`scripts/probe/echo_check.py`）

判断一个 MTK 「VCOM 端口」是真协议还是假回环，10 秒出结论：

```bash
python echo_check.py
# send a0 -> recv 5f   => 真协议
# send a0 -> recv a0   => 回环，此路不通
```

### 2. 内核偏移表复用包（`reuse-kit/`）

239 个 `#define`，其中 49 项经独立方法交叉复核 **PASS 49 / FAIL 0**。配套可重跑管线：

```bash
cd reuse-kit/pipeline
python gen_target.py      # 从 vmlinux 重算偏移表
python verify_target.py   # 独立复核，必须 PASS 49 / FAIL 0
```

> 这台设备的漏洞利用失败了，但偏移表对「同一 4.19 内核将来出现新漏洞」仍然可用。复用方法见 `reuse-kit/REUSE-GUIDE.md`。

---

## 本仓库**不含**什么

出于合规与安全考虑，以下内容**均已排除**：

- ❌ 厂商二进制：`boot.img`、`vmlinux`、`lk`、`preloader`、`DA`、分区镜像
- ❌ 可运行的 exploit 代码（`docs/06` 只记录**为什么不可行**，不含可用原语）
- ❌ 厂商签名私钥、证书、解密密钥
- ❌ 第三方商业工具（刷机工具、破解服务）
- ❌ 含个人隐私的 `bugreport` 包（IMEI、账号、日志）
- ❌ 设备真实序列号（全文替换为 `<DEVICE_SN>`）

---

## 免责声明

本项目为**个人设备上的技术研究与学习记录**，目的是理解 MTK 启动链与 Android 安全机制的设计。

- 不提供、不鼓励任何绕过厂商安全保护的服务或工具
- 不保证任何内容的准确性；所有结论以文中的实测证据为准
- 设备为本人所有，全程未刷写任何分区、未解锁、未安装任何提权组件
- 请遵守当地法律法规及设备厂商的服务条款

如果这个仓库对你有帮助，它的价值主要在于**方法**，而不是**结论**——你的设备可能完全不同。

---

## 阅读建议

| 你的兴趣 | 从这里开始 |
|---|---|
| 只想搞懂 MTK 启动链 | `docs/01-attack-surface.md` |
| 手上也有解不开的 MTK 机 | `docs/02-route-inventory.md` → `docs/07-methodology-lessons.md` |
| 在做内核漏洞研究 | `docs/05` → `docs/06` → `reuse-kit/` |
| 想看实验怎么设计的 | `docs/07-methodology-lessons.md` |
| 想知道哪些文件被排除了 | `docs/appendix/file-inventory.md` |
