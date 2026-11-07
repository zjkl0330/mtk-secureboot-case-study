# 01 · MTK 启动链与三层保护

> 本文是后续所有分析的背景。理解这条链，才能理解为什么「破端口 preloader」这类方案会形成死结。
>
> 文中标注「**本机实测**」的内容来自 `evidence/` 下的原始日志；其余为平台通用机制。

---

## 1. 启动链全景

联发科平台从上电到 Android，要经过四个阶段。每一阶段都有独立的校验和独立的入口：

```
上电
 │
 ├─① BROM          SoC 内部掩膜 ROM（不可修改）
 │      │          职责：读 eFuse 判断安全启动状态 → 校验并加载 PreLoader
 │      │          USB: 0E8D:0003（标准 VID）或厂商自定义 VID
 │      │
 │      ├─ 校验失败 → 停留在 BROM，暴露下载协议（可被 kamakiri 类漏洞攻击）
 │      │
 │      └─ 校验通过 ↓
 │
 ├─② PreLoader     存储中的第一段代码（preloader 分区）
 │      │          职责：初始化 DRAM、加载 LK、按按键进入下载/恢复模式
 │      │          USB: 本机为 22D9:0006（OPPO 自定义 VID）  ← 本机实测
 │      │
 │      └─ 校验通过 ↓
 │
 ├─③ LK (little kernel)  = bootloader
 │      │          职责：实现 fastboot 协议、校验 boot 镜像、决定是否解锁
 │      │          注意：厂商可**完全不实现 fastboot 接口**
 │      │
 │      └─ ↓
 │
 └─④ Kernel / Android
```

**关键点：BROM 在 SoC 内，无法被写入；PreLoader 在存储里，可被写入但需要权限；LK 也在存储里，同样需要权限。**

---

## 2. 每一层各自守着什么

| 层 | 保护机制 | 突破前提 | 本机状态 |
|---|---|---|---|
| **BROM** | SLA / SBC / Secure Boot 链 | 需要 BROM 级漏洞（如 kamakiri），且漏洞未被修补 | `0E8D:0003` 从未出现 → 无法评估 |
| **PreLoader** | DAA（Download Agent Authentication）+ SLA | 需要能和 PreLoader 完成握手，才能发 DA | 端口存在但**是回环** → 握手不可能 |
| **LK / fastboot** | `ro.boot.flash.locked=1` | 需要能进 fastboot 并执行 `flashing unlock` | **没有 fastboot 接口** → 无法执行 |
| **Android** | verified boot / dm-verity | 需要已解锁的 BL | `verifiedbootstate=green` |

> `DAA = Download Agent Authentication`，即 BROM/PreLoader 要求主机发来的 DA 必须带有效签名，否则拒绝。错误码 `0x7024` 就是 `DAA_SIG_VERIFY_FAILED`。

---

## 3. 为什么这会形成死结

三个「破锁包」看上去是三套方案，实际上是**同一件事的三层包装**：

| 方案 | 内容 | 需要什么 |
|---|---|---|
| 破端口 preloader | 替换 preloader，让 DA 校验失效 | 写入 preloader 分区 |
| 解锁版 LK | 修改 LK 条件判断，放出 fastboot 菜单 | 写入 lk 分区 |
| boot1 补丁 | 修改 boot1 分区里的 preloader 副本 | 写入 boot1 分区 |

**三者都需要「能写分区」。而「能写分区」需要先突破 BROM 或拿到 fastboot。**

```
要解锁 → 要能写分区
要能写分区 → 要进 BROM 或有 fastboot
要进 BROM → 要 preloader 失效
要 preloader 失效 → 要能写分区   ← 回到起点
```

这个循环里唯一不需要「写」的入口，就是**LK 里那个 fastboot 接口**。所以整个问题的关键变成一句话：

> **这台设备的 LK，到底有没有实现 fastboot？**

本项目的实测答案见 `03-preloader-da.md` 和 `07-methodology-lessons.md`：**没有**。

---

## 4. 几个容易混淆的点

### 4.1 BROM ≠ PreLoader

两者都能叫「下载模式」，但完全不同：

| | BROM | PreLoader |
|---|---|---|
| 位置 | SoC 内部 ROM | 存储分区 |
| PID | `0E8D:0003`（本机未出现） | `22D9:0006`（本机实测） |
| 能否被 kamakiri 攻击 | 能（视漏洞与平台代际） | 不能，需先 crash 到 BROM |
| 是否可写 | 否 | 是（需权限） |

**只要 PreLoader 完好，SoC 校验通过就会跳过去，永远不会停在 BROM。** 这一点决定了「拆机断电池也进不了 BROM」——断电重上电，PreLoader 还在存储里。

### 4.2 fastboot 和 fastbootd 不是一回事

| | fastboot（bootloader 模式） | fastbootd（userspace 模式） |
|---|---|---|
| 运行在 | LK | Android recovery 内的用户态进程 |
| `is-userspace` | no | **yes** |
| 能否 `flashing unlock` | 能（若 BL 允许） | **不能**，无 bootloader HAL |
| 本机实测 | 无法进入 | 能进，但 unlock 报 `Unrecognized command` |

很多人看到 `fastboot devices` 有输出就以为可以解锁，实际进的是 fastbootd，什么都做不了。

### 4.3 `22D9` 是 OPPO 自有 VID

联发科标准 VID 是 `0E8D`，但 OPPO 用了自己的 `22D9`：

| PID | 含义 |
|---|---|
| `22D9:0006` | PreLoader VCOM（本机实测：**回环**） |
| `22D9:2765` | MTP + ADB（正常系统） |
| `22D9:2769` | 重启瞬态，接口描述符是 fastboot 但设备不停留 |

mtkclient 的 `config/usb_ids.py` 需要手动补 `0x22D9` 条目，否则工具不认。

---

## 5. DA 是什么

DA（Download Agent）是主机发给 BROM/PreLoader 的一段程序，由 SoC 执行，负责实际读写存储。流程：

```
主机 → 发握手序列（A0 0A 50 05）
设备 → 回取反值（5F F5 AF FA）        ← 本机实测：回的是原值，说明是回环
主机 → 发 DA
设备 → 校验 DA 签名（DAA）
        ├─ 通过 → 加载执行，进入可读写状态
        └─ 失败 → 返回 0x7024
```

DA 必须由**该厂商的私钥**签名。所以「MTK 公钥的 AllInOne DA」在这台 OPPO 上必然被拒——这不是配置错误，是密码学上的不可能。

本项目实测过的 DA 组合与结果见 `03-preloader-da.md`。

---

## 6. 一句话总结

> MTK 的安全不是「一道锁」，而是**三级火箭式的接力校验**：BROM 校验 PreLoader，PreLoader 校验 LK，LK 校验 boot。每一级失败都会停在自己那一层。
>
> 厂商最容易做、也最有效的一件事，就是在 LK 里**不实现 fastboot**——因为 fastboot 是唯一不需要「先写入」的入口。堵住它，整个链条就只剩需要写入的入口，而写入又需要先突破链条。
