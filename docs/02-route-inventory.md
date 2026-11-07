# PEYM00（OPPO K9 Pro / MT6893 / 内核 4.19.191）解锁与提权 —— 路线总账

> 生成时间：2026-11-07 17:5x
> 设备：`<DEVICE_SN>`，Android 13，`OPPO/PEYM00/OP5245:13/TP1A.220905.001/R.233ce9b-1:user/release-keys`
> 内核：`4.19.191+`，编译于 `Thu Apr 2 17:07:29 CST 2026`
> 锁状态：`ro.boot.flash.locked = 1`，`verifiedbootstate = green`，`veritymode = enforcing`

## 一句话

**五条技术路线全部走完或判死，没有一条能产出 root。剩下的是非技术路线。**

---

## 总账

| # | 路线 | 状态 | 封死原因（一句话） | 证据 |
|---|---|---|---|---|
| 1 | **GhostLock / CVE-2026-43499**（内核 futex PI UAF） | ❌ 静态判死 | 三条 write route 在 4.19 全部擦边；即便有 `tree_entry` 钉子，KASLR slide 与写原语互为前置 | `利用链-4.19-PEYM00.md`、`_feas.txt`、`_routes419*.txt`、`_mcast_*.txt` |
| 2 | **fastboot 刷 fastboot 版 preloader** | ❌ 实测封死 | 锁 BL，且 bootloader 根本不向主机暴露可用的 fastboot 接口 | `评估-破端口preloader.md` §3.5.2 |
| 3 | **`adb reboot edl` + mtkclient** | ❌ 握手被拒 | PreLoader 的 SLA/DAA：端口能开，DA 下载握手 `Handshake failed` ×34 | `评估-破端口preloader.md` §3.5.3、`boot/_mtk_handshake.txt` |
| 4 | **短接/按键进真 BROM** | ❌ 无效 | MT6893 的 BROM 已带 SLA/Secure Boot；kamakiri 只覆盖 2019 年前平台 | 用户判定 + 平台代际事实 |
| 5 | **换工具（AxManager / Shizuku）** | ⚠️ 不解决问题 | 它们跑在 uid 2000（shell），上限就是 shell；「让它提权」= 提权本身 | 前轮分析 |
| 6 | **OPPO 官方深度测试** | ⬜ 未评估 | 唯一还没认真评估的合法路径 | — |
| 7 | **PEYM00 专用强解 / 售后工具** | ⬜ 未评估 | 需第三方服务或授权工具，成本与可信度未知 | — |

---

## 路线 1 的完整死因（三层，缺一不可）

```text
漏洞存在（✅ 四条代码形态全匹配）
   ↓
① 注入原语：可控数据要落在 waiter 的 tree_entry（+0x00..0x18）
   ├─ select_stack   : W=19 > 7，差 96 字节            ❌
   ├─ tcp_zerocopy   : 4.19 结构只有 0x18，装不下 0x50  ❌
   └─ multicast      : 覆盖到 waiter+0x20，差 16 字节
        → 但 tree_entry 全在覆盖区，构成 1 次 4 字节对齐的 8 字节写 ✅
   ↓
② KASLR slide：写入位置 = parent+8，需要知道真实运行时地址
   └─ 已实测确认 KASLR 开启（unmap_kernel_at_el0 分支 + KPTI forced ON）
      且 text slide 取 seed 低 21 位、linear map 取高 16 位，两段独立
      ⇒ kernelsnitch 给的是 mm_struct（linear map），推不出 slide ❌
   ↓
③ 循环死锁：
   写 ashmem_misc.fops（建 physrw）→ 需要 slide
   读 kimage_voffset（得 slide）→ 需要 physrw
```

**注意**：偏移表本身是完整的（`target-PEYM00.h`，239 个 `#define`，49 项独立复核全 PASS）。
卡的不是数据，是原语和地址。这两项都是「还没解的研究问题」，不是工程量。

---

## 路线 2/3/4 的死因（两个不同层面）

| 层 | 保护 | 能否绕过 |
|---|---|---|
| bootloader（fastboot） | `flash.locked = 1` + 不暴露 fastboot 接口 | ❌ 实测无接口可用 |
| PreLoader（EDL `PID 0006`） | SLA/DAA 握手认证 | ❌ 34 次握手全失败 |
| BROM（`PID 0003`） | SLA/Secure Boot（MT6893 已修 kamakiri） | ❌ 无公开绕过 |

三者是**同一个东西的三层包装**：MTK 的 Secure Boot 链。
「破端口 preloader」的作用是把 PreLoader 层的认证拆掉，
**但刷它本身又需要一次成功握手** —— 鸡生蛋，无解。

---

## 真正剩下的选项

### A. OPPO 官方深度测试（唯一合法路径）

OPPO/一加 的「深度测试」是官方的 BL 解锁申请通道。通过后可以正常 `fastboot flashing unlock`，
之后 root 是常规工程问题（Magisk / KernelSU / APatch）。

需要确认的现状（**本文件未核实**）：
- PEYM00 是否在深度测试支持机型列表内
- 当前 ColorOS 13 版本的申请资格与名额窗口
- 申请通过后是否仍需等待、是否有次数限制

### B. PEYM00 专用强解 / 售后工具

第三方服务（淘宝、售后授权工具）能直接解锁，但：
- 成本与可信度未知
- 需要把设备交给别人操作
- 可能影响保修

### C. 接受「没有 root，但有 shell 级深度控制」

AxManager / Shizuku 这条线不属于「提权」，但对日常需求覆盖度很高：
禁自启、改系统设置、跑脚本、给 app 授权、组件拦截。
**上限明确是 uid 2000，不能改内核、不能写系统分区、不支持 LSPosed。**

---

## 项目资产清单（保留，勿删）

| 资产 | 说明 |
|---|---|
| `reuse-kit/` | ** Consolidated 复用包**：`offsets/target-PEYM00.h`（239 宏，49 项复核 PASS）+ `pipeline/`（已去硬编码、可重跑的提取管线）+ `REUSE-GUIDE.md`（新 CVE 复用 5 步操作手册）+ `chain/利用链-4.19-PEYM00.md` |
| `boot/target-PEYM00.h` | 完整设备头，239 个 `#define`，49 项复核 PASS（与 `reuse-kit/offsets/` 同源） |
| `boot/verify_target.py` | 独立复核器（已复制到 `reuse-kit/pipeline/`） |
| `boot/offsets-PEYM00.json` | 机器可读 OFF 清单 |
| `利用链-4.19-PEYM00.md` | 端到端链路文档，阶段 0–7 + 全部实测数据 |
| `偏移提取-结果.md` | 第一轮证据报告 + 第十节补完记录 |
| `评估-kernelsnitch.md` | 侧信道可行性评估 |
| `评估-破端口preloader.md` | preloader 方案 + 上机实测记录 |
| `da/*.img|bin` | 官方/破端口 preloader、LK、4MB 分区备份 |
| `boot/*.txt` | 全部反汇编与实测原始输出 |
| `boot/bugreport/*.zip` | 13 MB bugreport，含 11 份 MTK 内核日志 |

这些资产的价值：**如果将来这个内核出现新的公开漏洞，偏移表和利用链可以直接复用**。
`target-PEYM00.h` 的 239 个宏不是只给 GhostLock 用的。复用闭环见 `reuse-kit/REUSE-GUIDE.md`：
`cd reuse-kit/pipeline && python gen_target.py && python verify_target.py`（已实跑验证 PASS 49 / FAIL 0）。

---

## 状态声明

截至本文件生成：
- 未刷写任何分区
- 未解锁 BL
- 未安装任何 APK
- 未运行任何 exploit
- 所有设备操作仅为「重启 + 读属性」
