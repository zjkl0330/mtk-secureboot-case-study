# OPPO K9 Pro 解 BL —— 重启后继续

> 重启原因：UsbDk 内核驱动需完整初始化，之前服务状态在 Running/Stopped 间抖动，导致 libusb 抓不到 Preloader。

## 一、当前进度

| 阶段 | 状态 |
|---|---|
| adb/fastboot 环境 | ✅ 完成 |
| 设备基线采集 | ✅ 完成 |
| OEM 解锁开关 | ✅ 已开（UI 层 checked=true） |
| UsbDk 驱动 | ✅ 已装，已设 Automatic |
| mtkclient Python 依赖 | ✅ 完成 |
| path_preloader.py | ✅ 已下载校验 |
| OPPO 官方 DA | ✅ 已下载 |
| **BROM/Preloader 握手** | ❌ **卡在这里** |
| 备份 / 补丁 / 回写 / 解锁 | ⏸ 未开始 |

## 二、设备已确认的事实

```
型号      PEYM00 / OP5245
SoC       mt6893 (天玑1200)
系统      Android 13 / ColorOS V13.1.0
版本号    PEYM00_13.1.0.254(CN01)
安全补丁  2026-01-01   编译 2026-04-02
锁状态    flash.locked=1  verifiedbootstate=green
槽位      单槽（slot_suffix 空，ab_update 空）
分区      boot/lk/lk2/bootloader1/bootloader2/seccfg/vbmeta/recovery
          preloader_emmc_a/_b  preloader_ufs_a/_b  preloader_raw_a/_b
```

## 三、重启后第一步

### 1. 确认 UsbDk 自动起来了

```powershell
Get-Service UsbDk | Select-Object Name,Status,StartType
```
期望：`Running  Automatic`

### 2. 启动监听

```bash
cd /f/root/mtkclient-2.1.4.1
python mtk.py gettargetconfig
```

### 3. 手机进 Preloader/BROM

```
完全关机 → 按住 音量上+音量下+电源 三键 → 插线 → 按住至少 10 秒不松手
```

**已证实**：三键能触发 `MediaTek PreLoader USB VCOM_V2023 (COM5)`
（`USB\VID_22D9&PID_0006`，OPPO 自己的 VID，mtkclient 配置里已支持）

窗口只有 1~3 秒，之后手机会继续启动进 Recovery。

## 四、关键发现（排查记录）

| 发现 | 结论 |
|---|---|
| `adb.zip` 内容是 KernelSU 备份（dmesg 显示 Qualcomm Kalama / 骁龙8Gen3） | 与 K9 Pro 无关，不是工具 |
| 两个 `VID_0000&PID_0002` 未知设备 | 集线器 Hub_#0003 的常驻问题设备，拔手机也不消失，与刷机无关 |
| 手机 Preloader 用 `VID_22D9 PID_0006` | 不是标准 MTK 的 0E8D，但 mtkclient 已支持 |
| UsbDk 曾从 Running 掉到 Stopped | **握手失败的真正原因** |
| 三键会进 Recovery | Preloader 窗口已过；必须插线后按住 10 秒不松 |

## 五、技术路线（握手成功后）

**主路线：preloader 补丁**
1. 备份：`mtk.py r seccfg seccfg.bin` + `r preloader boot1/boot2 --parttype=boot1/boot2`
2. 打补丁：`python path_preloader.py boot1.bin`（单槽写 boot1）
3. 回写：`mtk.py w preloader preloader_path/boot1.bin --parttype=boot1 --noreconnect`
4. 解锁：`adb reboot bootloader` → `fastboot flashing unlock`

**备选：lk 补丁**（path_preloader 报 exit(6) 时）

## 六、风险红线

- 绝不写 `preloader_raw`
- 改完 preloader 必须永久禁 OTA
- 降级到 A11 **不建议**（ARB 无法验证 + 固件需付费 + 该机型在支持列表标注 Full support 无需降级）

## 七、工具位置

```
F:\root\platform-tools\           adb / fastboot
F:\root\mtkclient-2.1.4.1\        mtkclient + mt6893_payload.bin
F:\root\k9pro\path_preloader.py   补丁脚本
F:\root\k9pro\tools\DA_BR_MT6893.bin    OPPO 官方 DA (805KB)
F:\root\k9pro\recon.txt           只读侦察脚本
F:\root\k9pro\backup.txt          备份脚本
F:\root\k9pro\baseline.txt        设备基线
F:\root\紫罗兰工具箱 V3.3.exe      欧加向刷机工具（含降级助手/刷机资源）
```

---

## 八、2026-11-07 下午：转向 GhostLock 漏洞路线

### 结论：mtkclient 路线已走到尽头

**铁证（Port.py:139）**：
```python
brom_pids = [0x3, 0xF200, 0xD1E9, 0xD1E2, 0xD1EC, 0xD1DD]
if self.cdc.pid not in brom_pids: ep_out(b"\xa0")
```
- 手机 Preloader PID = `0x0006`，不在列表
- 已试过把它加进白名单 → 仍失败
- **根因：OPPO Preloader 不响应 MTK BROM 握手协议（固件层加固）**
- 按键三键只能进 Preloader（PID 22D9:0006），进不了 BROM（PID 0E8D:0003）

### 已解决的驱动问题（全部验证通过）

| 项 | 结果 |
|---|---|
| libusb 1.0.24 不支持 UsbDk | 换 1.0.30，set_option 从 -5 → 0 |
| UsbDk 组件缺失 | 从 MSI 7z 解包，手动补 UsbDkHelper.dll + 服务 |
| UsbDk 1.0.22 与 libusb 1.0.30 接口不兼容 | 判定此路不通 |
| 设备被 MediaTek VCOM 独占 | **Zadig 换成 WinUSB（oem6.inf）成功** |
| 设备现在可被 libusb 枚举和通信 | ✅ |

**驱动层已完全打通，卡在协议层。**

### 新路线：GhostLock (CVE-2026-43499)

- Linux 内核 rtmutex 栈 UAF，**锁 BL 可拿临时 root**
- 4.19 内核无 EOL 回补 → 本机 4.19.191 可能受影响
- 有 MTK6893 先例（Motorola Edge 40）、4.19 先例（Redmi K40）
- 参考仓库：JoinChang/ghostlock-oneplus、YuKongA/ghostlock-app

### 当前阻塞：拿不到 boot.img

| 源 | 状态 |
|---|---|
| Google Drive（flashfilefirmware 的 OTA 6.29GB） | ❌ 三个域名全部 HTTP 000 |
| oplus 官方 OTA 服务器 | ❌ 000 |
| onfix.cn | ⚠️ 需登录，百度网盘/123网盘 |
| azrom.net | ⚠️ 付费（10,000 VND ≈ 3 元） |

OTA 直链（已解析出来）：
`https://drive.google.com/file/d/1BTjM-1CXM5VqcehFjf5rIscMCI38KndT/view`

### 已备好

- `F:/root/k9pro/ota/payload_dumper.py`（可解 payload.bin 提取 boot.img）

### 下一步（需要用户）

1. 用户自行下载 OTA 到 `F:/root/k9pro/ota/`
2. 或用 payload-dumper URL 模式直接从可达链接提取 boot
3. 拿到 boot.img 后分析：`do_futex` 是否被 PGO 内联 → 决定可行性

### 手机状态

**完全没动过。BL 仍锁，数据完好，保修有效。** 全程只读。
