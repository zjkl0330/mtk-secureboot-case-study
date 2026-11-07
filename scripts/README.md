# scripts · 探测与验证脚本

> 本目录的脚本**全部为只读探测**：不写分区、不刷镜像、不改设备。
>
> 唯一例外是 `mtk/` 下的 payload 尝试（`run_payload.py`），它会调用 mtkclient 的 payload 命令——在本机上该命令因通道不可用而失败，未对设备造成任何写入。使用前请自行评估风险。

## 环境

```bash
pip install pyserial pyusb
# fastboot / adb 需在 PATH（本项目使用 platform-tools 37.0.1）
```

---

## probe/ · 通道真伪判定（最实用）

### `echo_check.py` ★

判断一个 MTK VCOM 端口是**真协议**还是**假回环**。

```bash
python echo_check.py            # 默认 COM6
```

输出判读：

```
send a0           -> recv 5f      ← 真协议（取反），可以继续
send a0           -> recv a0      ← 回环，此路不通，立即停止投入
send 11 22 33 44  -> recv 11 22 33 44   <== 原样回显(loopback)
VERDICT: PURE LOOPBACK
```

> 原理：MTK 的握手是「主机发 X，设备回 ~X」。回原值说明对面只是个 echo。

### `serial_probe.py`

握手序列的对照实验：带 `0xA0` 唤醒字节 vs 不带，各跑两轮。用于排查「是不是缺唤醒字节」这类问题。

### `port_watch.py`

监测指定 COM 口的存在状态，记录每次翻转的时间戳。

```bash
python port_watch.py
```

用途：确认「设备是否真的断电重连过」。如果操作后日志是 `flips=0`，说明设备根本没断过——你测的还是旧连接。

---

## fastboot/ · LK 是否有 fastboot 接口

### `chain.sh` ★

判定「设备能不能停在 bootloader」的标准手法：

1. 等设备回系统
2. `adb reboot fastboot` 进 fastbootd
3. `fastboot reboot bootloader` 试图跳真 bootloader
4. **立刻用阻塞的 `getvar all` 占住 90 秒**

判读：
- 90 秒内有响应 → LK 实现了 fastboot，有戏
- 全程 `< waiting for any device >` → 设备没停在那里，此路不通

### `hot_wait.py` / `fb_poll.sh`

毫秒级轮询并抢连 fastboot 接口。用于捕捉极短的窗口。

### `fb.py` / `fb2.py` / `fb_winusb.py` / `fb_reset.py`

不依赖 `fastboot.exe`，直接用 libusb / 原生 WinUSB 构造 fastboot 协议包（`getvar:` 命令）。

适用场景：`fastboot devices` 列不出设备，但你知道它就是 fastboot 接口（可通过接口描述符 `Class_FF/SubClass_42/Prot_01` 判断）。

> 注意：Windows 上 adb server 会独占 USB 接口句柄，导致 `claim_interface` 报 `Access denied`。这是权限问题，不是设备问题。

---

## mtk/ · PreLoader 抢连

### `run_payload.py`

`adb reboot edl` 后轮询串口，一旦出现立刻执行 `mtk.py payload`（该命令内部自带 crash 到 BROM 的步骤）。

```bash
python run_payload.py
```

需要修改脚本顶部的 `MTK_DIR` 为你的 mtkclient 路径。

### `watch_port_and_crash.py` / `auto_crash.sh`

检测到设备回到系统或出现端口时，自动触发 `mtk.py crash`。

> `crash` 的作用是让 PreLoader 崩溃，试图回落 BROM。本机从未成功（通道是回环）。

---

## 已知限制

| 限制 | 说明 |
|---|---|
| 硬编码端口 | 多数脚本默认 `COM6`，使用前按需修改 |
| Windows 路径 | 脚本内路径为作者环境（`F:\root\...`），移植需调整 |
| adb 授权 | 设备需先 `adb devices` 显示 `device`（不是 `unauthorized`） |
| 依赖 mtkclient | `mtk/` 下脚本需要 mtkclient 2.1.x |

---

## 安全提示

- 这些脚本的定位是**判定**，不是**操作**。它们回答「这条路通不通」，不负责「走通它」。
- 任何涉及写入分区的操作都不在本仓库范围内。
- 在自己拥有的设备上使用；刷写分区有变砖风险。
