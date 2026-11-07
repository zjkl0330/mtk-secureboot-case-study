# PEYM00 4.19 内核 —— 偏移表 / 利用链复用包（reuse-kit）

> 对象：OPPO K9 Pro `PEYM00` / MT6893 / Android 13 / Linux `4.19.191+`
> 生成：2026-11-07，离线静态分析产物；**本包不含任何运行时 exploit，不触碰设备**。

## 这个包解决什么

之前在 `k9pro/` 下把 GhostLock（CVE-2026-43499）的偏移表从 127 宏补到 239 宏、独立复核 49 项全 PASS，
并写完了整条利用链的方法论。结论是：**五条提权路线全部走完/判死**（见 `../路线总账.md`），
但偏移表和链路框架本身对「这个 4.19 内核将来出现新公开漏洞」是可复用的。

本包把那个「可复用」落成现实：

| 内容 | 位置 | 说明 |
|---|---|---|
| 锁定偏移表（239 宏，49 项复核 PASS） | `offsets/target-PEYM00.h` | 直接当 `TARGET_CONFIG_H` 用 |
| 机器可读清单 | `offsets/offsets-PEYM00.json` | 给脚本/校验用 |
| 利用链方法论模板 | `chain/利用链-4.19-PEYM00.md` | 端到端 0–7 阶段，含三条 write route 量法、KASLR 定案 |
| 可重跑提取管线 | `pipeline/` | `kelf→ksymtab→frames→gen_target→verify`，已去硬编码、路径可移植 |
| 新 CVE 复用操作手册 | `REUSE-GUIDE.md` | 照做 5 步即可重算偏移 + 接入新漏洞原语 |
| 原始证据索引 | `evidence/EVIDENCE.md` | 指向 `../boot/` 里的 bugreport / 反汇编留档（不重复拷贝 41MB） |

## 复用方式（最短路径）

```bash
cd reuse-kit/pipeline
python gen_target.py     # 从 ../boot 重算偏移表 → offsets/
python verify_target.py  # 独立复核，必须 PASS 49 / FAIL 0
```

若要给**新内核/新 OTA** 用，把新提取的 `vmlinux.elf/.bin`、`device-*.txt`、`boot.img`
放进 `reuse-kit/inputs/`（或设环境变量 `K9_INPUT_DIR`），再跑上面两步即可。详见 `REUSE-GUIDE.md`。

## 关键结论（防止重复劳动）

- 本机 `KASLR` 实测**开着**（slide≠0、KPTI 强制），所有静态 OFF 运行时必须叠加 slide。
- `CONFIG_KALLSYMS_ALL=n` → 数据符号只能静态挖 `__ksymtab`（已还原 12649 条，94.1% 自校验）。
- 地址空间 `VA_BITS=39`：`VA_START 0xffffff8000000000`、`PAGE_OFFSET 0xffffffc000000000`、`P0_KERNEL_PHYS_LOAD 0x40080000`。
- 已踩坑（旧表/P40 对照的错误）：`P0_PAGE_OFFSET` 不是 `0xffffff8000000000`；pipe 是 4.19 RING 非 K40 legacy；`task_struct` 相对 K40 后半段整差 `-0x80`；`do_futex` 帧是 `0x210` 非 `0x60`。
