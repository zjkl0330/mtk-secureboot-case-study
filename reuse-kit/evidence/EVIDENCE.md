# 原始证据索引（本包不重复拷贝大文件）

所有一手证据仍在 `k9pro/boot/`。本文件只做索引，避免把 41MB `vmlinux.elf` / 32MB `boot.img` 再拷贝一份。

## 设备实测证据（决定性）
- `../boot/bugreport/bugreport-PEYM00-TP1A.220905.001-2026-11-07-17-01-56.zip`（13 MB）
  - `FS/cache/recovery/last_kmsg*` ×10+：含 `kernel page table isolation forced ON by KASLR` 行 → **KASLR 实测开启、KPTI 强制**。
  - `last_pl_lk`：LK 日志，DTB 物理 `0x47c80000`、`kernel_sz=0x0109d577`、RNG 值（gauge 认证）。

## 内核静态分析留档（反汇编 / 偏移还原）
- `../boot/_dis_waiter.txt` `../boot/_dis_task.txt` `../boot/_dis_pipe.txt` `../boot/_dis_misc.txt` `../boot/_dis_globals.txt` — 关键结构体与指针表反汇编。
- `../boot/_feas.txt` — 栈叠加可行性，得出 `waiter_word=19`、可控上限 `W≤7`、缺口 96B。
- `../boot/_fields2.txt` `../boot/_pin*.txt` `../boot/_pin3.txt` — `task_struct` / 全局符号字段钉死。
- `../boot/_routes419*.txt` `../boot/_mcast_*.txt` `../boot/_rb_probe.txt` — 三条 write route 逐层量化；`remove_waiter` 只读了 `tree_entry` 的钉证。
- `../boot/_spsame*.txt` — `S_FRAME_SIZE=0x140`、入口 sp 恒定、Δ≡0 的翻盘点关闭证明。
- `../boot/_frame.py` `../boot/_frames.txt` — 全函数栈帧测量（修正 `do_futex` 为 `0x210`）。
- `../boot/_dtb_parse.txt` `../boot/_kaslr_check.txt` — dtb 模板 `kaslr-seed=0`、KASLR 分支核验。

## 设备上机实测（封死路线 2/3/4）
- `../boot/_mtk_handshake.txt` — `adb reboot edl` 进 PreLoader VCOM，`mtkclient` 握手 `Handshake failed` ×34。
- `../评估-破端口preloader.md` §3.5 — fastboot 无接口、`ro.boot.flash.locked=1` 实读。

## 管线源（本包已复制并改为可移植）
- `../reuse-kit/pipeline/`：`kelf.py` `ksymtab.py` `frames.py` `gen_target.py` `verify_target.py` `paths.py`
- 原始版本（与 `boot/` 内当前有效版一致）：`../boot/` 同名文件。
