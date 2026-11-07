# KernelSnitch 在 PEYM00 / MT6893 / 4.19 的可行性评估

> 2026-11-07｜对象：OPPO K9 Pro `PEYM00` / MT6893 / Linux `4.19.191+` / Android 13
> 目的：判定上游 GhostLock 的纯用户态侧信道 `kernelsnitch` 能否打破
> 「任意写 ↔ KASLR slide」的死循环。
> **纯本地静态分析，未上机、未运行任何 exploit。**

---

## 零、一句话结论

**技术上可行，但泄的不是我们要的东西。**

`kernelsnitch` 不需要任何内核漏洞，只靠 `futex` + `rdtsc` 就能拿到**本进程 `struct mm_struct`
的内核虚拟地址**。但 `mm_struct` 位于 **linear map**，其随机化来自 KASLR seed 的高 16 位；
而我们缺的 kernel text slide 来自 **同一 seed 的低 21 位**。两段位不相交、互相独立。

⇒ 即使 `kernelsnitch` 100% 成功，**slide 仍然未知**，阶段 2c 的「没有可钉的地址」不变。

---

## 一、原理（读上游源码得出，不是推测）

### 1.1 内核侧的被测对象

Linux futex 用一个哈希表管理等待队列，桶数由 CPU 数决定：

```c
/* kernel/futex/core.c */
hashsize = roundup_pow_of_two(256 * num_possible_cpus());
```

哈希 key 是 `union futex_key`，`FUTEX_WAIT_PRIVATE` 时形如：

```c
struct { struct mm_struct *mm; unsigned long address; unsigned int offset; } private;
```

计算用 Jenkins `jhash2`，**initval 取 `key.both.offset`**：

```c
u32 hash = jhash2((u32*)&key->both.word, (sizeof(word)+sizeof(ptr))/4, key->both.offset);
return &futex_queues[hash & (futex_hashsize - 1)];
```

关键点：**hash 里含 `current->mm` 这个内核指针**。同一个用户地址，在不同进程里落到不同桶。

### 1.2 攻击侧的三步

| 步 | 动作 | 依赖 |
|---|---|---|
| 1 | `mmap` 64 GB 虚拟空间，在上面铺满 futex 地址 | 只需 `mmap` |
| 2 | 起 1024 个线程在同一个 futex 上 `FUTEX_WAIT_PRIVATE`，把某个桶「堆起来」 | 只需 `futex` + 线程 |
| 3 | 用 `rdtsc` 测量 `FUTEX_WAKE_PRIVATE(0)` 的耗时；落在同一桶的地址会明显变慢 | 只需计时 |

于是得到一组**互相冲突**（同桶）的用户地址。再暴力枚举候选 `mm`：

```c
/* 候选 mm 若让这组地址仍全部同桶，就是真的 mm_struct */
static int32_t __mm_candidate_matches(ks, candidate) {
    for (i = 1; i < ks->collisions; ++i)
        if (futex_hash_context_bucket(&ks->futex_hash, ks->futex_addrs[0], candidate) !=
            futex_hash_context_bucket(&ks->futex_hash, ks->futex_addrs[i], candidate))
            return 0;
    return 1;
}
```

扫描范围 `IDENTITY_START..IDENTITY_END`，步进 = `mm_struct` slab 大小，三次嵌套
（`COARSE_SZ = 1GB` 粗分 → slab → 对象）。

**全程零漏洞：只用 `futex` / `mmap` / `pthread` / `rdtsc`。**

---

## 二、本机前提逐项实测

| 前提 | 上游假设 | 本机实测 | 结论 |
|---|---|---|---|
| `futex_hashsize` | `roundup_pow_of_two(256 * cpus)` | `futex_init` 汇编 `lsl w8,w0,#8` + `clz` 推出 = **2048** | ✅ 一致 |
| `num_possible_cpus` | 由 `sysconf(_SC_NPROCESSORS_CONF)` 取 | `CONFIG_NR_CPUS=8` | ✅ 8 |
| `IDENTITY_START/END` | ARM `VA_BITS=39` 走 `KERNELSNITCH_IDENTITY_*` | `0xffffffbe00000000` ~ `0xffffffc400000000` | ✅ 24 GB，正是上游注释的窗口 |
| `MM_STRUCT_SIZEOF` | 调用方传入 | `proc_caches_init` 实测 `0x398` | ✅ 已有 |
| `g_direct_map_end` | 由「address space layer」测得 | `DIRECT_MAP_END = 0xffffffc400000000` | ⚠️ 该 layer 在 GhostLock 里本身依赖 physrw |

`futex_init` 关键反汇编（`0xffffff800a081fa0`）：

```
ldrb w0, [x8, #0xb50]     ; possible cpus
bl   num_possible_cpus
lsl  w8, w0, #8           ; * 256
sub  x8, x8, #1
clz  x8, x8
lsl  x2, x19, x8          ; roundup_pow_of_two -> 2048
```

参数顺序也对得上：`x0="futex"`、`x1=0x40`(桶大小)、`x2=2048`(numentries)、
`x5=&futex_shift`、`x7=2048`(low_limit)、`[sp]=2048`(high_limit)。

**所以「表太小跑不了」这个担忧不成立，本机是标准 2048 桶。**

---

## 三、关键否证：它给的地址不是我们要的地址

### 3.1 两个随机量各自取哪几位

反汇编本机 `kaslr_early_init`（`0xffffff800a076bac`）得到：

```
0xffffff800a076cbc  lsr  x10, x20, #0x30        ; seed >> 48
0xffffff800a076cc8  strh w10, [x22]             ; -> memstart_offset_seed（半字）
0xffffff800a076d00  and  x11, x20, #0x1fffff    ; seed & 0x1fffff
0xffffff800a076d0c  mul  x9, x11, x9
0xffffff800a076d10  add  x8, x8, x9, lsr #21    ; -> kernel text offset
```

| 随机量 | 影响什么 | 取自 seed |
|---|---|---|
| `memstart_offset_seed` | **linear map / direct map** 的物理起点 | **高 16 位**（`seed >> 48`） |
| `offset`（slide） | **kernel text / .data** 的虚拟地址 | **低 21 位**（`seed & 0x1fffff`） |

两段位**完全不相交**。

### 3.2 因此

`mm_struct` 是 direct map 里的 slab 对象，它的 VA：

```
mm_va = PAGE_OFFSET + (phys - memstart_addr)
```

`PAGE_OFFSET` 是编译期常量 `0xffffffc000000000`，`memstart_addr` 含 `memstart_offset_seed`。
所以 `mm_va` 只泄漏 **seed 高 16 位**。而 slide 需要 **seed 低 21 位**。

**知道 mm_va 推不出 slide。** 这不是精度问题，是信息不在里面。

### 3.3 补充：也不能靠 direct map 别名绕

拿 `mm_va` 只能得到 `phys - memstart` 这个差值。要访问 kernel text 的物理页，
还得知道 `text_phys`，而 `text_phys` 本身带 slide。两个未知量一个也没消。

---

## 四、唯一真实价值

虽然解决不了 slide，`kernelsnitch` 能给**第一个可信的内核地址**，可用于：

| 用途 | 价值 |
|---|---|
| 阶段 2c 的 C2 门槛（PI write 的 `parent` 必须可读） | ✅ 直接满足 |
| 缩小 brute force 范围 | 有限 |
| 作为 physrw 的跳板（若能在 mm_struct 附近构造对象） | 未验证，且仍需 slide 才能碰 text |

也就是说：**它能把 C2 从「挑个可读地址」变成「有确定地址」，但不推进主瓶颈。**

---

## 五、附带确认的两条否定结论

### 5.1 KPTI 被强制打开

`unmap_kernel_at_el0`（`0xffffff8008098418`）的判据：

```
ldr x8, [kimage_vaddr]
mov x9, #-0x8000000000 ; movk x9,#0x800,lsl#16   -> KIMAGE_VADDR
cmp x8, x9
b.eq skip
add x20, x20, #0x5bc        ; 原因串偏移
str w8(=1), [kpti_forced]
```

常量读出：`0x9f045a3="kpti command line option"`、`0x9f045bc="KASLR"`、
`0x9d0734a="mitigations=off"`、`0x9ed450b="ON"`。

设备日志命中 `kernel page table isolation forced ON by KASLR` ⇒
`kimage_vaddr != KIMAGE_VADDR` ⇒ **slide ≠ 0，且 KPTI 同时开启**。
（`CONFIG_UNMAP_KERNEL_AT_EL0=y`、`RANDOMIZE_BASE=y`、`RANDOMIZE_MODULE_REGION_FULL=y`）

### 5.2 seed 位段分离也解释了「为什么这条路注定绕不出来」

只要 slide 只由 seed 低 21 位决定，任何只观测 linear map 的侧信道都拿不到它。
要破这个局，需要的是能**直接测 text 段**的侧信道（例如 prefetch 时序扫 `.text` 映射），
而不是 futex hash 这类以 `mm` 为 key 的信道。

---

## 六、建议

| 选项 | 判断 |
|---|---|
| 在 4.19 上实现 `kernelsnitch` | 能做，但**对主瓶颈无帮助**，不建议投时间 |
| 找「能测 text 段映射」的侧信道 | 理论正确方向，但 4.19/ARM64/PAN+KPTI 下难度极高，属研究级 |
| 放弃内核路线 | **建议**，见 `评估-破端口preloader.md` |

证据与产物：
- `boot/kelf.py`（ELF/反汇编基座）
- 本文件所引反汇编均可用 `kelf.py` 复现：`futex_init` OFF `0x2001f80`、
  `kaslr_early_init` OFF `0x1f76bac`、`unmap_kernel_at_el0` OFF `0x18418`
