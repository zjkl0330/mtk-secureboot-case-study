# -*- coding: utf-8 -*-
"""paths.py — 复用包内统一输入/输出路径解析（让管线摆脱硬编码绝对路径）。

输入目录（放 vmlinux.elf / vmlinux.bin / ksymtab.json / device-*.txt / boot.img）：
  优先级：环境变量 K9_INPUT_DIR → 当前工作目录 → <root>/inputs → <root>/../boot → pipeline 自身目录
  （<root> = reuse-kit/，即本文件的上一级目录）

输出目录：<root>/offsets （target-PEYM00.h / offsets-PEYM00.{h,json} 落这里）

之所以默认回退到 ../boot：本机冷冻输入仍留在 k9pro/boot/，复用包不重复拷贝 41MB 的
vmlinux.elf / 32MB 的 boot.img；换一台机器或换一个新内核时，把新内核提取产物放进
<root>/inputs/（或设 K9_INPUT_DIR）即可，管线无需改动。
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # reuse-kit/
HERE = os.path.dirname(os.path.abspath(__file__))                  # pipeline/


def input_root():
    env = os.environ.get("K9_INPUT_DIR")
    if env:
        return os.path.abspath(env)
    cands = [
        os.getcwd(),
        os.path.join(ROOT, "inputs"),
        os.path.join(ROOT, "..", "boot"),
        HERE,
    ]
    for c in cands:
        if os.path.isfile(os.path.join(c, "vmlinux.elf")) or \
           os.path.isfile(os.path.join(c, "vmlinux.bin")):
            return os.path.abspath(c)
    # 都没找到也给出一个默认，让报错信息更明确
    return os.path.abspath(os.path.join(ROOT, "..", "boot"))


def ipath(name):
    """输入文件绝对路径。"""
    return os.path.join(input_root(), name)


def opath(name):
    """输出文件绝对路径，必要时创建 offsets/ 目录。"""
    d = os.path.join(ROOT, "offsets")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)
