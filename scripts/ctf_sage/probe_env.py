#!/usr/bin/env python3
"""probe_env — ctf_sage 模板库环境软探测（P0-1，2026-10-25）。

用途：给 runner/agent 的赛前预检与运行期降级判定提供机器可读事实——
「当前环境能不能跑模板库、缺什么、缺了退化成什么」。**只读探测，不装任何东西**。

探测面：
  1. Python 版本
  2. 可选依赖：sage / gmpy2 / flint / fpylll / numpy / sympy / pwntools
     （sage 走子进程 `sage -c`，启动慢，单独 20s 超时；其余 import 探测）
  3. 六个模板 + common 的可导入性（纯 Python 自包含是设计目标，缺可选依赖
     不应影响导入——numpy 缺失时 t1 自动退化为暴力/精确验证路径）

退出码（调用方按此降级，fail-closed）：
  0 = 六模板全部可导入（完全就绪）
  1 = 有模板不可导入（退化：该模板不可用，其余照常；调用方应按 detail 处理）
  2 = 探测自身失败（Python 环境坏）

输出：stdout 一个 JSON（--pretty 时缩进）；stderr 只放探测过程的警告。
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

SAGE_TIMEOUT_SEC = 20

# (显示名, import 名)；sage 特殊处理（子进程探测）
OPTIONAL_DEPS = [
    ("gmpy2", "gmpy2"),
    ("flint", "flint"),
    ("fpylll", "fpylll"),
    ("numpy", "numpy"),
    ("sympy", "sympy"),
    ("pwntools", "pwn"),
]

TEMPLATE_MODULES = [
    "common",
    "t1_coppersmith",
    "t2_ecdsa_hnp",
    "t3_truncated_lfsr",
    "t4_boneh_durfee",
    "t5_dlp_bsgs_ph",
    "t6_hastad_broadcast",
]


def probe_sage() -> dict:
    """sage 探测：优先 `sage -c`，找不到命令则报 missing（不视为错误）。"""
    t0 = time.time()
    try:
        proc = subprocess.run(
            ["sage", "-c", "print(version())"],
            capture_output=True, text=True, timeout=SAGE_TIMEOUT_SEC,
        )
    except FileNotFoundError:
        return {"available": False, "detail": "sage 命令不在 PATH"}
    except subprocess.TimeoutExpired:
        return {"available": False, "detail": f"sage 启动超过 {SAGE_TIMEOUT_SEC}s"}
    if proc.returncode == 0:
        return {"available": True, "detail": proc.stdout.strip()[:80],
                "elapsed_ms": int((time.time() - t0) * 1000)}
    return {"available": False, "detail": f"rc={proc.returncode}: {proc.stderr.strip()[:120]}"}


def probe_import(name: str) -> dict:
    try:
        found = importlib.util.find_spec(name) is not None
    except Exception as exc:  # noqa: BLE001 —— 坏包的 __init__ 抛错不该炸掉探测
        return {"available": False, "detail": f"find_spec 异常: {type(exc).__name__}: {exc}"}
    if not found:
        return {"available": False, "detail": "未安装"}
    try:
        mod = __import__(name)
        ver = getattr(mod, "__version__", "?")
        return {"available": True, "detail": str(ver)}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "detail": f"导入失败: {type(exc).__name__}: {exc}"}


def main() -> int:
    pretty = "--pretty" in sys.argv
    sage_dir = Path(__file__).resolve().parent
    if str(sage_dir) not in sys.path:
        sys.path.insert(0, str(sage_dir))

    report: dict = {
        "python": sys.version.split()[0],
        "sage_dir": str(sage_dir),
        "deps": {},
        "templates": {},
    }

    report["deps"]["sage"] = probe_sage()
    for display, mod in OPTIONAL_DEPS:
        report["deps"][display] = probe_import(mod)

    broken = []
    for name in TEMPLATE_MODULES:
        info = probe_import(name)
        report["templates"][name] = info
        if not info["available"]:
            broken.append(name)

    report["degraded"] = broken
    report["summary"] = (
        "完全就绪（六模板可导入）" if not broken
        else f"退化：{', '.join(broken)} 不可用（缺可选依赖时模板库应仍可导入，"
             "此处不可用 = 真问题，按 detail 查）"
    )

    text = json.dumps(report, ensure_ascii=False, indent=2 if pretty else None)
    print(text)
    return 0 if not broken else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 —— 探测自身坏掉必须显式非零
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        sys.exit(2)
