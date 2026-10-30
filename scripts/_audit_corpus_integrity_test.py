#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""⚠️ 本文件已作废 —— 请勿在此路径新增测试。

2026-10-26：我最初把 `_audit_corpus_integrity` 的回归测试误建在仓库根的 `scripts/` 下，
但被测模块实际位于 `CTF-Agent_融合/ctf_agent/scripts/_audit_corpus_integrity.py`，
两者不同根，导致 `from scripts._audit_corpus_integrity import ...` 直接 ModuleNotFoundError。

**正确的测试文件（唯一有效版本）：**
    CTF-Agent_融合/ctf_agent/scripts/_audit_corpus_integrity_test.py

运行方式：
    cd CTF-Agent_融合/ctf_agent
    python scripts/_audit_corpus_integrity_test.py

本文件保留为占位，仅为避免"同一测试存在两份实现"的漂移风险（AGENTS ㉚ 同型问题）。
其内容已替换为转发调用，确保误跑本文件时仍能执行真正的测试，而不是静默通过。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REAL = (Path(__file__).resolve().parent.parent
        / "CTF-Agent_融合" / "ctf_agent" / "scripts" / "_audit_corpus_integrity_test.py")


def main() -> int:
    if not REAL.is_file():
        print(f"[ERROR] 真正的测试文件不存在: {REAL}", file=sys.stderr)
        return 2
    print(f"[info] 转发到唯一有效测试: {REAL}")
    # 用被测模块所在目录作为 cwd，保证 sys.path 与导入根一致
    return subprocess.call([sys.executable, "-u", str(REAL)], cwd=str(REAL.parent.parent))


if __name__ == "__main__":
    sys.exit(main())
