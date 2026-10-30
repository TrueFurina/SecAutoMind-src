#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_ci_files_tracked_test.py —— 门禁自测（不联网、不改仓库）。

判据：
  T1  `python scripts/a.py` → 抽出 scripts/a.py
  T2  带引号路径（含空格）也能抽出
  T3  `python -m pip install` / `python -c ...` 不是文件，必须跳过
  T4  含 `$`/`{}`/通配符的一律跳过（静态判不了，不许误报）
  T5  bash / node / go run 三种形态
  T6  find_missing 用假 tracked 集合判定
  T7  **变异验证**：把提取函数换成「什么都不抽」，T1 必须失败（证明 T1 非恒绿）

用法：python scripts/check_ci_files_tracked_test.py    # 0=全过
"""
from __future__ import annotations

import sys

sys.path.insert(0, "scripts")
import check_ci_files_tracked as C  # noqa: E402

passed = failed = 0


def ok(n: str) -> None:
    global passed
    passed += 1
    print(f"  [PASS] {n}")


def bad(n: str, d: str = "") -> None:
    global failed
    failed += 1
    print(f"  [FAIL] {n}{('：' + d) if d else ''}")


# ── T1 ──────────────────────────────────────────────────────────────────────
got = [p for p, _ in C.extract_paths("run: python scripts/a.py")]
if got == ["scripts/a.py"]:
    ok("T1 抽出 scripts/a.py")
else:
    bad("T1 提取错误", repr(got))

# ── T2 引号路径 ─────────────────────────────────────────────────────────────
got = [p for p, _ in C.extract_paths('run: python "CTF-Agent/子目录/b.py"')]
if got == ["CTF-Agent/子目录/b.py"]:
    ok("T2 带引号路径可抽出")
else:
    bad("T2 引号路径提取错误", repr(got))

# ── T3 跳过 -m / -c ─────────────────────────────────────────────────────────
got = [p for p, _ in C.extract_paths(
    "run: python -m pip install x\nrun: python -c 'print(1)'\nrun: python3 -m venv v")]
if got == []:
    ok("T3 python -m / -c 被跳过（不是文件）")
else:
    bad("T3 把 -m/-c 当成了文件", repr(got))

# ── T4 变量与通配符 ─────────────────────────────────────────────────────────
got = [p for p, _ in C.extract_paths(
    "run: python ${{ matrix.dir }}/x.py\nrun: python scripts/$NAME.py\nrun: bash scripts/*.sh")]
if got == []:
    ok("T4 含 $/{}/* 的一律跳过（不误报）")
else:
    bad("T4 变量/通配符被当成文件", repr(got))

# ── T5 其它解释器 ───────────────────────────────────────────────────────────
got = [p for p, _ in C.extract_paths(
    "run: bash scripts/s.sh\nrun: node tools/n.js\nrun: go run ./cmd/liverange")]
if got == ["scripts/s.sh", "tools/n.js", "cmd/liverange"]:
    ok("T5 bash / node / go run 三种形态")
else:
    bad("T5 其它解释器提取错误", repr(got))

# ── T6 find_missing ─────────────────────────────────────────────────────────
paths = [("scripts/a.py", 1), ("scripts/b.py", 2)]
miss = C.find_missing(paths, {"scripts/a.py"})
if miss == [("scripts/b.py", 2)]:
    ok("T6 find_missing 只报未跟踪的那个")
else:
    bad("T6 find_missing 错误", repr(miss))

# ── T7 变异验证 ─────────────────────────────────────────────────────────────
_orig = C.extract_paths
C.extract_paths = lambda _t: []
try:
    if [p for p, _ in C.extract_paths("run: python scripts/a.py")] != ["scripts/a.py"]:
        ok("T7 变异验证：提取函数返回空会让 T1 失败（T1 非恒绿）")
    else:
        bad("T7 变异未生效", "T1 可能是恒绿的")
finally:
    C.extract_paths = _orig

print("-" * 60)
if failed == 0:
    print(f"结论：PASS —— {passed} 项全过（含 1 项变异验证）")
    sys.exit(0)
print(f"结论：FAIL —— {failed} 项未过")
sys.exit(1)
