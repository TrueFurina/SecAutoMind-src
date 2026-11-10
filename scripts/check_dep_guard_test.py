#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_dep_guard_test.py —— 门禁自测入口。

CI 在跑主门禁**之前**先跑本文件：变异自测证明「判据确实能变红」，
否则一道永远绿的判据比没有判据更糟（本项目已多次踩到正则被注释骗的坑）。

两种运行方式都支持：
    python scripts/check_dep_guard_test.py        # CI / 命令行
    pytest 收集到 test_dep_guard_selftest_must_pass  # 模块顶层不退出，安全

主脚本用 importlib 按同目录加载，不依赖 sys.path 或 cwd。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_MAIN = Path(__file__).with_name("check_dep_guard.py")
_spec = importlib.util.spec_from_file_location("check_dep_guard", _MAIN)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def test_dep_guard_selftest_must_pass() -> None:
    """变异自测必须全 PASS：判据能变红，才允许用它判仓库绿。"""
    assert _mod.selftest() == 0


if __name__ == "__main__":
    raise SystemExit(_mod.selftest())
