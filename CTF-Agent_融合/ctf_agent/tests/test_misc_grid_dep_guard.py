# -*- coding: utf-8 -*-
"""缺依赖守卫的「可达性」行为测试（2026-11-10）。

`tests/test_rsa_dep_guard.py` 守的是「标志生效时要告警」；本文件守的是更前面一层：
**标志本身能不能生效**。原实现把 numpy/PIL 放在模块级硬导入，又在 try 里重复
import 一次只为设 HAS_DEPS —— 缺依赖时模块在第 21 行就抛 ImportError，
`run()` 里的 `if not HAS_DEPS` 永远走不到。用 monkeypatch 把 HAS_DEPS 置 False
的测试看起来全绿，却证明不了真实缺依赖时模块还能被导入（判据测文字不测行为）。

所以这里在**独立子进程**里用 import hook 真屏蔽 numpy/PIL，验证：
  1. 模块仍可导入（不炸在模块级 import）；
  2. HAS_DEPS 为 False，run() 返回可机器区分的 reason=dependency_missing；
  3. 告警恰好一次，且措辞点明「不是解不出，是能力不存在」。
另有一条一致性测试：HAS_DEPS 必须等于 numpy/PIL 的真实可导入性，
防止有人为了让测试变绿把标志写死。

本文件顶层不 import skill 本身，因此不依赖 numpy/PIL 是否真的装着。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_SKILL_FILE = Path(__file__).resolve().parents[1] / "skills" / "misc_grid_resample.py"

_BLOCKED_PROBE = r'''
import builtins, importlib.util, sys
_real = builtins.__import__

def _blocked(name, *args, **kwargs):
    if name.split(".")[0] in ("numpy", "PIL"):
        raise ImportError("blocked by dep-guard probe: " + name)
    return _real(name, *args, **kwargs)

builtins.__import__ = _blocked
spec = importlib.util.spec_from_file_location("grid_under_probe", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
print("HAS_DEPS=" + repr(m.HAS_DEPS))
print("RUN1=" + repr(m.run({})))
print("RUN2=" + repr(m.run({})))
'''

_CONSISTENCY_PROBE = r'''
import importlib.util, sys
_want = (importlib.util.find_spec("numpy") is not None
         and importlib.util.find_spec("PIL") is not None)
spec = importlib.util.spec_from_file_location("grid_under_probe2", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
print("WANT=" + repr(_want))
print("HAS_DEPS=" + repr(m.HAS_DEPS))
sys.exit(0 if _want == m.HAS_DEPS else 1)
'''


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code, str(_SKILL_FILE)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )


def test_module_still_importable_when_numpy_and_pil_are_missing() -> None:
    """真屏蔽依赖后模块必须仍能加载，且 run() 明确回报「能力不存在」。"""
    r = _run(_BLOCKED_PROBE)
    assert r.returncode == 0, (
        "缺依赖时模块必须能被导入，不能炸在模块级 import：\n" + r.stderr)
    assert "HAS_DEPS=False" in r.stdout, r.stdout
    assert r.stdout.count("dependency_missing") == 2, (
        "两次 run 都要返回同一结构化 reason：\n" + r.stdout)
    # 数「告警行数」而不是数某个词：文案里「能力不存在」本身出现两次，
    # 按词计数会把一次告警误判成两次（度量工具必须先校准）。
    warn_lines = [ln for ln in r.stderr.splitlines() if ln.strip()]
    assert len(warn_lines) == 1, (
        "告警必须恰好一次（不刷屏也不能静默），实际 stderr：\n" + r.stderr)
    assert "依赖缺失（" in warn_lines[0], warn_lines[0]
    assert "能力不存在" in warn_lines[0], warn_lines[0]
    assert "不是「解不出」" in warn_lines[0], warn_lines[0]


def test_dep_flag_matches_real_importability() -> None:
    """HAS_DEPS 必须与真实可导入性一致；写死 True/False 都是假绿。"""
    r = _run(_CONSISTENCY_PROBE)
    assert r.returncode == 0, (
        "HAS_DEPS 与 numpy/PIL 真实可导入性不一致：\n" + r.stdout + r.stderr)
