"""script 动作的 `python:` 前缀判据：冒号后**直接换行**也必须识别为 Python。

事故（2026-11-10，实跑复现）：prompt 要求 code 写成 `python: <源码>`，但模型实际
常写 `"python:\nfrom math import gcd\n..."`（冒号后是换行，不是空格）。
旧判据是 `startswith(("python: ", "python3: "))` —— **要求冒号后有空格**，
于是 `python:\n...` 落到 bash 分支，`sh` 把 Python 源码当 shell 跑，
`compile` 报 `invalid syntax (<unknown>, line 1)`。

实测代价：10733 连续 5 步死在这，real_reverse_js 同样；两题合计空烧 ~360s。
"""
import asyncio

from sandbox.subprocess_executor import SubprocessExecutor


def _run(src: str):
    return asyncio.run(SubprocessExecutor().run(src))


def test_python_prefix_then_newline_runs_as_python():
    """核心回归：`python:` 后面直接换行。"""
    res = _run("python:\nfrom math import gcd\nprint('GCD', gcd(12, 18))")
    assert getattr(res, "exit_code", 0) == 0, getattr(res, "stderr", "")
    out = getattr(res, "stdout", "") or ""
    assert "GCD 6" in out, out


def test_python_prefix_with_space_still_works():
    """旧写法不能被改坏（冒号 + 空格 + 单行）。"""
    res = _run("python: print('SPACED')")
    assert getattr(res, "exit_code", 0) == 0, getattr(res, "stderr", "")
    assert "SPACED" in (getattr(res, "stdout", "") or "")


def test_python3_prefix_then_newline():
    res = _run("python3:\nprint('PY3')")
    assert "PY3" in (getattr(res, "stdout", "") or ""), getattr(res, "stderr", "")


def test_plain_python_source_without_prefix_still_recognized():
    """无前缀的纯 Python 源码走启发式识别（不能因为放宽前缀而丢这条）。"""
    res = _run("import math\nprint('HEUR', int(math.sqrt(16)))")
    assert "HEUR 4" in (getattr(res, "stdout", "") or ""), getattr(res, "stderr", "")
