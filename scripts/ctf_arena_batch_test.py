#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctf_arena_batch.py 的单元测试 + 仪器自检（纯本地，无需靶机/网络）。

判分纪律：只看输出里有没有 flag 明文。本测试不依赖任何未提交文件，自包含。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ctf_arena_batch as m  # noqa: E402


def _write_solver(tmp: str, body: str, name: str = "solver.py") -> str:
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def test_judge_local_solved():
    tmp = tempfile.mkdtemp()
    sp = _write_solver(tmp, "import sys; sys.stdout.write(open('flag', encoding='utf-8').read())\n")
    cmd = '"%s" "%s"' % (sys.executable, sp)
    rc = m._judge_local(cmd, tmp, "DASCTF{x}", 5, None)
    assert rc == 0, rc


def test_judge_local_unsolved():
    tmp = tempfile.mkdtemp()
    sp = _write_solver(tmp, "print('nope')\n")
    cmd = '"%s" "%s"' % (sys.executable, sp)
    rc = m._judge_local(cmd, tmp, "DASCTF{y}", 5, None)
    assert rc == 2, rc


def test_judge_local_no_flag_arg():
    tmp = tempfile.mkdtemp()
    sp = _write_solver(tmp, "print('hi')\n")
    cmd = '"%s" "%s"' % (sys.executable, sp)
    # 不埋 flag → 运行层面（rc=1），不得算 UNSOLVED
    rc = m._judge_local(cmd, tmp, None, 5, None)
    assert rc == 1, rc


def test_run_one_local():
    tmp = tempfile.mkdtemp()
    sp = _write_solver(tmp, "import sys; sys.stdout.write(open('flag', encoding='utf-8').read())\n")
    cmd = '"%s" "%s"' % (sys.executable, sp)
    r = m._run_one({"name": "p", "cmd": cmd, "cwd": tmp,
                    "flag": "DASCTF{p}", "mode": "local"}, 5)
    assert r["verdict"] == "SOLVED", r


def test_run_one_service_judging():
    # service 模式：起端口 + 假脆弱服务（echo hi），无外部客户端连接 → accept 超时 → 无输出 → UNSOLVED。
    # 这里只验证 service 分支不崩、返回合法 verdict（不依赖真实 pwn 题）。
    tmp = tempfile.mkdtemp()
    sp = _write_solver(tmp, "print('hi')\n")
    cmd = '"%s" "%s"' % (sys.executable, sp)
    r = m._run_one({"name": "s", "cmd": cmd, "cwd": tmp, "flag": "DASCTF{s}",
                    "mode": "service", "port": 32701}, 2)
    assert r["verdict"] in ("SOLVED", "UNSOLVED", "ERROR"), r


def test_compare():
    base = {"results": [{"name": "a", "verdict": "SOLVED"},
                        {"name": "b", "verdict": "UNSOLVED"}]}
    results = [{"name": "a", "verdict": "UNSOLVED"},
               {"name": "b", "verdict": "SOLVED"},
               {"name": "c", "verdict": "SOLVED"}]
    rep = m.compare(results, base)
    assert rep["regressed"] == ["a"], rep
    assert rep["new_solved"] == ["b"], rep
    assert rep["unknown"] == ["c"], rep


def test_self_test():
    assert m.self_test() == 0


def test_main_regression_gate_red():
    # 构造：基线 a SOLVED，本次 a 故意 UNSOLVED → 退化 1 > 闸门 0 → exit 3
    tmp = tempfile.mkdtemp()
    man = os.path.join(tmp, "m.json")
    base = os.path.join(tmp, "b.json")
    sp = _write_solver(tmp, "print('nope')\n")
    cmd = '"%s" "%s"' % (sys.executable, sp)
    manifest = [{"name": "a", "cmd": cmd, "cwd": tmp,
                 "flag": "DASCTF{a}", "mode": "local"}]
    with open(man, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    with open(base, "w", encoding="utf-8") as fh:
        json.dump({"results": [{"name": "a", "verdict": "SOLVED"}]}, fh)
    rc = m.main(["--manifest", man, "--baseline", base, "--gate-regression", 0,
                 "--out", os.path.join(tmp, "l.jsonl")])
    assert rc == 3, rc


def test_main_all_solved_green():
    tmp = tempfile.mkdtemp()
    man = os.path.join(tmp, "m.json")
    sp = _write_solver(tmp, "import sys; sys.stdout.write(open('flag', encoding='utf-8').read())\n")
    cmd = '"%s" "%s"' % (sys.executable, sp)
    manifest = [{"name": "a", "cmd": cmd, "cwd": tmp,
                 "flag": "DASCTF{a}", "mode": "local"}]
    with open(man, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    rc = m.main(["--manifest", man, "--out", os.path.join(tmp, "l.jsonl"),
                 "--save-baseline", os.path.join(tmp, "base.json")])
    assert rc == 0, rc


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print("ALL PASS (%d tests)" % len(fns))
