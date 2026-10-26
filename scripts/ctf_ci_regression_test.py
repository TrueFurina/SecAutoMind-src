#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctf_ci_regression.py 的集成测试（纯本地，无需靶机/网络）。

覆盖：manifest 令牌替换后仍是合法 JSON；record→check 稳定态；退化闸门 exit 3。
判分纪律：只看回归报告输出与退出码，不猜。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(HERE, "ctf_benchmark_manifest.example.json")
sys.path.insert(0, HERE)
import ctf_ci_regression as m  # noqa: E402


def _run_in_tmp(func):
    """在临时 cwd 里跑 func，避免 stray flag/log 污染仓库，返回 func 的返回值。"""
    prev = os.getcwd()
    tmp = tempfile.mkdtemp(prefix="ci_regress_test_")
    try:
        os.chdir(tmp)
        return func(tmp)
    finally:
        os.chdir(prev)


def test_materialize_valid_json():
    tmp = m._materialize_manifest(EXAMPLE)
    data = json.load(open(tmp, encoding="utf-8"))  # 不抛异常即合法
    assert isinstance(data, list) and len(data) == 2
    # {{PY}} 令牌已消失，且被替换为解释器绝对路径（json.load 后反斜杠已还原）
    assert m.MANIFEST_TOKEN not in json.dumps(data)
    assert all(sys.executable in inst["cmd"] for inst in data)


def test_record_then_check_stable():
    def _go(tmp):
        base = os.path.join(tmp, "baseline.json")
        rc_rec = m.main(["record", "--manifest", EXAMPLE, "--baseline", base])
        assert rc_rec == 2  # 1 题 UNSOLVED → exit 2
        assert os.path.exists(base)
        rc_chk = m.main(["check", "--manifest", EXAMPLE, "--baseline", base, "--gate", "0"])
        assert rc_chk == 2  # 与基线一致（stable），无退化
        return True
    _run_in_tmp(_go)


def test_regression_gate_red():
    def _go(tmp):
        fake = os.path.join(tmp, "fake_base.json")
        # 假基线：两题都 SOLVED；但示例清单里 local_unsolved_demo 实跑 UNSOLVED → 退化
        with open(fake, "w", encoding="utf-8") as fh:
            json.dump({"results": [
                {"name": "local_solved_demo", "verdict": "SOLVED"},
                {"name": "local_unsolved_demo", "verdict": "SOLVED"},
            ]}, fh)
        rc = m.main(["check", "--manifest", EXAMPLE, "--baseline", fake, "--gate", "0"])
        assert rc == 3  # 退化超闸门 → exit 3（最高优先级）
        return True
    _run_in_tmp(_go)


if __name__ == "__main__":
    for fn in (test_materialize_valid_json, test_record_then_check_stable, test_regression_gate_red):
        fn()
        print("PASS  %s" % fn.__name__)
    print("=== 3 passed ===")
