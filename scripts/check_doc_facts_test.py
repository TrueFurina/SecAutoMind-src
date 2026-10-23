#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_doc_facts.py 自测 —— 门禁必须能变红，且只在该红的时候红。

纪律来源（AGENTS.md 第四条 + 材料门禁的先例）：门禁自身必须有回归测试；
**失效的门禁比没有门禁更危险**。本测试含 6 项变异验证（故意注入漂移数字，
测试必须抓到）与 2 项 fail-closed 验证（缺真值/缺分解式必须炸，不许静默）。

用法：python scripts/check_doc_facts_test.py   退出码 0 = 自测通过
"""
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "scripts", "check_doc_facts.py")

TRUTH = {"tools_yaml": 90, "builtin_tools": 52, "runtime_tools": 142}

GOOD = '宁可写"90 YAML + 52 内置 = 142 运行时"，也不要写没有分解式的整数。'
GOOD_NEITHER = "140 既不等于 90（YAML 工具数）也不等于 142，凭空漂移。"

_failures = []


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_doc_facts_under_test", GATE)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print("  [%s] %s%s" % (status, name, (" — " + detail) if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def main():
    gate = _load_gate()

    print("=" * 70)
    print("check_doc_facts 自测（真值: %s）" % TRUTH)
    print("-" * 70)

    # T1 正确文本必须全绿
    issues = gate.check_text(GOOD + "\n" + GOOD_NEITHER, TRUTH)
    check("T1 正确分解式 + 正确引用 → 无问题", not issues, str(issues))

    # T2 变异：YAML 数漂移（91 —— 正是 2026-10-20 实测复发过的旧值）
    issues = gate.check_text(
        '宁可写"91 YAML + 52 内置 = 142 运行时"，也不要写没有分解式的整数。\n' + GOOD_NEITHER,
        TRUTH)
    check("T2 变异 YAML 91 → 必须报漂移", any("91" in i for i in issues), str(issues))

    # T3 变异：内置数漂移
    issues = gate.check_text(
        '宁可写"90 YAML + 53 内置 = 142 运行时"，也不要写没有分解式的整数。\n' + GOOD_NEITHER,
        TRUTH)
    check("T3 变异内置 53 → 必须报漂移", any("53" in i for i in issues), str(issues))

    # T4 变异：运行时数漂移（143 —— 删 lightx 前旧口径）
    issues = gate.check_text(
        '宁可写"90 YAML + 52 内置 = 143 运行时"，也不要写没有分解式的整数。\n' + GOOD_NEITHER,
        TRUTH)
    check("T4 变异运行时 143 → 必须报漂移", any("143" in i for i in issues), str(issues))

    # T5 变异：分解式自相矛盾（加和不对）
    issues = gate.check_text(
        '宁可写"90 YAML + 52 内置 = 144 运行时"，也不要写没有分解式的整数。\n' + GOOD_NEITHER,
        TRUTH)
    check("T5 变异 90+52≠144 → 必须报不自洽",
          any("不自洽" in i for i in issues), str(issues))

    # T6 变异：「既不等于」句的真值引用过期
    issues = gate.check_text(
        GOOD + "\n140 既不等于 91（YAML 工具数）也不等于 143，凭空漂移。", TRUTH)
    check("T6 变异「既不等于」句引用 91/143 → 必须报漂移",
          any("既不等于" in i for i in issues), str(issues))

    # T7 fail-closed：分解式整句消失（改写法）必须红，不许静默放行
    issues = gate.check_text("这类数字最危险，不要写没有分解式的整数。", TRUTH)
    check("T7 缺分解式 → 必须报 fail-closed",
          any("未找到分解式" in i for i in issues), str(issues))

    # T8 fail-closed：真值字段缺失必须炸（SystemExit），不许静默跳过
    raised = False
    try:
        gate.check_text(GOOD + "\n" + GOOD_NEITHER, {"tools_yaml": 90})
    except SystemExit:
        raised = True
    check("T8 真值缺 builtin_tools → 必须 SystemExit", raised)

    # T9 集成：真实 AGENTS.md + 真实真值 → 门禁实跑必须 rc=0
    rc = subprocess.run([sys.executable, GATE], capture_output=True, text=True)
    check("T9 真实 AGENTS.md 对真实真值 → rc=0", rc.returncode == 0,
          rc.stdout[-300:] + rc.stderr[-300:])

    print("-" * 70)
    if _failures:
        print("结论：FAIL —— %d 项未过: %s" % (len(_failures), "；".join(_failures)))
        print("=" * 70)
        return 1
    print("结论：PASS —— 门禁判定与自测预期一致（含 6 变异 + 2 fail-closed）")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
