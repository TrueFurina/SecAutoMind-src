#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_external_westlake_payload.py 的回归 + 变异用例。

项目纪律：门禁自身必须有回归测试；关键门禁必须有**变异验证**——
注入错误必须变红，否则"测试有效"无从证明。

变异用例的重点是证明判据**两端都灵**：
  · 未挂载却不许引用（防"拿没落地的基准当跑过分"）
  · 已挂载就必须题题有实物（防"声明齐全、实物缺失"）
  · 空基准不许静默放过（防"扫 0 文件 = 0 违规 = 全绿"）
  · 报数模式永不因违规退出（确认 --check 才是判定入口）
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_external_westlake_payload.py")
sys.path.insert(0, HERE)

import check_external_westlake_payload as G  # noqa: E402

PASS, FAIL = 0, 0


def report(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, detail))


def mk_repo(probs):
    """造一个最小 repo_root，并把存在的附件真的写到磁盘上。"""
    root = tempfile.mkdtemp(prefix="wl_gate_")
    return root, probs


def write_att(root, rel):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write("payload")
    return p


def bench_of(items):
    """items: [(qid, attachment_rel_or_None, status)]"""
    return {"problems": {
        qid: {"payload_status": st, **({"attachment": a} if a else {})}
        for qid, a, st in items
    }}


# ─────────────────────────── 1. 判据单元级（纯函数） ───────────────────────────

def case_unmounted_not_referenced():
    """真实现状：80 题声称、0 题实物、未被引用 → 允许存在，PASS。"""
    root, _ = mk_repo(None)
    an = G.analyze(bench_of([("q%d" % i, "data/remote/att%d.txt" % i, "verified_on_disk")
                             for i in range(80)]), root)
    vs = G.violations(an, [])
    report("未挂载且未引用 → PASS（允许存在，不许引用）",
           an["mode"] == "unmounted" and vs == [], "mode=%s vs=%s" % (an["mode"], vs))


def case_unmounted_but_referenced():
    """变异：载荷没落地却写进对外汇总 → 必须 FAIL。"""
    root, _ = mk_repo(None)
    an = G.analyze(bench_of([("q1", "data/remote/att.txt", "verified_on_disk")]), root)
    vs = G.violations(an, ["data/ctf_benchmark/all_benchmarks_summary.json"])
    report("未挂载却被写进对外汇总 → FAIL", len(vs) == 1, "vs=%s" % vs)


def case_mounted_all_present():
    """已挂载且题题有实物 → PASS。"""
    root, _ = mk_repo(None)
    write_att(root, os.path.join("data", "a1.txt"))
    write_att(root, os.path.join("data", "a2.txt"))
    an = G.analyze(bench_of([("q1", "data/a1.txt", "verified_on_disk"),
                             ("q2", "data/a2.txt", "verified_on_disk")]), root)
    vs = G.violations(an, [])
    report("已挂载全齐 → PASS",
           an["mode"] == "mounted" and len(an["resolved"]) == 2 and vs == [],
           "mode=%s resolved=%d vs=%s" % (an["mode"], len(an["resolved"]), vs))


def case_mounted_one_missing():
    """变异：已挂载态下 1 题实物缺失 → FAIL（这就是声明齐全≠实物存在的形态）。"""
    root, _ = mk_repo(None)
    write_att(root, os.path.join("data", "a1.txt"))
    # a2.txt 故意不写
    an = G.analyze(bench_of([("q1", "data/a1.txt", "verified_on_disk"),
                             ("q2", "data/a2.txt", "verified_on_disk")]), root)
    vs = G.violations(an, [])
    report("已挂载但 1 题实物缺失 → FAIL",
           an["mode"] == "mounted" and len(vs) == 1 and "q2" in vs[0],
           "mode=%s vs=%s" % (an["mode"], vs))


def case_empty_bench():
    """变异：空基准 → FAIL（fail-closed，不许"0 题 = 0 违规 = 全绿"）。"""
    root, _ = mk_repo(None)
    an = G.analyze({"problems": {}}, root)
    vs = G.violations(an, [])
    report("空基准 → FAIL（防零覆盖假绿）", an["mode"] == "empty" and len(vs) == 1, "vs=%s" % vs)


def case_plural_field_recognized():
    """attachments 复数形态也要认（只数单数字段会漏 5 题）。"""
    root, _ = mk_repo(None)
    b = {"problems": {"q1": {"payload_status": "verified_on_disk",
                             "attachments": ["data/no_such.txt"]}}}
    an = G.analyze(b, root)
    report("attachments 复数形态被计入声称",
           an["mode"] == "unmounted" and len(an["claimed"]) == 1,
           "claimed=%d" % len(an["claimed"]))


def case_non_claimed_ignored():
    """未声称 verified_on_disk 的题不进分母（避免误伤）。"""
    root, _ = mk_repo(None)
    an = G.analyze(bench_of([("q1", None, "no_payload")]), root)
    report("未声称的题不计入声称分母", len(an["claimed"]) == 0, "claimed=%d" % len(an["claimed"]))


# ─────────────────────────── 2. 端到端（子进程真跑） ───────────────────────────

def run_script(args, cwd=None):
    p = subprocess.run([sys.executable, SCRIPT] + args,
                       capture_output=True, text=True, cwd=cwd or HERE)
    return p.returncode, p.stdout + p.stderr


def case_real_repo_check_passes():
    """真仓库当前状态：未挂载 + 未引用 → --check 必须 PASS（不是靠放水）。"""
    rc, out = run_script(["--check"])
    report("真仓库 --check PASS（当前为未挂载且未引用）",
           rc == 0 and "未挂载" in out, "rc=%d" % rc)


def case_report_mode_never_fails():
    """报数模式即使有违规也不退出非 0 —— 确认 --check 才是判定入口。"""
    rc, _ = run_script([])
    report("报数模式 rc=0（判定入口是 --check）", rc == 0, "rc=%d" % rc)


def case_json_mode():
    """--json 可机读，且带出引用面与违规。"""
    rc, out = run_script(["--json"])
    try:
        d = json.loads(out)
        ok = rc == 0 and d["mode"] == "unmounted" and d["claimed_n"] == 80
    except Exception as e:  # noqa: BLE001
        ok = False
        d = str(e)
    report("--json 输出可解析且声称 80 题", ok, "d=%s" % str(d)[:120])


def main():
    print("=== check_external_westlake_payload 自测（含变异用例）===")
    for fn in (case_unmounted_not_referenced,
               case_unmounted_but_referenced,
               case_mounted_all_present,
               case_mounted_one_missing,
               case_empty_bench,
               case_plural_field_recognized,
               case_non_claimed_ignored,
               case_real_repo_check_passes,
               case_report_mode_never_fails,
               case_json_mode):
        fn()
    print()
    print("结果：%d PASS / %d FAIL" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
