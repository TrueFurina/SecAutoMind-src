#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_external_bench.py 的变异自测。

门禁只写测试不证明"真能失败" = 不实自证（AGENTS.md 第四条）。本测试把判据函数
`check()` 直接喂**变异后的输入**，逐条断言必须报红；并保留**反向对照**两条，
证明判据不是"恒红"（否则等于把门禁改成一律失败，同样是空转）。

技巧：`check()` 内部按模块级 `ROOT` 拼路径，测试把 `ROOT` 指向 tempdir，
即可在隔离夹具里同时覆盖"清单↔磁盘"（C3）与"不得混入 KPI"（C4/C5）两类判据。

用法：python scripts/check_external_bench_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_external_bench as M  # noqa: E402


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


FLAG = "flag{external_probe_flag}"
FLAG_SHA = sha(FLAG)


def mkprob(pid, files, desc="普通题面", title="t", flag_sha256=FLAG_SHA,
           complete=True, declared=None, present=None):
    af = []
    for (name, excluded, ak) in files:
        af.append({"name": name, "size": 10, "answer_key_shape": ak,
                   "git_excluded": excluded, "exclude_reason": "x" if excluded else ""})
    return {
        "id": pid, "description": desc, "title": title,
        "flag_sha256": flag_sha256,
        "payload_complete": complete,
        "attachment_declared": declared if declared is not None else len(af),
        "attachment_present": present if present is not None else len(af),
        "attachment_files": af,
    }


def build_root(tmp, problems, kpi_text="{}", summary_text='{"ok": true}',
               on_disk=None, anchor=None, with_report=True):
    """在 tmp 里搭一个最小仓库骨架。on_disk: {(pid,name): 是否落盘}"""
    bench = os.path.join(tmp, "data", "questions_external_bench")
    # 与门禁同路径：`_attachments`（下划线前缀使 Go 工具链不把它当模块内包）
    att = os.path.join(bench, "_attachments")
    os.makedirs(att, exist_ok=True)
    for pid, p in problems.items():
        for af in p["attachment_files"]:
            want = True if on_disk is None else on_disk.get((pid, af["name"]), True)
            if want:
                d = os.path.join(att, pid)
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, af["name"]), "w", encoding="utf-8") as fh:
                    fh.write("challenge payload\n")
    doc = {"honesty": {"payload_complete": sum(1 for p in problems.values() if p["payload_complete"]),
                       "payload_partial": sum(1 for p in problems.values() if not p["payload_complete"])},
           "problems": problems}
    with open(os.path.join(bench, "external_bench.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    # C9 报告锚点：默认按真实题数生成；anchor=None/False 用于变异"锚点缺失/不符"
    if with_report:
        docs = os.path.join(tmp, "docs")
        os.makedirs(docs, exist_ok=True)
        total = len(problems)
        comp = sum(1 for p in problems.values() if p["payload_complete"])
        line = anchor if anchor is not None else (
            "<!-- AUTO-CHECK: total=%d payload_complete=%d -->" % (total, comp))
        with open(os.path.join(docs, "external_bench_report.md"), "w", encoding="utf-8") as fh:
            fh.write("# 报告\n\n" + line + "\n")
    kpi = os.path.join(tmp, "data", "ctf_benchmark")
    os.makedirs(kpi, exist_ok=True)
    with open(os.path.join(kpi, "benchmark.json"), "w", encoding="utf-8") as fh:
        fh.write(kpi_text)
    with open(os.path.join(kpi, "all_benchmarks_summary.json"), "w", encoding="utf-8") as fh:
        fh.write(summary_text)
    return doc


def run(problems, honesty=None, kpi_text="{}", summary_text='{"ok": true}', on_disk=None,
        anchor=None, with_report=True):
    tmp = tempfile.mkdtemp(prefix="extbench_")
    old_root = M.ROOT
    try:
        doc = build_root(tmp, problems, kpi_text, summary_text, on_disk, anchor, with_report)
        M.ROOT = tmp
        res = M.check(problems, honesty or doc["honesty"], {}, None)
        return [x for x in res if x.startswith("🔴")]
    finally:
        M.ROOT = old_root
        shutil.rmtree(tmp, ignore_errors=True)


CASES = []


def case(name):
    def _deco(fn):
        CASES.append((name, fn))
        return fn
    return _deco


def base_problems():
    return {"ext_gctf2021_pythia": mkprob("ext_gctf2021_pythia", [("server.py", False, False)])}


@case("基线：自洽产物不报红")
def c_baseline():
    reds = run(base_problems())
    assert not reds, "基线不应报红，实际：%s" % reds


@case("C7 题面含本题 flag 明文 → 必红（P0 红线）")
def c_flag_plaintext():
    p = mkprob("ext_gctf2021_pythia", [("server.py", False, False)],
               desc="答案是 " + FLAG)
    reds = run({"ext_gctf2021_pythia": p})
    assert any("C7" in r for r in reds), "题面 flag 明文未报红：%s" % reds


@case("C7 反向对照：题面含‘看着像 flag 但 sha256 不等’的已知输入 → 不得误伤")
def c_flag_lookalike():
    p = mkprob("ext_gctf2021_pythia", [("server.py", False, False)],
               desc="sample input: flag{this_is_not_the_answer}")
    reds = run({"ext_gctf2021_pythia": p})
    assert not reds, "C7 误伤已知输入：%s" % reds


@case("C3 登记附件在磁盘缺失 → 必红（清单与实物脱节）")
def c_missing_on_disk():
    reds = run(base_problems(), on_disk={("ext_gctf2021_pythia", "server.py"): False})
    assert any("C3" in r for r in reds), "附件缺失未报红：%s" % reds


@case("C3 反向对照：git_excluded 附件不在磁盘属预期 → 不得报红")
def c_excluded_missing_ok():
    p = mkprob("ext_gctf2021_pythia", [("flag.txt", True, True)])
    reds = run({"ext_gctf2021_pythia": p},
               on_disk={("ext_gctf2021_pythia", "flag.txt"): False})
    assert not reds, "排除文件缺失不应报红（CI 检出本就没有）：%s" % reds


@case("C4 外部尺题号混入 KPI 基准 → 必红")
def c_kpi_contamination():
    reds = run(base_problems(), kpi_text='{"problems": {"ext_gctf2021_pythia": {}}}')
    assert any("C4" in r for r in reds), "混入 KPI 未报红：%s" % reds


@case("C5 外部尺题号混入对外汇总 → 必红")
def c_summary_contamination():
    reds = run(base_problems(), summary_text='{"notes": "ext_gctf2021_pythia"}')
    assert any("C5" in r for r in reds), "混入对外汇总未报红：%s" % reds


@case("C2 honesty.payload_complete 与逐题计数不符 → 必红")
def c_ledger_mismatch():
    reds = run(base_problems(), honesty={"payload_complete": 99, "payload_partial": 0})
    assert any("C2" in r for r in reds), "台账不符未报红：%s" % reds


@case("C2 声明齐全但 present≠declared → 必红")
def c_declared_mismatch():
    p = mkprob("ext_gctf2021_pythia", [("server.py", False, False)],
               declared=3, present=1)
    reds = run({"ext_gctf2021_pythia": p},
               honesty={"payload_complete": 1, "payload_partial": 0})
    assert any("C2" in r for r in reds), "present/declared 不符未报红：%s" % reds


@case("C6 flag_sha256 非 64 位 hex → 必红")
def c_bad_flag():
    p = mkprob("ext_gctf2021_pythia", [("server.py", False, False)], flag_sha256="not-a-sha")
    reds = run({"ext_gctf2021_pythia": p})
    assert any("C6" in r for r in reds), "非 hex 真值未报红：%s" % reds


@case("C9 报告缺 AUTO-CHECK 锚点 → 必红（报告与实物脱节同型）")
def c_report_missing_anchor():
    reds = run(base_problems(), anchor="")
    assert any("C9" in r for r in reds), "报告缺锚点未报红：%s" % reds


@case("C9 报告声明题数与产物不符 → 必红")
def c_report_wrong_total():
    reds = run(base_problems(), anchor="<!-- AUTO-CHECK: total=99 payload_complete=1 -->")
    assert any("C9" in r for r in reds), "报告题数不符未报红：%s" % reds


@case("C9 报告文件缺失 → 必红")
def c_report_missing_file():
    reds = run(base_problems(), with_report=False)
    assert any("C9" in r for r in reds), "报告缺失未报红：%s" % reds


def main() -> int:
    failed = 0
    for name, fn in CASES:
        try:
            fn()
            print("  ✅ %s" % name)
        except AssertionError as e:
            failed += 1
            print("  ❌ %s —— %s" % (name, e))
    print("-" * 60)
    print("变异用例 %d 条，失败 %d" % (len(CASES), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
