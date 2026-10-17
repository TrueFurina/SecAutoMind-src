#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部真题对照尺（external-bench）的产物一致性门禁。

为什么单独一个门禁（不并入 check_cross_bench_manifest.py）
------------------------------------------------------
两把尺的**失效模式不同**，共用一个门禁会让判据互相稀释：
  · cross-bench（A 库真题 88 题）的病是「76/88 附件缺失」→ 门禁盯"缺载荷不得进汇总"；
  · external-bench（Google CTF 40 题）的卖点是「38/40 载荷齐全」→
    一旦有人手改产物、或把某题搬进自产集，**"载荷齐全"这个唯一价值就被静默抹掉**，
    而且没人会发现（数字还是 0/40，看起来没变）。故本门禁的核心是把
    「齐全」钉成机验事实，而不是文案声明。

判据（fail-closed：任何一条不满足即 exit 1）
------------------------------------------
  C1 产物存在且可解析（external_bench.json + external_bench_source_stats.json）
  C2 载荷台账自洽：payload_complete/partial 计数与 honesty 段一致；
                   声明齐全的题其 attachment_present == attachment_declared
  C3 清单 ↔ 磁盘：非 git_excluded 的登记附件必须在磁盘上（清单与实物脱节即红）
  C4 不得混入 KPI：本尺题号不得出现在 data/ctf_benchmark/*.json
                   （混入即污染对外数字；也防"把外部题搬进自产集"）
  C5 不得进对外汇总：本尺题号/来源串不得出现在 all_benchmarks_summary.json
  C6 flag 真值形态：每题 flag_sha256 必须是 64 位 hex
  C7 题面无 flag 明文：题面候选串 sha256 不得等于本题 flag_sha256（P0 红线复检）
  C8 生成器契约：给出 --src 时重跑生成器 --check，题数/载荷齐全数必须与产物一致；
                 未给 --src（CI 无 A 库）→ **显式记 SKIP**，不得静默放行

用法：
    python scripts/check_external_bench.py [--src <A库 data/questions_external>]
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_DIR = os.path.join("data", "questions_external_bench")
DOC = os.path.join(BENCH_DIR, "external_bench.json")
STATS = os.path.join(BENCH_DIR, "external_bench_source_stats.json")
ATT = os.path.join(BENCH_DIR, "_attachments")
KPI_DIR = os.path.join("data", "ctf_benchmark")
KPI_SUMMARY = os.path.join(KPI_DIR, "all_benchmarks_summary.json")

REPORT_DOC = os.path.join("docs", "external_bench_report.md")
AUTO_CHECK_RE = re.compile(r"<!--\s*AUTO-CHECK:\s*total=(\d+)\s+payload_complete=(\d+)\s*-->")

FLAG_CAND_RE = re.compile(r"([A-Za-z0-9_]{2,})\{[^}\n]{4,80}\}")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(msg: str, out: list) -> None:
    out.append("🔴 " + msg)


def load_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check(problems: dict, honesty: dict, stats: dict, src: str | None) -> list:
    out: list = []

    # C6 flag 真值形态
    for pid, p in problems.items():
        if not HEX64_RE.match(p.get("flag_sha256") or ""):
            fail("C6 %s 的 flag_sha256 非 64 位 hex——无外部真值不得计入" % pid, out)

    # C7 题面无 flag 明文（与生成器 sanitize_text 同判据：sha256 相等）
    for pid, p in problems.items():
        fs = p.get("flag_sha256") or ""
        for field in ("description", "title"):
            text = p.get(field) or ""
            for m in FLAG_CAND_RE.finditer(text):
                if hashlib.sha256(m.group(0).encode("utf-8")).hexdigest() == fs:
                    fail("C7 %s 的 %s 含本题 flag 明文——P0 红线（PUBLIC 仓不得含答案）"
                         % (pid, field), out)

    # C2 载荷台账自洽
    complete = [pid for pid, p in problems.items() if p.get("payload_complete")]
    partial = [pid for pid, p in problems.items() if not p.get("payload_complete")]
    if len(complete) != honesty.get("payload_complete"):
        fail("C2 逐题齐全数 %d ≠ honesty.payload_complete %s"
             % (len(complete), honesty.get("payload_complete")), out)
    if len(partial) != honesty.get("payload_partial"):
        fail("C2 逐题不齐全数 %d ≠ honesty.payload_partial %s"
             % (len(partial), honesty.get("payload_partial")), out)
    for pid in complete:
        p = problems[pid]
        if p.get("attachment_present") != p.get("attachment_declared"):
            fail("C2 %s 声明齐全但 attachment_present %s ≠ attachment_declared %s"
                 % (pid, p.get("attachment_present"), p.get("attachment_declared")), out)

    # C3 清单 ↔ 磁盘
    for pid, p in problems.items():
        for af in p.get("attachment_files") or []:
            if af.get("git_excluded"):
                continue
            path = os.path.join(ROOT, ATT, pid, af.get("name") or "")
            if not os.path.isfile(path):
                fail("C3 %s/%s 登记在册但磁盘不存在——清单与实物脱节" % (pid, af.get("name")), out)

    # C4 不得混入 KPI 基准
    kpi_files = sorted(glob.glob(os.path.join(ROOT, KPI_DIR, "*.json")))
    if not kpi_files:
        fail("C4 未找到 data/ctf_benchmark/*.json——无法核对混入，fail-closed", out)
    for f in kpi_files:
        text = open(f, encoding="utf-8", errors="ignore").read()
        for pid in problems:
            if pid in text:
                fail("C4 外部尺题目 %s 出现在 KPI 基准 %s" % (pid, os.path.basename(f)), out)

    # C5 不得进对外汇总
    if os.path.isfile(os.path.join(ROOT, KPI_SUMMARY)):
        text = open(os.path.join(ROOT, KPI_SUMMARY), encoding="utf-8", errors="ignore").read()
        for pid in problems:
            if pid in text:
                fail("C5 外部尺题目 %s 出现在对外汇总 all_benchmarks_summary.json" % pid, out)
    else:
        out.append("⚠️ C5 all_benchmarks_summary.json 不存在，跳过对外汇总核对")

    # C9 报告与产物一致（P0 红线：报告与实物脱节同型，见 data_incomplete_claim_test.go）
    # 只钉「结构事实」（题数/载荷齐全数），**不钉命中率**——按 §2.2 纪律不为分数问责，
    # 免得逼出"为转绿改数字"的退化。
    report = os.path.join(ROOT, REPORT_DOC)
    if not os.path.isfile(report):
        fail("C9 缺失报告 %s——对照结论无处留痕" % REPORT_DOC, out)
    else:
        text = open(report, encoding="utf-8", errors="ignore").read()
        m = AUTO_CHECK_RE.search(text)
        if not m:
            fail("C9 报告缺 AUTO-CHECK 锚点行（total=N payload_complete=N）——无法机验一致性", out)
        else:
            if int(m.group(1)) != len(problems):
                fail("C9 报告声明题数 %s ≠ 产物 %d" % (m.group(1), len(problems)), out)
            if int(m.group(2)) != len(complete):
                fail("C9 报告声明载荷齐全 %s ≠ 产物 %d" % (m.group(2), len(complete)), out)

    # C8 生成器契约（无 A 库时显式 SKIP，不静默放行）
    if src:
        rc = subprocess.run([sys.executable, os.path.join("scripts", "build_external_bench.py"),
                             "--src", src, "--check"],
                            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                            errors="ignore")
        m = re.search(r"题数=(\d+)", rc.stdout or "")
        m2 = re.search(r"载荷齐全\s+(\d+)", rc.stdout or "")
        if rc.returncode != 0 or not m:
            fail("C8 生成器 --check 未成功（rc=%s）——产物与生成器契约无法核对" % rc.returncode, out)
        else:
            if int(m.group(1)) != len(problems):
                fail("C8 生成器题数 %s ≠ 产物 %d" % (m.group(1), len(problems)), out)
            if m2 and int(m2.group(1)) != len(complete):
                fail("C8 生成器载荷齐全 %s ≠ 产物 %d" % (m2.group(1), len(complete)), out)
    else:
        out.append("⚠️ C8 未提供 --src（CI 无 A 库）：生成器↔产物一致性**未核对**（显式 SKIP）")

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=None, help="A 库 data/questions_external 目录（可选）")
    args = ap.parse_args()

    doc_path = os.path.join(ROOT, DOC)
    stats_path = os.path.join(ROOT, STATS)
    if not os.path.isfile(doc_path):
        print("[FAIL] 缺失产物 %s（先跑 scripts/build_external_bench.py）" % DOC)
        return 1
    if not os.path.isfile(stats_path):
        print("[FAIL] 缺失产物 %s" % STATS)
        return 1

    try:
        doc = load_json(doc_path)
        stats = load_json(stats_path)
    except Exception as e:  # noqa: BLE001
        print("[FAIL] 产物解析失败: %s" % e)
        return 1

    problems = doc.get("problems") or {}
    if not problems:
        print("[FAIL] external_bench.json 无题目——产物被清空，fail-closed")
        return 1

    problems_out = check(problems, doc.get("honesty") or {}, stats, args.src)
    reds = [x for x in problems_out if x.startswith("🔴")]

    print("=" * 62)
    print("  外部真题对照尺门禁  题数=%d" % len(problems))
    print("=" * 62)
    for x in problems_out:
        print("  " + x)
    if reds:
        print("\n[FAIL] %d 项不满足" % len(reds))
        return 1
    print("\n[PASS] 外部尺产物自洽（载荷台账/清单↔磁盘/未混入 KPI/无 flag 明文）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
