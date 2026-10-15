#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真题基准有效性审计：把「55 题 20/55」这个数字拆成可解释的三层。

为什么需要这个脚本
------------------
覆盖率数字只有在「分母可解、分子真实」时才具备度量能力。若分母里混进
物理不可解的题（题面只有一句中文摘要，无密文/无附件/无目标 URL），
那么 sha256_match 对它们恒为 False，无论算法怎么改进都翻不了红为绿——
这是**不可达判据**。反过来，若分子里有题把 flag 明文写在 description 里，
求解器用正则一扫就「解出」，这是**平凡判据**。两者同时存在时，
一个覆盖率数字会双向失真：既低估真实能力，又虚增可信度。

本脚本把 real_benchmark 的每题归入三层，分别统计：

- **A 题面即答案**：description 里直接含 flag 明文。命中不代表能力。
- **B 有输入可解**：description 含真实数据载荷（长 base64/hex/长数字/
  长正文）或有附件目录。这一层的真解率才是可信的能力指标。
- **C 无输入不可解**：题面只是一句话摘要，无密文、无附件、无目标。
  这一层应当被剔除出分母，或补录真实题面后再计入。

用法
----
    python scripts/audit_benchmark_validity.py                 # 只报数
    python scripts/audit_benchmark_validity.py --check         # 跑门禁断言
    python scripts/audit_benchmark_validity.py --check --max-noinput-pct 20
    python scripts/audit_benchmark_validity.py --detail        # 列出每层题号

退出码：--check 下任一断言失败为 1；仅报数恒为 0。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "data", "ctf_benchmark", "real_benchmark.json")
REPORT = os.path.join(ROOT, "data", "ctf_benchmark", "real_coverage_report.json")
ATTACH = os.path.join(ROOT, "data", "questions_real_bench", "attachments")

# 题面里直接出现 flag 明文（含大小写与常见前缀变体）
FLAG_PLAIN_RE = re.compile(r"(?:flag|FLAG|picoCTF|picoctf|d0g3|DASCTF)\{[^{}]{3,}\}")
# 真实数据载荷特征
B64ISH_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")
HEX_RE = re.compile(r"0x[0-9a-fA-F]{8,}")
LONGNUM_RE = re.compile(r"[0-9]{12,}")
MIN_PROSE_LEN = 100  # 正文长度阈值：超过即认为题面携带了实质内容


def load():
    with open(BENCH, encoding="utf-8") as fh:
        bench_doc = json.load(fh)
    with open(REPORT, encoding="utf-8") as fh:
        rep_doc = json.load(fh)
    problems = bench_doc.get("problems", bench_doc)
    results = {r["id"]: r for r in rep_doc.get("results", [])}
    attach = set()
    if os.path.isdir(ATTACH):
        attach = set(os.listdir(ATTACH))
    return problems, results, attach


def has_payload(desc: str, pid: str, attach: set) -> bool:
    """题面是否携带可求解的真实输入。"""
    d = desc or ""
    if len(d) > MIN_PROSE_LEN:
        return True
    if B64ISH_RE.search(d) or HEX_RE.search(d) or LONGNUM_RE.search(d):
        return True
    return pid in attach


def classify(problems: dict, attach: set) -> dict:
    layers = {"A": [], "B": [], "C": []}
    for pid, meta in problems.items():
        desc = meta.get("description") or ""
        if FLAG_PLAIN_RE.search(desc):
            layers["A"].append(pid)
        elif has_payload(desc, pid, attach):
            layers["B"].append(pid)
        else:
            layers["C"].append(pid)
    return layers


def stats(ids, results):
    hit = [i for i in ids if results.get(i, {}).get("sha256_match")]
    scan = [
        i
        for i in hit
        if (results.get(i, {}).get("presolve_engine") or "") == "flag_scan"
    ]
    real = [i for i in hit if i not in set(scan)]
    n = len(ids)
    return {
        "total": n,
        "hit": len(hit),
        "scan_only": len(scan),
        "real": len(real),
        "hit_pct": (100.0 * len(hit) / n) if n else 0.0,
        "real_pct": (100.0 * len(real) / n) if n else 0.0,
    }


NAMES = {
    "A": "A 题面即答案（伪解风险）",
    "B": "B 有输入可解（可信分母）",
    "C": "C 无输入不可解（应剔除/补录）",
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="真题基准有效性审计")
    ap.add_argument("--check", action="store_true", help="跑门禁断言（默认只报数）")
    ap.add_argument(
        "--max-noinput-pct",
        type=float,
        default=20.0,
        help="C 层占比上限（%%），超过即判分母注水，默认 20",
    )
    ap.add_argument("--detail", action="store_true", help="列出每层题号")
    args = ap.parse_args(argv)

    problems, results, attach = load()
    layers = classify(problems, attach)
    total = len(problems)

    print("=== 真题基准有效性审计 ===")
    print("题目总数: %d" % total)
    for key in ("A", "B", "C"):
        s = stats(layers[key], results)
        print()
        print("【%s】%d 题（占 %.1f%%）" % (NAMES[key], s["total"], 100.0 * s["total"] / total if total else 0))
        print(
            "   命中 %d | flag_scan 伪解 %d | 真求解器 %d"
            % (s["hit"], s["scan_only"], s["real"])
        )
        print("   命中率 %.1f%% | 真解率 %.1f%%" % (s["hit_pct"], s["real_pct"]))
        if args.detail and layers[key]:
            for pid in sorted(layers[key]):
                eng = results.get(pid, {}).get("presolve_engine") or "-"
                print("     - %-32s engine=%s" % (pid, eng))

    head = stats(problems.keys(), results)
    b = stats(layers["B"], results)
    print()
    print("=== 口径对比 ===")
    print("   宣传口径 : %d/%d = %.1f%%" % (head["hit"], total, head["hit_pct"]))
    print(
        "   诚实口径 : %d/%d = %.1f%%  （B 层：有真实输入且非题面即答案）"
        % (b["real"], b["total"], b["real_pct"])
    )

    if not args.check:
        return 0

    # ---- 门禁断言 ----
    failures = []
    a = stats(layers["A"], results)
    c_ratio = 100.0 * len(layers["C"]) / total if total else 0.0

    if a["total"] != 0:
        failures.append(
            "A 层 %d 题题面直接含 flag 明文（%s）——这些命中来自正则扫描，"
            "不代表解题能力，必须从基准中剔除或改写题面。"
            % (a["total"], ", ".join(sorted(layers["A"])[:5]))
        )
    if c_ratio > args.max_noinput_pct:
        failures.append(
            "C 层占比 %.1f%% 超过上限 %.1f%%：%d/%d 题无密文/无附件/无目标，"
            "物理不可解却计入分母，覆盖率数字失真。"
            % (c_ratio, args.max_noinput_pct, len(layers["C"]), total)
        )
    # 覆盖度自证：分层题数之和必须等于总数，否则分类逻辑漏题
    if len(layers["A"]) + len(layers["B"]) + len(layers["C"]) != total:
        failures.append(
            "分层题数之和 %d != 总数 %d，分类逻辑漏题。"
            % (len(layers["A"]) + len(layers["B"]) + len(layers["C"]), total)
        )

    print()
    if failures:
        print("=== 门禁结论：FAIL ===")
        for f in failures:
            print("  [FAIL] %s" % f)
        return 1
    print("=== 门禁结论：PASS（%d 项断言全过）===" % 3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
