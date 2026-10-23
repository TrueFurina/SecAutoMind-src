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

- **A 题面即答案**：description 里的 flag 串，其 sha256 **等于该题 flag_sha256**。
  命中不代表能力。
- **B 有输入可解**：description 含真实数据载荷（长 base64/hex/长数字/
  长正文）或有附件目录。这一层的真解率才是可信的能力指标。
- **C 无输入不可解**：题面只是一句话摘要，无密文、无附件、无目标。
  这一层应当被剔除出分母，或补录真实题面后再计入。

A 层判据：不许"看着像"（2026-10-16 修正）
------------------------------------------
初版用正则 ``flag{...}`` 直接判 A 层，即"题面出现 flag 形态串就算答案在题面"。
**这是错的**：CRC32 伪造、LCG 参数恢复一类题的 flag 是**已知输入**，
形态也是 ``flag{...}`` 但与答案指纹不等。唯一权威判据是 **sha256 比对**
（与 ``scripts/check_benchmark_plaintext_answer.py`` 同源）。

登记基线：防恶化，不是目标值
----------------------------
``--check`` 的默认阈值是 **2026-10-16 实测的当前值**（A=4、C=70.9%），
语义是"**不许再恶化**"，不是"已经合格"。理想目标仍是 A=0、C 层尽量低。
C 层问题已由 ``internal/ctfplatform/miss_attribution_test.go`` 机验，
本脚本守住的是**分母不被继续注水**（新增无输入的题会让占比上升即红）。

用法
----
    python scripts/audit_benchmark_validity.py                 # 只报数
    python scripts/audit_benchmark_validity.py --check         # 跑门禁断言
    python scripts/audit_benchmark_validity.py --check --max-a 0 --max-noinput-pct 20
    python scripts/audit_benchmark_validity.py --detail        # 列出每层题号

退出码：--check 下任一断言失败为 1；仅报数恒为 0。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "data", "ctf_benchmark", "real_benchmark.json")
REPORT = os.path.join(ROOT, "data", "ctf_benchmark", "real_coverage_report.json")
ATTACH = os.path.join(ROOT, "data", "questions_real_bench", "attachments")

# 题面里 flag 形态串的**候选**提取（含大小写与常见前缀变体）。
# 注意：这只是候选，是否真是答案由 answer_in_statement() 的 sha256 比对裁定。
FLAG_PLAIN_RE = re.compile(r"(?:flag|FLAG|picoCTF|picoctf|d0g3|DASCTF|ctf)\{[^{}]{3,}\}")

# 登记基线（2026-10-16 实测当前值）：语义是"不许再恶化"，不是"已经合格"。
BASELINE_A = 4            # A 层题面即答案数
BASELINE_C_PCT = 71.0     # C 层占比上限（当前实测 70.9%，留 0.1 余量；40/55=72.7% 会超）
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


def answer_in_statement(meta: dict) -> bool:
    """权威判据：题面里的 flag 串，其 sha256 是否等于该题答案指纹。

    与 scripts/check_benchmark_plaintext_answer.py 同源。
    不等 ⇒ flag 只是已知输入（如 CRC32 伪造给定原文），**不**算题面即答案。
    没有 flag_sha256 的题无法裁定，返回 False（不误伤）。
    """
    want = meta.get("flag_sha256")
    if not want:
        return False
    desc = meta.get("description") or ""
    for cand in FLAG_PLAIN_RE.findall(desc):
        if hashlib.sha256(cand.encode("utf-8")).hexdigest() == want:
            return True
    return False


def classify(problems: dict, attach: set) -> dict:
    layers = {"A": [], "B": [], "C": []}
    for pid, meta in problems.items():
        desc = meta.get("description") or ""
        if answer_in_statement(meta):
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
        default=BASELINE_C_PCT,
        # 用 f-string 而非 `%` 预格式化：Python 3.14 的 argparse._check_help 会校验
        # 最终 help 字符串里的 `%`，预格式化后残留的裸 `%` 会直接抛
        # `ValueError: badly formed help string`（3.13 及以前不校验，故一直没暴露）。
        # 字面百分号保留 `%%`，交给 argparse 自己的格式化渲染成 `%`。
        help=f"C 层占比上限（%%）。默认 {BASELINE_C_PCT:.1f} 是登记基线（当前实测值，语义为不许恶化，"
             "非目标值）；理想目标应远低于此",
    )
    ap.add_argument(
        "--max-a",
        type=int,
        default=BASELINE_A,
        help=f"A 层（题面即答案）题数上限。默认 {BASELINE_A} 是登记基线（当前实测值）；"
             "理想目标为 0",
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

    if a["total"] > args.max_a:
        failures.append(
            "A 层 %d 题题面即答案 > 基线 %d（%s）——题面 flag 串的 sha256 == flag_sha256，"
            "这些命中来自正则扫描，不代表解题能力。"
            % (a["total"], args.max_a, ", ".join(sorted(layers["A"])[:5]))
        )
    if c_ratio > args.max_noinput_pct:
        failures.append(
            "C 层占比 %.1f%% 超过基线 %.1f%%：%d/%d 题无密文/无附件/无目标，"
            "物理不可解却计入分母，覆盖率数字失真（基线语义为不许继续注水，非已合格）。"
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
