#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判分「不去壳」假阴性审计（只读，不改判分）。

背景：scripts/ctf_stepfun_orchestrator.py::verify_flag() 走
scripts/experiments/flag_util.py::candidate_variants()，后者只做
「原文 / 小写 / 前缀归一」，**不产生裸内容变体**。当某题真值登记为
sha256(裸内容 X) 而模型按题面要求输出 `flag{X}` 时，永远判不中。
2026-11-06 v1 全量 160 题实锤 5 题「答对判不中」。

该文件属他人在途 WIP，本轮不修改判分函数；本脚本在**审计层**用纯
sha256 比对重算，量化假阴性面，并写进证据供 verdict 作用域引用。
输出绝不含明文答案，只有题号 / 形态类别 / 长度 / sha8。

用法：
  python scripts/audit_scoring_variant_gap.py --result <result.json> --out <audit.json>
  python scripts/audit_scoring_variant_gap.py --selftest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105",
                           "scoring_variant_gap.json")
WRAPPED_RE = re.compile(r"[A-Za-z0-9_]+\{[^{}]{0,200}\}")


def _sha8(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


def _variants(candidate):
    """候选的所有合理去壳/带壳形态（判分层缺的就是这一组）。"""
    c = str(candidate or "")
    if not c:
        return set()
    out = {c, c.lower()}
    m = re.fullmatch(r"([A-Za-z0-9_]+)\{(.+)\}", c)
    if m:
        inner = m.group(2)
        out |= {inner, inner.lower(), inner.upper(),
                "flag{%s}" % inner, "FLAG{%s}" % inner,
                "DASCTF{%s}" % inner}
    if re.fullmatch(r"[A-Za-z0-9_]{1,64}", c):
        out |= {"flag{%s}" % c, "FLAG{%s}" % c, "DASCTF{%s}" % c}
    return {v for v in out if v}


def _candidates(row):
    """只取模型自己产出的候选：got 字段 + raw_head 里的花括号 token。"""
    got = str(row.get("got") or "")
    out = []
    if got:
        out.append(got)
    for tok in WRAPPED_RE.findall(str(row.get("raw_head") or "")):
        out.append(tok)
    return list(dict.fromkeys(out))


def inspect_row(row):
    """原判未命中、但去壳后命中本题真值 → 假阴性。返回证据或 None。"""
    if row.get("solved"):
        return None
    want = str(row.get("expected_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        return None
    for cand in _candidates(row):
        for v in _variants(cand):
            if hashlib.sha256(v.encode("utf-8")).hexdigest() == want:
                return {
                    "id": str(row.get("id", "?")),
                    "candidate_form": "wrapped" if "{" in cand else "bare",
                    "candidate_length": len(cand),
                    "matched_form_length": len(v),
                    "matched_form_sha8": _sha8(v),
                    "reason": "去壳变体 sha256 == 本题 expected_sha256，但 verify_flag 原判未命中",
                }
    return None


def audit(result_path):
    doc = json.load(open(result_path, encoding="utf-8"))
    details = doc.get("details", [])
    hits = [ev for row in details if isinstance(row, dict)
            for ev in [inspect_row(row)] if ev]
    return {
        "tool": "scripts/audit_scoring_variant_gap.py",
        "result_path": os.path.relpath(result_path, ROOT).replace("\\", "/"),
        "result_sha256": hashlib.sha256(open(result_path, "rb").read()).hexdigest(),
        "rows": len(details),
        "originally_solved": sum(1 for r in details if r.get("solved")),
        "false_negative_count": len(hits),
        "false_negative_ids": sorted(h["id"] for h in hits),
        "hits": sorted(hits, key=lambda h: h["id"]),
        "note": "证据不含明文答案；本审计只量化假阴性，不改判分、不重算分数。",
        "root_cause": ("scripts/experiments/flag_util.py::candidate_variants 不产生裸内容变体；"
                       "verify_flag 位于他人在途 WIP 的 ctf_stepfun_orchestrator.py，本轮未修"),
    }


def selftest():
    def row(got, want, solved=False):
        return {"id": "t", "got": got, "expected_sha256": want,
                "solved": solved, "raw_head": ""}
    secret = "zz_synthetic_secret_0001"
    bare = hashlib.sha256(secret.encode()).hexdigest()
    wrapped = hashlib.sha256(("flag{%s}" % secret).encode()).hexdigest()
    cases = [
        ("带壳候选 vs 裸内容真值 → 假阴性命中",
         row("flag{%s}" % secret, bare), True),
        ("答案错误 → 不命中", row("flag{totally_wrong}", bare), False),
        ("原判已命中 → 不计", row("flag{%s}" % secret, wrapped, solved=True), False),
        ("真值为带壳形态且原判未命中 → 命中（另一类漏判）",
         row("flag{%s}" % secret, wrapped), True),
        ("无真值指纹 → 不裁定", row("flag{%s}" % secret, ""), False),
        ("raw_head 里才出现答案 → 也能抓到",
         {"id": "t", "got": "", "expected_sha256": bare,
          "solved": False, "raw_head": "答案是 flag{%s}" % secret}, True),
    ]
    ok = 0
    for name, r, want in cases:
        got = inspect_row(r) is not None
        ok += int(got == want)
        print("%s %-48s got=%-5s want=%s" %
              ("PASS" if got == want else "FAIL", name, got, want))
    ev = inspect_row(row("flag{%s}" % secret, bare))
    no_plain = ev is not None and secret not in json.dumps(ev, ensure_ascii=False)
    ok += int(no_plain)
    print("%s 证据不含明文答案" % ("PASS" if no_plain else "FAIL"))
    total = len(cases) + 1
    print("selftest %d/%d" % (ok, total))
    return 0 if ok == total else 1


def main():
    ap = argparse.ArgumentParser(description="判分不去壳假阴性审计（只读）")
    ap.add_argument("--result", help="跑批结果 json")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.result or not os.path.isfile(args.result):
        print("需要 --result <存在的跑批结果 json>", file=sys.stderr)
        return 2
    ev = audit(args.result)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("判分不去壳假阴性 → %s" % os.path.relpath(args.out, ROOT))
    print("  %d 题，原判命中 %d，去壳后新增命中 %d 题"
          % (ev["rows"], ev["originally_solved"], ev["false_negative_count"]))
    for i in ev["false_negative_ids"][:10]:
        print("    %s" % i)
    return 0


if __name__ == "__main__":
    sys.exit(main())
