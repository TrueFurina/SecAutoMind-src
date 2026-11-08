#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""题面自曝答案审计：补上 `check_benchmark_plaintext_answer.py` 的空洞绿。

2026-11-06 全量 160 题跑批后复核发现：干净池里有题面写着
「writeup 明确给出 <X>。flag{端口}。」这类句子（X 为短裸内容值，
按 R10 本文件不落真值明文）。现有门禁 `answer_is_in_statement()`
只把 `FLAG_RE`（`word{content}`）token 过 `candidate_variants` 对撞
`flag_sha256`，而 `candidate_variants("flag{<X>}")` 只返回它自己
（**不产生裸内容变体**）⇒ 真值登记为 `sha256(<X>)` 时，
题面里的 X 永远扫不到，门禁报「零违规/零伪解」。

本脚本不依赖明文答案字段，**纯 sha256 反查**：
  1. 把题面切成词法 token（长度 1–64）；
  2. 对每题，用该题 `flag_sha256` 反查 token 的全部常见形态
     （裸内容 / 常见赛事前缀包裹 / 题面里出现过的 `word{}` 形态）；
  3. 命中即判「题面自曝答案」，并检查是否含自然语言自曝措辞
     （writeup / 题解 / 明确给出 / 答案是 …）。

宁可多报不漏报：题面里出现与真值裸内容完全相同的普通词（例如答案 `1`
而题面写了数字 1），本身就可能让模型照抄得分，也应剔除。

⚠️ 输出**绝不写明文答案**，只写命中形态的长度与 sha8 前缀（项目红线）。

用法：
  python scripts/audit_writeup_answer.py                 # 扫全部 *benchmark*.json
  python scripts/audit_writeup_answer.py --verify       # 复核证据与题库集合一致
  python scripts/audit_writeup_answer.py --selftest     # 分类逻辑变异验证
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_benchmark_plaintext_answer import (GLOB, SKIP_FILES, REPO_ROOT,  # noqa: E402
                                              self_disclosure_in_statement)

EVIDENCE = os.path.join(REPO_ROOT, "docs", "evidence", "capability_eval_20261105",
                        "writeup_answer_audit.json")


def inspect_problem(pid: str, prob: dict) -> dict | None:
    """命中返回证据（无明文）；未命中返回 None。

    判据单一真值源 = check_benchmark_plaintext_answer.self_disclosure_in_statement
    （2026-11-06 收紧门禁时迁移）。本函数只负责补上题号，**不另实现判据**，
    避免「门禁一套、审计一套」再次产生口径漂移。
    """
    ev = self_disclosure_in_statement(prob)
    if ev is None:
        return None
    out = {"id": pid}
    out.update(ev)
    return out


def _iter_pool_files():
    for path in sorted(glob.glob(os.path.join(REPO_ROOT, GLOB))):
        if os.path.basename(path) in SKIP_FILES:
            continue
        yield path


def audit() -> dict:
    files = []
    hits = []
    total = 0
    for path in _iter_pool_files():
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except (ValueError, OSError):
            continue
        probs = doc.get("problems", doc)
        if isinstance(probs, list):
            probs = {p.get("id", str(i)): p for i, p in enumerate(probs)}
        if not isinstance(probs, dict):
            continue
        n_hit = 0
        for pid, prob in probs.items():
            total += 1
            ev = inspect_problem(pid, prob)
            if ev:
                n_hit += 1
                ev["file"] = os.path.basename(path)
                hits.append(ev)
        files.append({"file": os.path.basename(path), "problems": len(probs),
                      "answer_in_statement": n_hit})
    by_pool = {}
    for h in hits:
        by_pool[h["pool"]] = by_pool.get(h["pool"], 0) + 1
    return {
        "tool": "scripts/audit_writeup_answer.py",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "glob": GLOB,
        "files_scanned": len(files),
        "problems_scanned": total,
        "answer_in_statement_total": len(hits),
        "self_disclosing_wording_count": sum(1 for h in hits if h["self_disclosing_wording"]),
        "by_pool": dict(sorted(by_pool.items(), key=lambda x: -x[1])),
        "files_with_hits": [f for f in files if f["answer_in_statement"]],
        "hits": sorted(hits, key=lambda h: (h["file"], h["id"])),
        "note": "证据不含明文答案，只有命中形态长度与 sha8；判分不读本文件，本审计只用于剔除题池/收紧门禁。",
        "existing_gate_gap": (
            "check_benchmark_plaintext_answer.py::answer_is_in_statement 只扫 word{content} "
            "且 candidate_variants 不产生裸内容变体 ⇒ 自然语言自曝答案的题被判为零违规（空洞绿）"
        ),
    }


def selftest() -> int:
    def prob(desc, sha):
        return {"description": desc, "flag_sha256": sha}
    synth = "zzz_synthetic_value"
    bare = hashlib.sha256(synth.encode()).hexdigest()
    wrapped = hashlib.sha256(("flag{%s}" % synth).encode()).hexdigest()
    cases = [
        ("自然语言自曝裸内容", prob("writeup 明确给出 %s。flag{端口}。" % synth, bare), True),
        ("题面不含答案", prob("分析流量包，找出端口号。", bare), False),
        ("真值为带壳形态", prob("题解给出 flag{%s}。" % synth, wrapped), True),
        ("无 flag_sha256 不裁定", {"description": "writeup 明确给出 %s" % synth}, False),
        ("同题词但不等值", prob("writeup 明确给出 another_value。", bare), False),
        ("自曝措辞识别", prob("writeup 明确给出 %s。" % synth, bare), True),
    ]
    ok = 0
    for name, p, want in cases:
        got = inspect_problem("x", p) is not None
        ok += int(got == want)
        print("%s %-28s got=%-5s want=%s" %
              ("PASS" if got == want else "FAIL", name, got, want))
    ev = inspect_problem("x", prob("writeup 明确给出 %s。" % synth, bare))
    no_plain = ev is not None and synth not in json.dumps(ev, ensure_ascii=False)
    ok += int(no_plain)
    print("%s 证据不含明文答案" % ("PASS" if no_plain else "FAIL"))
    print("selftest %d/%d" % (ok, len(cases) + 1))
    return 0 if ok == len(cases) + 1 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="题面自曝答案审计（sha256 反查，无明文输出）")
    ap.add_argument("--out", default=EVIDENCE)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.verify:
        if not os.path.isfile(args.out):
            print("证据不存在", file=sys.stderr)
            return 2
        saved = json.load(open(args.out, encoding="utf-8"))
        now = audit()
        same = (saved.get("files_scanned") == now["files_scanned"]
                and saved.get("problems_scanned") == now["problems_scanned"]
                and saved.get("answer_in_statement_total") == now["answer_in_statement_total"]
                and saved.get("hits") == now["hits"])
        print("%s 证据与题库集合%s" % ("PASS" if same else "FAIL",
                                    "一致" if same else "不一致/已漂移"))
        return 0 if same else 1
    ev = audit()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    # `newline="\n"`：Windows 的文本模式会写 \r\n ⇒ 同一份证据在 Linux 上复现
    # 不出来，提交时整文件 83 行全变（2026-11-08 实锤，实质只改了 2 个计数）。
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(ev, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("题面自曝答案审计 → %s" % os.path.relpath(args.out, REPO_ROOT))
    print("  扫描 %d 集 / %d 题" % (ev["files_scanned"], ev["problems_scanned"]))
    print("  题面即答案: %d 题（其中含自然语言自曝措辞 %d 题）" %
          (ev["answer_in_statement_total"], ev["self_disclosing_wording_count"]))
    print("  按池: %s" % ev["by_pool"])
    for f in ev["files_with_hits"]:
        print("    %-52s %d 题" % (f["file"], f["answer_in_statement"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
