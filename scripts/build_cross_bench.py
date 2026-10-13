#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把西湖论剑（A 库）的 93 道真题搬成 SecAutoMind（B 库）可跑的同卷基准。

定位（规划 §2.2）：**仅作尺，不混入 B 题库刷数字**。
  - 产物落在 `data/questions_real_bench/`（独立目录），
    **不进** `data/ctf_benchmark/` —— 后者是 B 的 KPI 基准，混进去会污染对外数字。

诚实约束（写死在产物里，防止后人口径漂移）：
  - A 侧 93 题的挑战数据（附件）**大部分已缺失**（实测仅 13/93 的附件路径仍存在）。
    故本基准是**文本口径**（只喂 description），测出的是 B 的**下限**，
    不是 B 的能力上限，也不代表 A 当时的真实水位。
  - flag 一律沿用 A 的 `flag` 字段（sha256 真值），B 侧命中判定同样用 sha256 比对，
    符合"无外部真值不计入战果"的铁律。
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
from collections import Counter

OUT_DIR = os.path.join("data", "questions_real_bench")
OUT_FILE = os.path.join(OUT_DIR, "cross_bench.json")
REPORT = os.path.join(OUT_DIR, "cross_bench_source_stats.json")


def is_sha256(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


def load_source(src: str):
    """读取 A 库真题，返回 (题目列表, 附件可用性统计)。"""
    files = sorted(glob.glob(os.path.join(src, "**", "*.json"), recursive=True))
    base = os.path.dirname(os.path.dirname(os.path.abspath(src)))  # ctf_agent 根
    probs, att_ok, att_missing = [], 0, 0
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as e:  # noqa: BLE001
            print(f"  [WARN] 跳过无法解析的 {f}: {e}", file=sys.stderr)
            continue
        qid = str(d.get("id") or os.path.splitext(os.path.basename(f))[0])
        flag = d.get("flag") or ""
        if not is_sha256(flag):
            # 非 sha256 的 flag 不是外部真值，按铁律不计入本题
            print(f"  [SKIP] {qid}: flag 非 sha256 真值，不纳入", file=sys.stderr)
            continue
        atts = d.get("attachments") or []
        ok = any(os.path.exists(os.path.join(base, a)) for a in atts) if atts else False
        if atts and ok:
            att_ok += 1
        else:
            att_missing += 1
        probs.append({
            "id": qid,
            "category": d.get("category") or "misc",
            "sub": d.get("category") or "misc",
            "description": d.get("description") or "",
            "title": d.get("title") or "",
            "flag_sha256": flag.lower(),
            "difficulty": d.get("difficulty") or "",
            "attachment_declared": bool(atts),
            "attachment_available": ok,
        })
    return probs, att_ok, att_missing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="A 库 questions_real 目录")
    ap.add_argument("--check", action="store_true", help="只校验不写盘")
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        print(f"[FAIL] 源目录不存在: {args.src}", file=sys.stderr)
        return 1

    probs, att_ok, att_missing = load_source(args.src)
    if not probs:
        print("[FAIL] 未读到任何题目", file=sys.stderr)
        return 1

    cats = Counter(p["category"] for p in probs)
    doc = {
        "version": "v1",
        "created": "2026-10-13",
        "source": {
            "repo": "西湖论剑 CTF-Agent (A 库)",
            "path": os.path.abspath(args.src),
            "note": "仅作尺；不并入 B 的 KPI 基准 data/ctf_benchmark/",
        },
        "honesty": {
            "input_mode": "text-only",
            "why": "A 侧 93 题中挑战数据(附件)仅 13 题仍存在，其余路径已失效；"
                   "本基准只喂 description，测得的是 B 的下限而非能力上限。",
            "attachment_available": att_ok,
            "attachment_missing": att_missing,
            "flag_truth": "沿用 A 的 flag 字段(sha256)，命中判定用 sha256 比对",
        },
        "problems": {p["id"]: p for p in probs},
    }
    stats = {
        "total": len(probs),
        "by_category": dict(cats),
        "attachment_available": att_ok,
        "attachment_missing": att_missing,
        "sha256_of_doc": hashlib.sha256(
            json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
    }

    print("=" * 62)
    print(f"  cross-bench 基准构建  题数={len(probs)}")
    print("=" * 62)
    for k, v in sorted(cats.items()):
        print(f"    {k:<10} {v}")
    print(f"    附件仍存在  {att_ok}    附件已缺失  {att_missing}")
    print(f"    🔴 输入口径：仅 description（文本口径，非完整同卷）")

    if args.check:
        print("[check] 未写盘")
        return 0

    os.makedirs(OUT_DIR, exist_ok=True)
    for path, payload in ((OUT_FILE, doc), (REPORT, stats)):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"  已写入 {OUT_FILE}")
    print(f"  已写入 {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
