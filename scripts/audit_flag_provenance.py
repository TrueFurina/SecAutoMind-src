#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""明文 flag 命中的**溯源分档**审计（不是门禁，是让数字可解释）。

## 为什么需要它（2026-10-25 复盘）

`secret_guard` 报的「真赛事品牌 N 条（真泄露，优先清）」是个**外形启发式**：
只要前缀长得像真题品牌就算。问题是外形判不出真伪 ——
协议大小写解析夹具里那几条（`DASCTF{…}` / `Dasctf{…}`，正文是 `abc-123` /
`mixed_case` 这种装饰串）品牌前缀纯装饰；`gen_exec_artifacts_v2.py` 里的
`picoCTF{…}` 是自产工件的种子值。
上一轮实测：161 条「真泄露」里 53 条是占位符模板（已修），
剩下 99 条里**只有 32 条能在题库真值集里找到对应的 sha256**。

外形像 ≠ 是答案。唯一可机验的判据是**溯源**：这条命中算出的 sha256，
是否等于某个题库登记的 `flag_sha256`。

## 分档

| 档 | 判据 | 处置 |
|---|---|---|
| `known_answer` | sha256 ∈ 题库真值集 | **铁实锤**真题答案，最高优先级清 |
| `unknown_brand` | 品牌像真、但不在真值集 | 需人工看一眼（可能是夹具/已下线题/新题） |
| `placeholder` | 占位符形态（与 Go 引擎同判据） | 非答案，不处理 |
| `self` | 通用前缀（`flag{}` 等） | 自产构造，低优先级 |

⚠️ 口径诚实声明：真值集只覆盖**已登记 sha256 的题库**（本仓 data/ 下的
benchmark + 本地真值文件）。所以 `known_answer` 是「实锤数的**下界**」，
不是「真泄露总数」；`unknown_brand` 也不是「都不是答案」。两个数要一起看。

## 用法
    python scripts/audit_flag_provenance.py               # 人类可读
    python scripts/audit_flag_provenance.py --json        # 机读
    python scripts/audit_flag_provenance.py --top 15      # 每档按文件 TopN
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import secret_guard as sg  # noqa: E402

# 真值收集与分档**只实现一次**，在本模块的下游 secret_guard 里。这里全部复用：
# 两处各写一份 = 必然漂移（本仓在 Go/Python 占位词表上已经因此栽过一次）。


def audit(repo_root: str = REPO_ROOT, use_local: bool = True) -> dict:
    truth, tstats = sg.harvest_truth_hashes(repo_root, use_local=use_local)
    tracked = sg._git_tracked(repo_root)
    if tracked is None:
        raise RuntimeError("该目录不在 git 仓库中，无法区分入库/未入库")
    # 复用门禁那一次扫描：hits 里已带 brand 与 sha256，不必自己再走一遍文件树。
    # 自己重扫 = 两套 IO 口径（跳过规则、编码、大小上限）迟早对不上。
    hits, _untracked = sg.scan_plaintext_flags(repo_root, tracked)
    buckets: dict[str, list[dict]] = collections.defaultdict(list)
    for h in hits:
        if not h["tracked"]:
            continue
        kind = sg.provenance_of(h["brand"], h["sha256"], truth)
        buckets[kind].append({"file": h["file"], "line": h["line"],
                              "sha256": h["sha256"], "masked": h["masked"]})
    return {
        "truth_hashes": len(truth),
        "truth_stats": tstats,
        "counts": {k: len(v) for k, v in buckets.items()},
        # 同一道题的答案常在同一仓里出现几十遍（题库 + 生成器 + 报告 + 夹具），
        # 只报「处数」会把 247 道题报成 1144 条，读者无法判断到底泄了多少题。
        # 两个数必须一起报：处数说明治理工作量，不同答案数说明泄露面。
        "distinct_answers": len({r["sha256"] for r in buckets.get("known_answer", [])}),
        "buckets": {k: v for k, v in buckets.items()},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="明文 flag 命中溯源分档审计")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--repo-root", default=REPO_ROOT)
    ap.add_argument("--no-local-truth", action="store_true",
                    help="不读 data/flag_truth.local.json（模拟 CI 环境）")
    args = ap.parse_args(argv)

    rep = audit(args.repo_root, use_local=not args.no_local_truth)
    if args.json:
        print(json.dumps({k: v for k, v in rep.items() if k != "buckets"} | {
            "upstream_files": {k: v for k, v in
                               _file_counts(rep["buckets"]).items()}},
            ensure_ascii=False, indent=1))
        return 0

    c = rep["counts"]
    total = sum(c.values())
    print(f"真值集 {rep['truth_hashes']} 个 sha256"
          f"（{rep['truth_stats']['benchmark_files']} 个 benchmark json"
          f"{'，含本地真值文件 ' + str(rep['truth_stats']['local_values']) + ' 个' if rep['truth_stats']['local_file'] else '，未读本地真值文件'}）")
    print(f"已入库明文命中 {total} 条：\n")
    order = [("known_answer", "铁实锤真题答案（sha256 命中题库真值）"),
             ("unknown_brand", "品牌像真但无实锤（需人看：夹具/下线题/新题）"),
             ("placeholder", "占位符模板（非答案）"),
             ("self", "通用前缀自产构造")]
    for key, desc in order:
        if key == "known_answer" and c.get(key):
            print(f"  {c.get(key):>5}  {desc}"
                  f"  ← {rep['distinct_answers']} 道不同题（同一答案常重复出现）")
        else:
            print(f"  {c.get(key, 0):>5}  {desc}")
    print("\n⚠️ 口径：known_answer 是**下界**（只覆盖已登记 sha256 的题库），"
          "unknown_brand 也不等于「都不是答案」。两个数一起看，别单看一个。")
    print("⚠️ 口径：判据是「哈希命中真值」，**不按品牌过滤** —— "
          "`flag{真答案}` 与 `DASCTF{真答案}` 同罪；只有占位符形态除外"
          "（题库里有把 DASCTF 前缀的 printf 模板登记成答案的脏数据）。")
    for key, desc in order[:2]:
        rows = rep["buckets"].get(key, [])
        if not rows:
            continue
        print(f"\n== {key} 按文件 Top{args.top}")
        for f, n in collections.Counter(r["file"] for r in rows).most_common(args.top):
            print(f"   {n:>3}  {f}")
    return 0


def _file_counts(buckets) -> dict:
    out = {}
    for kind, rows in buckets.items():
        for r in rows:
            out.setdefault(kind, {})
            out[kind][r["file"]] = out[kind].get(r["file"], 0) + 1
    return out


if __name__ == "__main__":
    sys.exit(main())
