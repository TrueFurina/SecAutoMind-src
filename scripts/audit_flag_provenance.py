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

HEX64 = re.compile(r"^[0-9a-f]{64}$")
# 题库里表示「答案哈希」的键名（含各 benchmark 的历史命名变体）
SHA_KEY_HINTS = ("flag_sha256", "answer_sha256", "expected_sha256", "sha256")


def _iter_sha_values(doc):
    """深度遍历任意 JSON 结构，产出所有像 sha256 的字符串值。"""
    stack = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, str) and HEX64.match(v.lower()):
                    stack_keys = k.lower()
                    if any(h in stack_keys for h in SHA_KEY_HINTS):
                        yield v.lower()
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(x for x in cur if isinstance(x, (dict, list)))


def harvest_truth(repo_root: str = REPO_ROOT, use_local: bool = True) -> tuple[set, dict]:
    """收集题库真值 sha256 集。返回 (集合, 统计)。"""
    truth: set[str] = set()
    stats = {"benchmark_files": 0, "local_file": False, "local_values": 0}
    data_dir = os.path.join(repo_root, "data")
    local_path = os.path.join(data_dir, "flag_truth.local.json")
    for dp, dn, fn in os.walk(data_dir):
        dn[:] = [d for d in dn if d not in sg.SKIP_DIRS]
        for f in fn:
            if not f.endswith(".json"):
                continue
            path = os.path.join(dp, f)
            # 本地真值文件**永远**从常规扫描里排除，只在 use_local=True 时显式加入。
            # 否则 `use_local=False`（模拟 CI 环境）会偷偷把它算进来 —— 那这个开关
            # 就只是装饰，报出来的「CI 口径」是假的。实测被这一条抓过。
            if os.path.abspath(path) == os.path.abspath(local_path):
                continue
            try:
                if os.path.getsize(path) > 8 * 1024 * 1024:
                    continue
                doc = json.load(open(path, encoding="utf-8"))
            except Exception:
                continue
            stats["benchmark_files"] += 1
            truth.update(_iter_sha_values(doc))
    if use_local:
        if os.path.isfile(local_path):
            try:
                doc = json.load(open(local_path, encoding="utf-8"))
                vals = set(_iter_sha_values(doc))
                stats["local_file"] = True
                stats["local_values"] = len(vals)
                truth.update(vals)
            except Exception:
                pass
    return truth, stats


def classify_hit(raw: str, truth: set[str]) -> tuple[str, str]:
    """返回 (档位, sha256)。档位含 placeholder/self 时 sha256 仍给出，便于人工核对。"""
    sha = hashlib.sha256(raw.encode()).hexdigest()
    brand = sg.classify_brand(raw)
    if brand == "placeholder":
        return "placeholder", sha
    if brand == "self":
        return "self", sha
    return ("known_answer" if sha in truth else "unknown_brand"), sha


def _iter_tracked_flag_hits(repo_root: str, tracked: set[str]):
    """重扫一遍并保留 raw（secret_guard 的 hits 只存打码值，算不了哈希）。"""
    for dp, dn, fn in os.walk(repo_root):
        dn[:] = [d for d in dn if d not in sg.SKIP_DIRS]
        for f in fn:
            ext = os.path.splitext(f)[1].lower()
            if ext in sg.SKIP_FILE_SUFFIX:
                continue
            if ext and ext not in sg.TEXT_EXT and f not in (".env", "Dockerfile"):
                continue
            path = os.path.join(dp, f)
            try:
                if os.path.getsize(path) > sg.MAX_FILE_BYTES:
                    continue
                text = open(path, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            rel = os.path.relpath(path, repo_root).replace("\\", "/")
            if rel not in tracked:
                continue
            for m in sg.FLAG_CAND_RE.finditer(text):
                raw = m.group(0)
                if sg.FLAG_PLACEHOLDER_RE.search(raw):
                    continue
                if not sg._flag_is_printable(raw):
                    continue
                yield rel, text.count("\n", 0, m.start()) + 1, raw


def audit(repo_root: str = REPO_ROOT, use_local: bool = True) -> dict:
    truth, tstats = harvest_truth(repo_root, use_local)
    tracked = sg._git_tracked(repo_root)
    if tracked is None:
        raise RuntimeError("该目录不在 git 仓库中，无法区分入库/未入库")
    buckets: dict[str, list[dict]] = collections.defaultdict(list)
    for rel, line, raw in _iter_tracked_flag_hits(repo_root, tracked):
        kind, sha = classify_hit(raw, truth)
        buckets[kind].append({"file": rel, "line": line, "sha256": sha,
                              "masked": sg.mask(raw)})
    return {
        "truth_hashes": len(truth),
        "truth_stats": tstats,
        "counts": {k: len(v) for k, v in buckets.items()},
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
        print(f"  {c.get(key, 0):>5}  {desc}")
    print("\n⚠️ 口径：known_answer 是**下界**（只覆盖已登记 sha256 的题库），"
          "unknown_brand 也不等于「都不是答案」。两个数一起看，别单看一个。")
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
