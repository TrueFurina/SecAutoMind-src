#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""附件可用性盘点：产出「哪些题真的能跑」的权威分母。

为什么需要（2026-11-02）
-----------------------
实测反复踩到同一个坑：跑批报告写 ``total=0 solved=0``，看起来像「跑了但没解出」，
实际是「**根本没跑**」——题目的附件在磁盘上不存在，``apply_corpus_gate`` 全判
``no_input`` 跳过了。这是本项目最贵的假动作：它把「数据缺失」伪装成「能力不足」。

本脚本不改任何代码、不跑任何题，只回答一个问题：
**给定当前磁盘状态，每个题库池里有多少题是真正可跑的（有输入 + 有真值）。**

口径（复用，不另造）
-------------------
全部判定走 ``eval.corpus`` 的单一真相源：
  · ``attachment_health`` —— 附件磁盘可用度
  · ``has_input``         —— 有输入（无附件登记 = 纯文本题，也算有输入）
  · ``has_truth``         —— 有可校验真值（64 位 hex sha256 或明文 flag）
  · ``measurable``        —— 两者皆真，才能计入 KPI 分母
本脚本只做**聚合与呈现**，任何一条判定都不自己实现。

🔴 同时显式报告 cwd 敏感性（2026-11-02 实测发现）
------------------------------------------------
``attachment_health`` 用 ``os.path.isfile(str(a))`` 判定，附件路径几乎全是
**相对 ctf_agent/** 的（如 ``data/questions_real/_attachments/...``）。
于是同一份题库，从不同目录启动得到的可测量题数完全不同：
  · cwd=ctf_agent/      → real 13 / external 39 / ext 34
  · cwd=CTF-Agent_融合/ → real  1 / external  0 / ext  0
这不是本脚本的 bug，是被测口径的既有缺陷（与 ``_preload_attachment_evidence``
那个已修的同类问题同源）。本脚本**必须**把这个差异摆出来，否则对外数字会随
启动目录漂移而无人察觉。

用法：
    python scripts/audit_attachment_availability.py
    python scripts/audit_attachment_availability.py --json out.json
    python scripts/audit_attachment_availability.py --pool data/questions_real

退出码：0 正常 / 2 参数或输入错误
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                        # ctf_agent/
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.cases import Question                      # noqa: E402
from eval.corpus import (                            # noqa: E402
    DEFAULT_ROOTS, attachment_health, has_input, has_truth, measurable,
)

#: 参与盘点的池（按可信度排序，与 eval.corpus.DEFAULT_ROOTS 同序）
POOLS = list(DEFAULT_ROOTS)


def _iter_question_dicts(pool_dir: Path):
    """遍历池内所有题目 JSON，产出 (文件路径, dict)。"""
    if not pool_dir.is_dir():
        return
    for f in sorted(pool_dir.rglob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items = data if isinstance(data, list) else [data]
        for q in items:
            if isinstance(q, dict) and q.get("id"):
                yield f, q


def _to_question(q: dict) -> Question:
    return Question(
        id=str(q["id"]),
        title=str(q.get("title") or ""),
        category=str(q.get("category") or ""),
        difficulty=str(q.get("difficulty") or ""),
        attachments=list(q.get("attachments") or []),
        flag=q.get("flag"),
        flag_sha256=q.get("flag_sha256"),
    )


def audit_pool(pool: str) -> dict:
    """盘点单个池。返回聚合结果 + 逐题明细。"""
    pdir = ROOT / pool
    rows = []
    for _f, qd in _iter_question_dicts(pdir):
        q = _to_question(qd)
        h = attachment_health(q)
        rows.append({
            "id": q.id,
            "category": q.category,
            "declared": h.declared,
            "existing": h.existing,
            "missing_sample": list(h.missing[:3]),
            "has_input": has_input(q),
            "has_truth": has_truth(q),
            "measurable": measurable(q),
            # 三态分类：可跑 / 缺输入 / 缺真值（后者极少，但必须能看见）
            "status": ("runnable" if measurable(q)
                       else "no_input" if not has_input(q)
                       else "no_truth"),
        })

    total = len(rows)
    runnable = sum(1 for r in rows if r["measurable"])
    no_input = sum(1 for r in rows if not r["has_input"])
    no_truth = sum(1 for r in rows if r["has_input"] and not r["has_truth"])
    # 「登记了附件但一个都不在」是最典型的 no_input 成因，单独计数
    declared_but_all_missing = sum(
        1 for r in rows if r["declared"] > 0 and r["existing"] == 0)

    return {
        "pool": pool,
        "dir_exists": pdir.is_dir(),
        "total": total,
        "runnable": runnable,
        "no_input": no_input,
        "no_truth": no_truth,
        "declared_but_all_missing": declared_but_all_missing,
        "by_category": dict(Counter(r["category"] or "?" for r in rows)),
        "runnable_by_category": dict(Counter(
            r["category"] or "?" for r in rows if r["measurable"])),
        "rows": rows,
    }


def cwd_probe() -> dict:
    """在同一份题库上，从不同 cwd 各测一次，暴露口径的 cwd 敏感性。

    这是本脚本最重要的输出之一：如果两个 cwd 结果不同，说明
    `attachment_health` 的相对路径解析不可移植，对外数字会随启动目录漂移。

    实现要点：**题目文件本身**始终从 ``ROOT/pool`` 读（保证三项口径用的是同一批题），
    只切换 ``os.chdir`` —— 这恰好复现生产情形：进程从不同目录启动，但读的是同一批 JSON。
    ``attachment_health`` 内部的 ``os.path.isfile(相对路径)`` 会按新 cwd 解析，
    于是能真实暴露「同一道题在不同 cwd 下判定不同」。
    """
    targets = {
        "ctf_agent/（生产跑批的 cwd）": ROOT,
        "CTF-Agent_融合/（上一层）": ROOT.parent,
        "SecAutoMind/（仓库根）": ROOT.parent.parent,
    }
    old = os.getcwd()
    out = {}
    try:
        for label, chdir_to in targets.items():
            if not chdir_to.is_dir():
                continue
            os.chdir(chdir_to)
            snap = {}
            for pool in POOLS:
                pdir = ROOT / pool          # 读题始终用绝对位置
                if not pdir.is_dir():
                    snap[pool] = None
                    continue
                runnable = total = 0
                for _f, qd in _iter_question_dicts(pdir):
                    q = _to_question(qd)
                    total += 1
                    if measurable(q):
                        runnable += 1
                snap[pool] = {"total": total, "runnable": runnable}
            out[label] = {"cwd": str(chdir_to), "pools": snap}
    finally:
        os.chdir(old)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="附件可用性盘点")
    ap.add_argument("--pool", action="append", default=None,
                    help=f"只盘指定池（可多次）。默认全部：{POOLS}")
    ap.add_argument("--json", default="", help="把完整结果写到该 JSON 路径")
    ap.add_argument("--no-cwd-probe", action="store_true",
                    help="跳过 cwd 敏感性探测（较慢）")
    args = ap.parse_args(argv)

    pools = args.pool or POOLS
    # 显式指定却不存在 → 参数错误，fail-closed；
    # 默认全量里某个池不存在 → 正常（DEFAULT_ROOTS 含历史目录，如 data/questions
    # 已在迁移中消失），跳过并留痕，不应让整个盘点失败。
    if args.pool:
        bad = [p for p in pools if not (ROOT / p).is_dir()]
        if bad:
            print(f"❌ 池目录不存在：{bad}", file=sys.stderr)
            return 2
    absent = [p for p in pools if not (ROOT / p).is_dir()]
    pools = [p for p in pools if (ROOT / p).is_dir()]
    if not pools:
        print("❌ 没有任何可用池", file=sys.stderr)
        return 2

    print("=" * 78)
    print("附件可用性盘点（口径：eval.corpus.measurable，单一真相源）")
    print(f"cwd = {os.getcwd()}")
    if absent:
        print(f"ℹ️  跳过不存在的池（DEFAULT_ROOTS 历史项）：{absent}")
    print("=" * 78)

    results = [audit_pool(p) for p in pools]

    # ── 汇总表 ──
    print(f"\n{'池':<26}{'题数':>6}{'可跑':>6}{'缺输入':>8}{'缺真值':>8}{'附件全缺':>10}")
    print("-" * 78)
    grand = {"total": 0, "runnable": 0, "no_input": 0, "no_truth": 0}
    for r in results:
        print(f"{r['pool']:<26}{r['total']:>6}{r['runnable']:>6}"
              f"{r['no_input']:>8}{r['no_truth']:>8}"
              f"{r['declared_but_all_missing']:>10}")
        for k in grand:
            grand[k] += r[k]
    print("-" * 78)
    print(f"{'合计':<26}{grand['total']:>6}{grand['runnable']:>6}"
          f"{grand['no_input']:>8}{grand['no_truth']:>8}")

    # ── 可跑题的类别分布（这才是能对外说的能力分母构成）──
    print("\n可跑题按类别分布：")
    for r in results:
        if r["runnable"]:
            dist = ", ".join(f"{k}={v}" for k, v in
                             sorted(r["runnable_by_category"].items(), key=lambda x: -x[1]))
            print(f"  {r['pool']}: {dist}")

    # ── 缺输入题的原因抽样 ──
    print("\n缺输入题的缺失附件样例（前 5 题）：")
    shown = 0
    for r in results:
        for row in r["rows"]:
            if row["status"] == "no_input" and row["declared"] > 0:
                print(f"  [{r['pool']}] {row['id']}")
                for m in row["missing_sample"]:
                    print(f"      ✗ {m}")
                shown += 1
                if shown >= 5:
                    break
        if shown >= 5:
            break
    if shown == 0:
        print("  （无）")

    # ── cwd 敏感性 ──
    probe = {}
    if not args.no_cwd_probe:
        print("\n" + "=" * 78)
        print("cwd 敏感性探测（同一份题库，从不同目录启动）")
        print("=" * 78)
        probe = cwd_probe()
        for label, info in probe.items():
            cells = []
            for pool, v in info["pools"].items():
                short = pool.split("/")[-1]
                if v is None:
                    cells.append(f"{short}=—")
                else:
                    cells.append(f"{short}={v['runnable']}/{v['total']}")
            print(f"  {label:<32} " + "  ".join(cells))

        # 判定是否漂移
        sigs = set()
        for info in probe.values():
            sig = tuple(sorted(
                (p, None if v is None else v["runnable"]) for p, v in info["pools"].items()))
            sigs.add(sig)
        print()
        if len(sigs) > 1:
            print("  🔴 结论：可跑题数**随 cwd 漂移** —— `attachment_health` 的相对路径")
            print("     解析不可移植。对外引用分母时必须绑定 cwd=ctf_agent/，")
            print("     或先修口径（与 _preload_attachment_evidence 的已修问题同源）。")
        else:
            print("  ✅ 结论：可跑题数不随 cwd 变化。")

    if args.json:
        payload = {
            "cwd": os.getcwd(),
            "pools": [{k: v for k, v in r.items() if k != "rows"} for r in results],
            "summary": grand,
            "details": results,
            "cwd_probe": probe,
        }
        Path(args.json).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n完整结果已写入：{args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
