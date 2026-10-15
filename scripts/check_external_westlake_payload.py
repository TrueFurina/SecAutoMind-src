#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部真题基准（external_westlake）载荷落地门禁。

## 为什么要这个门禁（2026-10-16 实测动机）

``data/ctf_benchmark/external_westlake/benchmark.json`` 里 **80/80 题**标着
``payload_status = "verified_on_disk"``，但附件路径是**导出方仓库**的相对路径
（``data/race_attachments/...``、``data/questions_real/_attachments/...``），
在本仓库**从未落地**——用仓库根相对与基准目录相对两种解析实测 **0/80 可解析**。

（口径提醒：80 题里 75 题用 ``attachment`` 单数字段、5 题用 ``attachments`` 复数，
只数单数字段会得到 75 这个错值；本门禁两种都认。）

而同目录的 ``judge_external_westlake.py --self-check`` 只验「字段非空」、
不验 ``os.path.exists``，照样报 ``问题=0``、rc=0。这是标准的
**「元数据兜底、不读实物」** 形态：声明看起来齐全，实物一个都没有。
PROVENANCE.md §6 甚至把这条写成了设计（"路径与存在性以 payload_status 字段为准"）。

## 判别力设计（三态，均非恒真）

| 态 | 条件 | 判据 |
|---|---|---|
| A 已挂载 | 声称题里**至少 1 题**附件可解析 | 逐题断言：所有声称题都必须解析到实物，缺一即 FAIL |
| B 未挂载 | 声称 N>0 但解析数 == 0 | 允许存在，但**禁止**被写进对外汇总/机验 claim，写了即 FAIL；并强制打印警告 |
| C 空/异常 | 题数 0 | FAIL（防「扫 0 文件 = 0 违规 = 全绿」） |

B 态允许存在不是放水——挂载附件需要先从导出方复制，属于数据准备工作；
门禁守的是**另一件事**：不许把没落地的基准当成"已经跑过分"写进对外数字。
一旦有人把它接进汇总，门禁立刻变红，逼他先挂载。

## 用法
    python scripts/check_external_westlake_payload.py            # 报数
    python scripts/check_external_westlake_payload.py --check     # 门禁断言（exit 1 = 红）
    python scripts/check_external_westlake_payload.py --json      # 机读
"""
from __future__ import annotations

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_REL = os.path.join("data", "ctf_benchmark", "external_westlake", "benchmark.json")

# 对外数字入口：这两处一旦出现 westlake 字样，即视为"被计入对外成绩"。
SUMMARY_REL = os.path.join("data", "ctf_benchmark", "all_benchmarks_summary.json")
QUANT_REL = os.path.join("docs", "quant_effect.md")

CLAIM = "verified_on_disk"


def _read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def resolve_attachment(rel, base_dirs):
    """附件能否解析到磁盘实物。

    路径可能相对仓库根（``data/...``）或相对基准目录，两种都试；
    任一命中即算存在。返回命中的绝对路径，否则 None。
    """
    if not rel:
        return None
    for base in base_dirs:
        cand = rel if os.path.isabs(rel) else os.path.join(base, rel)
        if os.path.exists(cand):
            return cand
    return None


def analyze(bench, repo_root=REPO_ROOT):
    """纯函数：统计声称数与实物解析数。供主流程与变异用例共用同一判据。"""
    probs = bench.get("problems") or {}
    base_dirs = [repo_root, os.path.join(repo_root, "data", "ctf_benchmark", "external_westlake")]

    claimed, resolved, unresolved = [], [], []
    for qid, p in probs.items():
        if p.get("payload_status") != CLAIM:
            continue
        claimed.append(qid)
        atts = p.get("attachments") or ([p["attachment"]] if p.get("attachment") else [])
        hit = None
        for a in atts:
            hit = resolve_attachment(a, base_dirs)
            if hit:
                break
        (resolved if hit else unresolved).append(qid)

    return {
        "total": len(probs),
        "claimed": claimed,
        "resolved": resolved,
        "unresolved": unresolved,
        "mode": "empty" if not probs else ("mounted" if resolved else "unmounted"),
    }


def is_referenced_externally(repo_root=REPO_ROOT):
    """该基准是否已被写进对外数字入口。"""
    hits = []
    for rel in (SUMMARY_REL, QUANT_REL):
        p = os.path.join(repo_root, rel)
        if not os.path.exists(p):
            continue
        if "westlake" in _read_text(p).lower():
            hits.append(rel)
    return hits


def violations(an, referenced):
    """纯函数：返回违规描述列表；空列表 = 通过。"""
    v = []
    if an["mode"] == "empty":
        v.append("基准解析出 0 题：对象缺失或格式变更，不得静默放过（fail-closed）")
        return v

    if an["mode"] == "mounted":
        # 已挂载：声称 verified_on_disk 就必须题题有实物，缺一即红
        if an["unresolved"]:
            v.append(
                "已挂载态下 %d 题声称 %s 但附件解析不到：%s"
                % (len(an["unresolved"]), CLAIM, ", ".join(an["unresolved"][:8]))
            )
        return v

    # 未挂载态：允许存在，但不得计入对外数字
    if referenced:
        v.append(
            "载荷未挂载（声称 %d 题、实物 0 题）却已出现在对外数字入口 %s；"
            "必须先从导出方复制附件再做路径重定位，否则跑出来是「缺载荷恒 miss」的假成绩"
            % (len(an["claimed"]), ", ".join(referenced))
        )
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description="外部真题基准载荷落地门禁")
    ap.add_argument("--check", action="store_true", help="门禁断言模式（有违规 exit 1）")
    ap.add_argument("--json", action="store_true", help="机读输出")
    args = ap.parse_args(argv)

    bench_path = os.path.join(REPO_ROOT, BENCH_REL)
    if not os.path.exists(bench_path):
        print("❌ 基准缺失：%s" % BENCH_REL)
        return 1
    try:
        bench = json.loads(_read_text(bench_path))
    except Exception as e:  # noqa: BLE001 - 解析失败必须硬失败
        print("❌ 基准解析失败：%s" % e)
        return 1

    an = analyze(bench)
    referenced = is_referenced_externally()
    vs = violations(an, referenced)

    if args.json:
        print(json.dumps({**{k: v for k, v in an.items() if k != "claimed"},
                          "claimed_n": len(an["claimed"]),
                          "referenced_externally": referenced,
                          "violations": vs}, ensure_ascii=False, indent=1))
        return 1 if vs else 0

    print("=== 外部真题基准载荷落地检查 ===")
    print("  题数 %d ｜ 声称 %s %d 题 ｜ 实物可解析 %d 题"
          % (an["total"], CLAIM, len(an["claimed"]), len(an["resolved"])))
    print("  状态: %s" % {"empty": "空基准", "mounted": "已挂载", "unmounted": "未挂载"}[an["mode"]])
    print("  对外数字入口引用: %s" % (", ".join(referenced) if referenced else "无"))
    if an["mode"] == "unmounted":
        print("  ⚠️ 载荷在本仓库未落地：附件路径是导出方仓库相对路径，"
              "需先复制/挂载才能跑；在此之前把它计入任何成绩都是假的。")
    print()

    if not args.check:
        print("（报数模式，未做断言；加 --check 进入门禁判定）")
        return 0

    if vs:
        print("❌ 违规 %d 条：" % len(vs))
        for x in vs:
            print("   -", x)
        return 1
    print("✅ PASS —— 无违规")
    return 0


if __name__ == "__main__":
    sys.exit(main())
