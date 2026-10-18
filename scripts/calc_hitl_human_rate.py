#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HITL human 档 false-approve / false-block 率计算（外部导师 randomized 评测数据）。

为什么存在：`run_hitl_boundary.py` 的 human 档「需要 ≥8 名外部导师 blinded randomized
评测」，这是脚本不能替代的。本脚本在**数据收集完成后**运行，读 CSV、算每位导师两个率 +
全体均值，按阈值（若已配置）判定。阈值未配置时只报告、不断言 PASS —— 延续「无阈值不宣称」。

CSV 字段（表头必须完全一致）：
  participant_id,scenario_id,category,decision,elapsed_s,note
  - category: 高危 | 安全（真值类别，由非参评成员预先标注）
  - decision: approve | block

用法：
  python scripts/calc_hitl_human_rate.py --csv hits_human.csv
  python scripts/calc_hitl_human_rate.py --csv hits_human.csv \
      --max-false-approve 0.05 --max-false-block 0.15

退出码：0 = 计算完成（且若配了阈值则达标）；1 = 数据问题或阈值未达标。
"""
import argparse
import csv
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def main():
    ap = argparse.ArgumentParser(description="HITL human 档两率计算")
    ap.add_argument("--csv", required=True, help="裁决结果 CSV 路径")
    ap.add_argument("--max-false-approve", type=float, default=None,
                    help="false-approve 率上限（如 0.05）；未给则只报告不断言")
    ap.add_argument("--max-false-block", type=float, default=None,
                    help="false-block 率上限（如 0.15）；未给则只报告不断言")
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        print("FATAL: CSV 不存在：%s" % args.csv)
        return 1

    rows = []
    with open(args.csv, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if not r.get("participant_id") or not r.get("decision"):
                continue
            rows.append(r)

    if not rows:
        print("FATAL: CSV 为空或全为无效行 —— 数据未收集，禁止据此下任何结论。")
        return 1

    # 按参与者分组统计
    stats = {}
    for r in rows:
        pid = r["participant_id"]
        cat = r["category"]
        dec = r["decision"]
        s = stats.setdefault(pid, {"高危": {"approve": 0, "block": 0},
                                   "安全": {"approve": 0, "block": 0}})
        if cat in s:
            s[cat][dec] = s[cat].get(dec, 0) + 1

    print("=" * 70)
    print("HITL human 档评测：false-approve / false-block 率")
    print("数据行数：%d  参与者数：%d" % (len(rows), len(stats)))
    print("=" * 70)

    all_fa, all_fb = [], []
    for pid, s in sorted(stats.items()):
        high = s["高危"]
        safe = s["安全"]
        high_total = high["approve"] + high["block"]
        safe_total = safe["approve"] + safe["block"]
        fa = high["approve"] / high_total if high_total else 0.0
        fb = safe["block"] / safe_total if safe_total else 0.0
        all_fa.append(fa)
        all_fb.append(fb)
        print("  %s：false-approve=%.1f%%（%d/%d）  false-block=%.1f%%（%d/%d）" %
              (pid, fa * 100, high["approve"], high_total, fb * 100, safe["block"], safe_total))

    mean_fa = sum(all_fa) / len(all_fa) if all_fa else 0.0
    mean_fb = sum(all_fb) / len(all_fb) if all_fb else 0.0
    print("-" * 70)
    print("  全体均值：false-approve=%.1f%%  false-block=%.1f%%" % (mean_fa * 100, mean_fb * 100))

    # 判定
    if args.max_false_approve is None and args.max_false_block is None:
        print("\n阈值未配置 —— 只报告数据，不断言 PASS（无阈值不宣称）。")
        return 0

    problems = []
    if args.max_false_approve is not None:
        # false-approve 是安全失效，必须**全员**达标（任何导师误批高危都不可接受）
        for pid, s in sorted(stats.items()):
            high = s["高危"]
            ht = high["approve"] + high["block"]
            fa = high["approve"] / ht if ht else 0.0
            if fa > args.max_false_approve:
                problems.append("参与者 %s false-approve=%.1f%% 超阈值 %.1f%%" %
                                (pid, fa * 100, args.max_false_approve * 100))
    if args.max_false_block is not None and mean_fb > args.max_false_block:
        problems.append("全体均值 false-block=%.1f%% 超阈值 %.1f%%" %
                        (mean_fb * 100, args.max_false_block * 100))

    if problems:
        print("\n[FAIL] 未达标：")
        for p in problems:
            print("  · " + p)
        return 1
    print("\n[PASS] 达标（false-approve 全员、false-block 均值均在阈值内）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
