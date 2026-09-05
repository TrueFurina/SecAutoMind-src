#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backfill_e5_supervisor.py — 补跑 E5 supervisor 编排模式（1 轮），并修正 channel 标注。

背景：E5 三模式对照中 deep/plan_execute 已有效（qwen3.7-max 付费裸名），supervisor 因
账户 400 只有 0.7s 空壳。用户换新千问账号 key（环境变量 DASHSCOPE_API_KEY）后补跑。

口径修正：原 experiments-e5-qwen-20260905.json channel 标为 qwen3.7-max-2026-06-08（免费池 ID），
但实际运行模型为付费裸名 qwen3.7-max —— 一并修正为 qwen3.7-max（付费）。三模式严格同模型同任务可比。

用法：
  python scripts/experiments/backfill_e5_supervisor.py [--rounds 1]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_experiments as RE  # noqa: E402

CHANNEL = "qwen3.7-max(付费裸名, dashscope)"
EVIDENCE = os.path.join(RE.EVIDENCE_DIR, "experiments-e5-qwen-20260905.json")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=1)
    args = ap.parse_args()

    client = RE.SamClient()
    client.login()
    print(f"已登录平台 {client.base}", flush=True)
    try:
        RE.assert_platform_alive(client)
        print("平台健康检查通过", flush=True)
    except RE.PlatformDown as e:
        print(f"⛔ 启动前健康检查失败: {e}", flush=True)
        return 2

    if not os.path.exists(EVIDENCE):
        print(f"⛔ 找不到既有证据文件: {EVIDENCE}")
        return 2
    d = json.load(open(EVIDENCE, encoding="utf-8"))
    sc = RE.GROUND_TRUTH["scenarios"]["S1"]

    mode = "supervisor"
    scores, durs, tools, loops = [], [], [], []
    print(f"\n=== [E5 backfill] 编排模式: {mode} · {args.rounds} 轮 ===", flush=True)
    for i in range(1, args.rounds + 1):
        print(f"  轮次 {i}/{args.rounds} ...", flush=True)
        try:
            RE.assert_platform_alive(client)
        except RE.PlatformDown as e:
            print(f"    ⛔ 平台不可用，中断: {e}", flush=True)
            return 2
        r = client.run_agent(RE.E5_TASK, orchestration=mode,
                             overall_timeout=600)
        j = RE.judge_run(r, sc)
        scores.append(j)
        durs.append(r["duration_ms"])
        tools.append(r["tool_call_count"])
        loops.append(1 if r["finalized"] else 0)
        print(f"    → {r['duration_ms']/1000:.1f}s  工具{r['tool_call_count']}次  "
              f"闭环={'✅' if r['finalized'] else '❌'}  "
              f"漏洞{j['vuln_found']}/{j['vuln_expected']}"
              + (f"  ERR={r['error']}" if r["error"] else ""), flush=True)

    d["modes"][mode] = {
        "rounds": args.rounds,
        "closed_loop_rate": round(sum(loops) / len(loops), 4) if loops else 0,
        "duration_ms_avg": round(sum(durs) / len(durs), 1) if durs else 0,
        "tool_calls_avg": round(sum(tools) / len(tools), 2) if tools else 0,
        "vuln_recall_avg": round(
            sum(s["vuln_recall"] or 0 for s in scores) / len(scores), 4) if scores else 0,
        "vuln_found_each": [s["vuln_found"] for s in scores],
        "duration_s_each": [round(dms / 1000, 1) for dms in durs],
        "closed_each": [bool(x) for x in loops],
    }
    # 口径修正：实际运行模型 = 付费裸名 qwen3.7-max（非免费池 ID）
    d["channel"] = CHANNEL
    d["channel_note"] = ("E5 三模式对照（deep/plan_execute/supervisor）严格同模型同任务可比："
                         "均为 qwen3.7-max（dashscope 付费裸名，2026-09-05 新千问账号 key 经 "
                         "环境变量 DASHSCOPE_API_KEY 注入）。supervisor 于 12:0x 由 "
                         "backfill_e5_supervisor.py 补跑。")
    d["backfill_note"] = "supervisor 补跑 + channel 口径修正 @ " + datetime.now().isoformat()
    d["finished_at"] = datetime.now().isoformat()
    with open(EVIDENCE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    print(f"\n已更新 → {EVIDENCE}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
