#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qwen_s3_e5.py — qwen3.7-max-2026-06-08 通道补跑（S3 主机场景 + E5 三编排对照）

背景：deepseek 通道余额耗尽（402），E1/E2 主数据中 S1/S2 有效、S3 三轮空壳作废。
用户 2026-09-05 充值后确认「只走免费额度模型」→ 用 qwen3.7-max-2026-06-08
（1M tokens 免费额度，未消耗）补跑缺口。

口径纪律（数字必须同质）：
  - 本脚本产物全部标注 channel=deepseek 之外的新口径 qwen3.7-max-2026-06-08
  - 文件名带 -qwen 后缀，绝不覆盖 deepseek 主 JSON
  - E5 三模式（deep/plan_execute/supervisor）同通道同任务 → 内部可比

用法：
  python scripts/experiments/qwen_s3_e5.py --s3-rounds 3 --e5-rounds 2
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_experiments as RE  # noqa: E402  (复用 TASKS/E5_TASK/GROUND_TRUTH/judge_run/assert)

CHANNEL = "qwen3.7-max-2026-06-08"
CHANNEL_NOTE = ("跨通道数据禁止合并统计。S1/S2 为 deepseek-chat 口径"
                f"（experiments-e1e2-20260905.json），本文件为 {CHANNEL} 口径。")


def _save(payload: dict, tag: str, day: str) -> str:
    os.makedirs(RE.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(RE.EVIDENCE_DIR, f"experiments-{tag}-{day}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def run_s3(client, rounds: int, day: str):
    sid = "S3"
    sc = RE.GROUND_TRUTH["scenarios"][sid]
    out = {
        "experiment": "E1+E2 (S3 only, qwen 补跑)",
        "channel": CHANNEL,
        "channel_note": CHANNEL_NOTE,
        "started_at": datetime.now().isoformat(),
        "rounds": rounds,
        "scenario": sid,
        "name": sc["name"],
        "target": sc["target"],
        "task": RE.TASKS[sid],
        "runs": [],
        "summary": {},
    }
    scores = []
    print(f"\n=== [qwen:{CHANNEL}] {sid} {sc['name']} · {rounds} 轮 ===", flush=True)
    for i in range(1, rounds + 1):
        print(f"  轮次 {i}/{rounds} ...", flush=True)
        try:
            RE.assert_platform_alive(client)
        except RE.PlatformDown as e:
            print(f"    ⛔ 平台不可用，中断: {e}", flush=True)
            out["aborted"] = {"reason": str(e), "round": i,
                              "at": datetime.now().isoformat()}
            out["finished_at"] = datetime.now().isoformat()
            _save(out, "e1e2-s3-qwen", day)
            return out
        r = client.run_agent(RE.TASKS[sid], orchestration="deep",
                             overall_timeout=600)
        j = RE.judge_run(r, sc)
        out["runs"].append({"round": i, "raw": r, "score": j})
        scores.append(j)
        print(f"    → {r['duration_ms']/1000:.1f}s  工具{r['tool_call_count']}次  "
              f"闭环={'✅' if r['finalized'] else '❌'}  "
              f"指纹{j['fingerprint_hit']}/{j['fingerprint_expected']}  "
              f"漏洞{j['vuln_found']}/{j['vuln_expected']}  HITL{r['hitl_count']}次"
              + (f"  ERR={r['error']}" if r["error"] else ""), flush=True)
    closed = sum(1 for s in scores if s["closed_loop"])
    recalls = [s["vuln_recall"] for s in scores if s["vuln_recall"] is not None]
    out["summary"] = {
        "closed_loop_rate": round(closed / len(scores), 4) if scores else 0,
        "vuln_found_each": [s["vuln_found"] for s in scores],
        "vuln_recall_each": recalls,
        "vuln_recall_avg": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "fingerprint_each": [f"{s['fingerprint_hit']}/{s['fingerprint_expected']}"
                             for s in scores],
        "duration_s_each": [round(s["duration_ms"] / 1000, 1) for s in scores],
        "tool_calls_each": [s["tool_call_count"] for s in scores],
        "hitl_each": [s["hitl_count"] for s in scores],
    }
    out["finished_at"] = datetime.now().isoformat()
    p = _save(out, "e1e2-s3-qwen", day)
    print(f"\nS3(qwen) 完成 → {p}", flush=True)
    return out


def run_e5(client, rounds: int, day: str):
    out = {
        "experiment": "E5 多策略对照",
        "channel": CHANNEL,
        "channel_note": CHANNEL_NOTE,
        "started_at": datetime.now().isoformat(),
        "task": RE.E5_TASK,
        "rounds_per_mode": rounds,
        "modes": {},
    }
    sc = RE.GROUND_TRUTH["scenarios"]["S1"]
    for mode in RE.E5_MODES:
        scores, durs, tools, loops = [], [], [], []
        print(f"\n=== [qwen:{CHANNEL}] E5 编排模式: {mode} · {rounds} 轮 ===", flush=True)
        for i in range(1, rounds + 1):
            print(f"  轮次 {i}/{rounds} ...", flush=True)
            try:
                RE.assert_platform_alive(client)
            except RE.PlatformDown as e:
                print(f"    ⛔ 平台不可用，中断: {e}", flush=True)
                out["aborted"] = {"reason": str(e), "mode": mode, "round": i,
                                  "at": datetime.now().isoformat()}
                out["finished_at"] = datetime.now().isoformat()
                _save(out, "e5-qwen", day)
                return out
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
        out["modes"][mode] = {
            "rounds": rounds,
            "closed_loop_rate": round(sum(loops) / len(loops), 4) if loops else 0,
            "duration_ms_avg": round(sum(durs) / len(durs), 1) if durs else 0,
            "tool_calls_avg": round(sum(tools) / len(tools), 2) if tools else 0,
            "vuln_recall_avg": round(
                sum(s["vuln_recall"] or 0 for s in scores) / len(scores), 4) if scores else 0,
            "vuln_found_each": [s["vuln_found"] for s in scores],
            "duration_s_each": [round(d / 1000, 1) for d in durs],
            "closed_each": [bool(x) for x in loops],
        }
        _save(out, "e5-qwen", day)
    out["finished_at"] = datetime.now().isoformat()
    p = _save(out, "e5-qwen", day)
    print(f"\nE5(qwen) 完成 → {p}", flush=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--s3-rounds", type=int, default=3)
    ap.add_argument("--e5-rounds", type=int, default=2)
    args = ap.parse_args()

    client = RE.SamClient()
    client.login()
    print(f"已登录平台 {client.base}（默认通道应已切到 {CHANNEL}）", flush=True)
    try:
        RE.assert_platform_alive(client)
        print("平台健康检查通过", flush=True)
    except RE.PlatformDown as e:
        print(f"⛔ 启动前健康检查失败: {e}", flush=True)
        return 2

    day = datetime.now().strftime("%Y%m%d")
    if args.s3_rounds > 0:
        run_s3(client, args.s3_rounds, day)
    if args.e5_rounds > 0:
        run_e5(client, args.e5_rounds, day)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
