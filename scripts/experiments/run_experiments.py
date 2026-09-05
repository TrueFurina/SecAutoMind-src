#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAutoMind 实验套件驱动（可复现）

前置条件：
  1. 靶场已启动：python scripts/experiments/target_range.py
  2. 靶场自检全绿：python scripts/experiments/verify_range.py
  3. 平台已启动：./secautomind-ai.exe -config config.yaml
  4. config.yaml 中 multi_agent.enabled: true

实验设计（对齐赛题 XH-202609 五维评分的 17-20 分档）：
  E1 多场景识别准确率   → 维度① 任务理解（深度理解、多策略）
  E2 端到端成功率与耗时 → 维度① 执行设计
  E3 可复现性（重复 N 次一致性）→ 维度③ 逻辑可追溯、可复现
  E5 多策略对照（deep/plan_execute/supervisor）→ 维度① 多策略选择 + 维度⑤ 验证创新
  E6 跨工具链协同 → 维度④ 跨工具链自动化编排（从 E1/E2 数据中提取）

数据落盘：docs/evidence/experiments-<日期>.json（原始可复核）

用法：
  python scripts/experiments/run_experiments.py --exp e1 --rounds 5
  python scripts/experiments/run_experiments.py --exp e5 --rounds 2
  python scripts/experiments/run_experiments.py --exp all --rounds 3   # 全流程（耗时较长）
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from sam_client import SamClient          # noqa: E402
from judge import judge_run               # noqa: E402
from target_range import GROUND_TRUTH     # noqa: E402

ROOT = os.path.dirname(os.path.dirname(HERE))
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence")

# ── 每场景的标准任务（自然语言，模拟真实下发）──
TASKS = {
    "S1": ("对 http://127.0.0.1:8501 的授权演示靶场做一次完整 Web 安全检测："
           "先识别服务与技术栈指纹，再探测常见漏洞（目录枚举、SQL 注入、XSS、敏感文件泄露等），"
           "最后输出结论与修复建议。"),
    "S2": ("对 http://127.0.0.1:8502 的授权 API 靶场做安全检测："
           "识别服务与技术栈，探测未授权接口、信息泄露、认证缺陷等问题，最后输出结论。"),
    "S3": ("对 127.0.0.1 的 8503、8504、8505 端口做主机服务探测："
           "识别开放服务与版本，检测未授权访问与配置错误，最后输出结论。"),
}

# E5 多策略对照用的任务（同一任务、不同编排模式）
E5_TASK = ("对 http://127.0.0.1:8501 的授权演示靶场做一次 Web 安全检测："
           "识别服务与指纹，探测主要漏洞，输出结论。")
E5_MODES = ["deep", "plan_execute", "supervisor"]


class PlatformDown(RuntimeError):
    """平台不可达。"""


def assert_platform_alive(client: SamClient) -> None:
    """每轮开始前确认平台存活。

    事故教训（2026-09-05）：平台在 S1 第 2 轮中途死掉后，脚本仍继续跑完剩余 18 轮，
    每轮都记录"连接被拒"的 0 值并落盘 → 产出一个看似完整、实则被 0 值污染的实验
    JSON。这类数据一旦被当成证据，就是西湖论剑式"注水"。故在此 fail-fast：
    平台不可用立即中断，且落盘文件名自动加 -ABORTED 标记，绝不冒充有效证据。
    """
    import urllib.request
    try:
        with urllib.request.urlopen(
                urllib.request.Request(f"{client.base}/api/setup/status", method="GET"),
                timeout=5) as resp:
            if resp.status != 200:
                raise PlatformDown(f"平台健康检查返回 HTTP {resp.status}")
    except PlatformDown:
        raise
    except Exception as e:  # noqa: BLE001 - 任何异常都视为平台不可用
        raise PlatformDown(f"平台不可达: {type(e).__name__}: {e}") from e


def _save(payload: dict, tag: str) -> str:
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    day = datetime.now().strftime("%Y%m%d")
    suffix = "-ABORTED" if payload.get("aborted") else ""
    path = os.path.join(EVIDENCE_DIR, f"experiments-{tag}-{day}{suffix}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def run_e1_e2(client: SamClient, rounds: int, save_every: bool = True) -> dict:
    """E1 识别准确率 + E2 端到端成功率/耗时（同一批数据，两维度共用）。"""
    out = {
        "experiment": "E1+E2",
        "started_at": datetime.now().isoformat(),
        "rounds_per_scenario": rounds,
        "scenarios": {},
        "runs_raw": [],
    }
    for sid in ("S1", "S2", "S3"):
        sc = GROUND_TRUTH["scenarios"][sid]
        runs, scores = [], []
        print(f"\n=== {sid} {sc['name']} · {rounds} 轮 ===", flush=True)
        for i in range(1, rounds + 1):
            print(f"  轮次 {i}/{rounds} ...", flush=True)
            try:
                assert_platform_alive(client)
            except PlatformDown as e:
                print(f"    ⛔ 平台不可用，中断本实验（避免产出全 0 的污染数据）: {e}", flush=True)
                out["aborted"] = {"reason": str(e), "scenario": sid, "round": i,
                                  "at": datetime.now().isoformat()}
                out["finished_at"] = datetime.now().isoformat()
                return out
            r = client.run_agent(TASKS[sid], orchestration="deep",
                                 overall_timeout=600)
            j = judge_run(r, sc)
            runs.append({"round": i, "raw": r, "score": j})
            scores.append(j)
            print(f"    → {r['duration_ms']/1000:.1f}s  工具{r['tool_call_count']}次  "
                  f"闭环={'✅' if r['finalized'] else '❌'}  "
                  f"指纹{j['fingerprint_hit']}/{j['fingerprint_expected']}  "
                  f"漏洞{j['vuln_found']}/{j['vuln_expected']}  "
                  f"HITL{r['hitl_count']}次"
                  + (f"  ERR={r['error']}" if r["error"] else ""), flush=True)

        # 可复现性（E3）：同一任务 N 轮之间的一致性
        recalls = [s["vuln_recall"] for s in scores if s["vuln_recall"] is not None]
        fps = [s["fingerprint_accuracy"] for s in scores if s["fingerprint_accuracy"] is not None]
        durs = [s["duration_ms"] for s in scores]

        def _stats(xs):
            if not xs:
                return None
            mean = sum(xs) / len(xs)
            var = sum((x - mean) ** 2 for x in xs) / len(xs)
            return {"n": len(xs), "mean": round(mean, 4),
                    "min": round(min(xs), 4), "max": round(max(xs), 4),
                    "stdev": round(var ** 0.5, 4),
                    "cv": round((var ** 0.5) / mean, 4) if mean else None}

        out["scenarios"][sid] = {
            "name": sc["name"],
            "target": sc["target"],
            "task": TASKS[sid],
            "runs": runs,
            "summary": {
                "closed_loop_rate": round(
                    sum(1 for s in scores if s["closed_loop"]) / len(scores), 4) if scores else 0,
                "vuln_recall": _stats(recalls),
                "fingerprint_accuracy": _stats(fps),
                "duration_ms": _stats(durs),
                "tool_calls_avg": round(
                    sum(s["tool_call_count"] for s in scores) / len(scores), 2) if scores else 0,
                "hitl_avg": round(
                    sum(s["hitl_count"] for s in scores) / len(scores), 2) if scores else 0,
            },
        }
        if save_every:
            _save(out, "e1e2")
    out["finished_at"] = datetime.now().isoformat()
    return out


def run_e5(client: SamClient, rounds: int) -> dict:
    """E5 多策略对照：同一任务，三种编排模式各跑 N 轮。"""
    out = {
        "experiment": "E5",
        "started_at": datetime.now().isoformat(),
        "task": E5_TASK,
        "rounds_per_mode": rounds,
        "modes": {},
    }
    sc = GROUND_TRUTH["scenarios"]["S1"]
    for mode in E5_MODES:
        scores, durs, tools, loops = [], [], [], []
        print(f"\n=== E5 编排模式: {mode} · {rounds} 轮 ===", flush=True)
        for i in range(1, rounds + 1):
            print(f"  轮次 {i}/{rounds} ...", flush=True)
            try:
                assert_platform_alive(client)
            except PlatformDown as e:
                print(f"    ⛔ 平台不可用，中断本实验（避免产出全 0 的污染数据）: {e}", flush=True)
                out["aborted"] = {"reason": str(e), "mode": mode, "round": i,
                                  "at": datetime.now().isoformat()}
                out["finished_at"] = datetime.now().isoformat()
                return out
            r = client.run_agent(E5_TASK, orchestration=mode, overall_timeout=600)
            j = judge_run(r, sc)
            scores.append(j); durs.append(r["duration_ms"])
            tools.append(r["tool_call_count"]); loops.append(1 if r["finalized"] else 0)
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
            "duration_each": durs,
        }
        _save(out, "e5")
    out["finished_at"] = datetime.now().isoformat()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="SecAutoMind 实验套件")
    ap.add_argument("--exp", default="e1", choices=["e1", "e5", "all"])
    ap.add_argument("--rounds", type=int, default=5, help="每场景/每模式轮次")
    args = ap.parse_args()

    client = SamClient()
    client.login()
    print(f"已登录平台 {client.base}", flush=True)
    try:
        assert_platform_alive(client)
        print("平台健康检查通过", flush=True)
    except PlatformDown as e:
        print(f"⛔ 启动前平台健康检查失败，放弃本次实验: {e}", flush=True)
        return 2

    t0 = time.time()
    aborted = False
    if args.exp in ("e1", "all"):
        out = run_e1_e2(client, args.rounds)
        p = _save(out, "e1e2")
        aborted = aborted or bool(out.get("aborted"))
        print(f"\nE1+E2 完成，耗时 {(time.time()-t0)/60:.1f} 分钟 → {p}")
    if args.exp in ("e5", "all") and not aborted:
        out = run_e5(client, max(2, args.rounds // 2))
        p = _save(out, "e5")
        aborted = aborted or bool(out.get("aborted"))
        print(f"\nE5 完成，耗时 {(time.time()-t0)/60:.1f} 分钟 → {p}")
    if aborted:
        print("\n⚠️ 本次实验被中断，产物文件名已带 -ABORTED 标记，不得作为证据引用。", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
