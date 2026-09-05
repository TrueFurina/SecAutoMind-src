#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gw_probe.py — 平台内 Agent 最小对话探针（供 verify_gateway.sh [2/4] 调用）

作用：登录 SecAutoMind 平台 → 下发一条「不调用任何工具」的最小任务 → 证明
平台内 Agent 对话链路可用。终审网关接入后，本条请求应出现在网关侧流量日志，
即对应 ai-gateway-compliance.md §3 接入验收清单第 2 条的人工复核点。

用法：
    python scripts/experiments/gw_probe.py          # 平台地址/密码从 data/ 自动发现
    python scripts/experiments/gw_probe.py --base http://127.0.0.1:18086
    python scripts/experiments/gw_probe.py --message "自定义最小任务"

退出码：0=链路闭环  1=失败
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sam_client import DEFAULT_BASE, DEFAULT_USER, SamClient  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="平台内 Agent 最小对话探针")
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--user", default=DEFAULT_USER)
    ap.add_argument("--password", default=None)
    ap.add_argument("--message",
                    default="输出两字：OK。不要调用任何工具，直接回复。")
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args()

    c = SamClient(base=args.base, user=args.user, password=args.password,
                  timeout=min(args.timeout, 30))
    print(f"[gw_probe] 登录 {args.base} ({args.user}) ...", flush=True)
    try:
        c.login()
    except Exception as e:
        print(f"[gw_probe] 登录失败: {e}", flush=True)
        return 1
    print(f"[gw_probe] token 获取成功: {c.token[:8]}...", flush=True)

    print(f"[gw_probe] 下发最小任务 (orchestration=deep, timeout={args.timeout}s): "
          f"{args.message[:60]}", flush=True)
    r = c.run_agent(args.message, orchestration="deep",
                    overall_timeout=args.timeout)
    print(f"[gw_probe] finalized={r['finalized']} status={r.get('status')} "
          f"duration_ms={r['duration_ms']} event_count={r['event_count']}", flush=True)
    if r.get("error"):
        print(f"[gw_probe] error={str(r['error'])[:300]}", flush=True)
    tail = (r.get("final_text") or "").strip().replace("\n", " ")[:150]
    print(f"[gw_probe] 最终回复: {tail or '(空)'}", flush=True)

    if r["finalized"]:
        print("[gw_probe] PASS —— 平台内 Agent 对话链路闭环。"
              "网关启用后请在网关控制台核对本条流量（对应验收清单第 2 条）。", flush=True)
        return 0
    print("[gw_probe] FAIL —— 任务未闭环，请查平台日志 logs/secautomind_run*.log", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
