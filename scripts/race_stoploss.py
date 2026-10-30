#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""race_stoploss.py —— 止损线（同题同类失败 2 次即换题，硬阻断）。

## 为什么存在（2026-10-24 羊城杯 0 分复盘的最后一条）
那天我在 12080 Jammed 上做了 **863 次哈希比对 + 8 方向键盘错位 + 336 种配对**，
全程没有一个工具能判断对错，也没人拦我。同类失败连续发生却不换题，
是「有能力的引擎打出 0 分」的最后一块拼图。

复盘结论：**同一题连续 2 次同类失败 → 换题，不解释。**
但「写进 checklist」等于没写（本项目纪律：「确认表打了警告」≠ 门禁）。
所以做成**会返回非 0 的阻断器**：想开新尝试，先过这一关。

## 规则（两条，任一命中即 STOP）
1. **同类失败 2 次**：同一题 + 同一 `failure_class` 出现 ≥2 次；
2. **总尝试 5 次**：同一题累计尝试 ≥5 次（防止「换个说法继续磨」）。

`failure_class` 是自由文本，但建议用固定词汇，便于统计：
`guess`（盲猜）/ `tool_missing`（工具缺失）/ `env_dead`（靶机死）/
`wrong_path`（方向错）/ `timeout`（超时）/ `format`（格式/通道）。

## 用法
    # 每次开新尝试前：不过就换题（退出码非 0）
    python scripts/race_stoploss.py check --challenge 12080 || echo "→ 换题"

    # 记一次失败（在失败发生的那一刻记，别事后补）
    python scripts/race_stoploss.py record --challenge 12080 \
        --class guess --note "第 3 轮哈希变体"

    # 看全量状态
    python scripts/race_stoploss.py status

退出码：0=可以继续 / 1=必须换题 / 2=用法错误。
日志默认 `logs/race_attempts.jsonl`（append-only，一行一次尝试）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

DEFAULT_LOG = os.path.join("logs", "race_attempts.jsonl")

MAX_SAME_CLASS = 2   # 同类失败次数上限
MAX_TOTAL = 5        # 单题总尝试上限


def load(path: str) -> list[dict]:
    """读 append-only JSONL。坏行跳过（不因一行脏数据让整条止损线失效）。"""
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def append(path: str, entry: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def evaluate(entries: list[dict], challenge: str,
             max_same_class: int = MAX_SAME_CLASS,
             max_total: int = MAX_TOTAL) -> tuple[str, str]:
    """纯函数：返回 (verdict, detail)。verdict ∈ ok / stop。

    只看「失败」记录（`outcome` 缺省视为失败；显式 `solved` 的不计入）。
    """
    mine = [e for e in entries
            if str(e.get("challenge")) == str(challenge)
            and (e.get("outcome") or "fail") != "solved"]
    if not mine:
        return "ok", "该题无失败记录"

    total = len(mine)
    by_class: dict[str, int] = {}
    for e in mine:
        cls = str(e.get("failure_class") or "unspecified")
        by_class[cls] = by_class.get(cls, 0) + 1

    worst = max(by_class.items(), key=lambda kv: kv[1])
    if worst[1] >= max_same_class:
        return "stop", ("同类失败 %d 次（%s ≥ %d）→ 换题，不解释"
                        % (worst[1], worst[0], max_same_class))
    if total >= max_total:
        return "stop", "该题累计尝试 %d 次（≥ %d）→ 换题" % (total, max_total)
    return "ok", "失败 %d 次（最多同类 %d 次），可继续" % (total, worst[1])


def status_table(entries: list[dict]) -> str:
    chs: dict[str, list[dict]] = {}
    for e in entries:
        if (e.get("outcome") or "fail") == "solved":
            continue
        chs.setdefault(str(e.get("challenge")), []).append(e)
    if not chs:
        return "（无失败记录）"
    lines = [f"{'题号':<12}{'失败次数':>8}  {'判定':<6} 详情"]
    for cid, es in sorted(chs.items()):
        v, d = evaluate(entries, cid)
        lines.append(f"{cid:<12}{len(es):>8}  {v:<6} {d}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="止损线：同题同类失败 2 次即换题")
    ap.add_argument("cmd", choices=("check", "record", "status"))
    ap.add_argument("--challenge", default="")
    ap.add_argument("--class", dest="failure_class", default="unspecified")
    ap.add_argument("--note", default="")
    ap.add_argument("--log", default=DEFAULT_LOG)
    args = ap.parse_args(argv)

    if args.cmd == "status":
        print(status_table(load(args.log)))
        return 0

    if not args.challenge:
        print("[FAIL] 需要 --challenge", file=sys.stderr)
        return 2

    entries = load(args.log)

    if args.cmd == "check":
        v, d = evaluate(entries, args.challenge)
        print(("⛔ STOP：%s" % d) if v == "stop" else ("✅ 可继续：%s" % d))
        return 0 if v == "ok" else 1

    # record：先记，再回读判定（这样这次失败本身也计入）
    entry = {"ts": datetime.now().isoformat(timespec="seconds"),
             "challenge": str(args.challenge),
             "failure_class": args.failure_class,
             "note": args.note,
             "outcome": "fail"}
    append(args.log, entry)
    v, d = evaluate(load(args.log), args.challenge)
    print(("⛔ 已记。STOP：%s" % d) if v == "stop" else ("✅ 已记。%s" % d))
    return 0 if v == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
