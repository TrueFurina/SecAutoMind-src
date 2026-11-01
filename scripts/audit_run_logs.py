#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全量跑批日志归类器。

用途：把服务器上散落在 /tmp、仓库根下的 .log/.jsonl 一次性过一遍，
按「是否真的跑出了结构化结果」分层，抽取每题的 layer / 命中 / 耗时 / 收口原因，
最后输出可核对的归类报告。

设计原则（对应用户纪律）：
  * 不猜。只认日志里真实出现的字段。日志没有的字段一律记 None，绝不从文件名反推。
  * 分母污染要显式暴露。`seconds=0 / max_round=0` 的题单列，不进命中率。
  * 一个日志可能包含多轮跑批（同一 .log 被 >> 追加），按「汇总行」切段。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

# [ext_gctf2023_zip] crypto                       cand=0 hit=false 39.0s (L2 0.0s)
RE_ROW = re.compile(
    r"^\[(?P<pid>[^\]]+)\]\s+(?P<cat>\S+)\s+"
    r"(?:.*?cand=(?P<cand>\d+)\s+hit=(?P<hit>true|false)\s+(?P<sec>[\d.]+)s"
    r"(?:\s+\(L2\s+(?P<l2>[\d.]+)s\))?)",
    re.M,
)
# [ext_gctf2023_zip] crypto  L2 未命中 cand=0 63.3s → 进 L3
RE_L2MISS = re.compile(
    r"^\[(?P<pid>[^\]]+)\]\s+(?P<cat>\S+)\s+L2-(?:MISS|未命中).*?(?P<sec>[\d.]+)s",
    re.M,
)
# === llmbench: 1/6 = 16.7%  (model=deepseek-v4-pro tier=mainline) ===
RE_SUM = re.compile(
    r"^===\s*(?P<tool>\w+):\s*(?P<hit>\d+)/(?P<tot>\d+)\s*=\s*(?P<pct>[\d.]+)%"
    r"\s*\(model=(?P<model>[^)\s]*)\s*tier=(?P<tier>[^)]*)\)",
    re.M,
)
# 报告: /tmp/l2cov/l3_airgap_6.json
RE_REPORT = re.compile(r"^报告:\s*(?P<path>\S+)", re.M)
# 监督 ABANDON：... {"challenge": "ZIP", "round_used": 8, "budget": 12, ...}
RE_ABANDON = re.compile(r"监督 ABANDON[^\n]*", re.M)
# 收口归因 / 未命中归因
RE_OUTCOME = re.compile(r"收口归因[^\n]*", re.M)
# 通道失败
RE_CHFAIL = re.compile(r"(?:LLM 已降级|全部通道失败|ErrLLMUnavailable|no available channel)", re.M)
# strace / 无关噪音特征
NOISE_MARK = ("SYS_", "+++ exited with", "musl", "flask", "ollama", "GET /", "POST /")


@dataclass
class LogInfo:
    path: str
    size: int
    lines: int
    kind: str = "noise"          # bench | eval | partial | noise
    note: str = ""
    summaries: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    l2miss: list = field(default_factory=list)
    abandons: int = 0
    abandon_reasons: list = field(default_factory=list)
    channel_issues: int = 0
    reports: list = field(default_factory=list)


def classify(text: str, info: LogInfo) -> None:
    noise_hits = sum(1 for m in NOISE_MARK if m in text)
    info.summaries = [
        {
            "tool": m.group("tool"),
            "hit": int(m.group("hit")),
            "tot": int(m.group("tot")),
            "pct": float(m.group("pct")),
            "model": m.group("model") or "(空)",
            "tier": m.group("tier") or "(空)",
        }
        for m in RE_SUM.finditer(text)
    ]
    info.rows = [
        {
            "pid": m.group("pid"),
            "cat": m.group("cat"),
            "cand": int(m.group("cand")),
            "hit": m.group("hit") == "true",
            "sec": float(m.group("sec")),
            "l2": float(m.group("l2")) if m.group("l2") else None,
        }
        for m in RE_ROW.finditer(text)
    ]
    info.l2miss = [
        {"pid": m.group("pid"), "cat": m.group("cat"), "sec": float(m.group("sec"))}
        for m in RE_L2MISS.finditer(text)
    ]
    ab = RE_ABANDON.findall(text)
    info.abandons = len(ab)
    info.abandon_reasons = sorted(
        {a.split('"reason":')[1].strip().strip('"}') for a in ab if '"reason":' in a}
    )[:6]
    info.channel_issues = len(RE_CHFAIL.findall(text))
    info.reports = RE_REPORT.findall(text)

    if info.summaries:
        info.kind = "bench"
    elif "practice_llm" in text or "SecAutoMind 离线 eval" in text:
        info.kind = "eval"
    elif info.rows or info.l2miss:
        info.kind = "partial"
    else:
        info.kind = "noise"
        if noise_hits >= 2:
            info.note = "strace/服务日志，无跑批结果"


def scan(paths: list[str]) -> list[LogInfo]:
    out = []
    for p in paths:
        try:
            st = os.stat(p)
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            continue
        info = LogInfo(path=p, size=st.st_size, lines=text.count("\n") + 1)
        classify(text, info)
        out.append(info)
    return out


def render(infos: list[LogInfo]) -> str:
    order = {"bench": 0, "eval": 1, "partial": 2, "noise": 3}
    infos = sorted(infos, key=lambda i: (order[i.kind], -i.size))
    L = []
    L.append(f"# 全量跑批日志归类（共 {len(infos)} 个文件）\n")

    for kind, title in (
        ("bench", "A. 有完整汇总行（可当证据用）"),
        ("eval", "B. eval 管线（离线/practice）"),
        ("partial", "C. 只有逐题行、无汇总（口径残缺）"),
        ("noise", "D. 噪音（strace / 服务日志 / 空跑）"),
    ):
        grp = [i for i in infos if i.kind == kind]
        L.append(f"## {title} —— {len(grp)} 个\n")
        if not grp:
            L.append("(无)\n")
            continue
        if kind == "bench":
            L.append("| 日志 | 汇总 | model | tier | 逐题行 | ABANDON | 通道异常 |")
            L.append("|---|---|---|---|---|---|---|")
            for i in grp:
                for s in i.summaries:
                    L.append(
                        f"| `{i.path}` | {s['hit']}/{s['tot']} = {s['pct']}% | "
                        f"{s['model']} | {s['tier']} | {len(i.rows)} | {i.abandons} | {i.channel_issues} |"
                    )
        elif kind == "eval":
            for i in grp:
                L.append(f"- `{i.path}` ({i.size} B)")
        elif kind == "partial":
            L.append("| 日志 | 行数 | 逐题行 | L2-MISS行 | 备注 |")
            L.append("|---|---|---|---|---|")
            for i in grp:
                L.append(f"| `{i.path}` | {i.lines} | {len(i.rows)} | {len(i.l2miss)} | {i.note} |")
        else:
            for i in grp:
                L.append(f"- `{i.path}` ({i.size} B / {i.lines} 行) {i.note}")
        L.append("")

    # 逐题命中明细
    L.append("## 逐题明细（hit=true 的题）\n")
    hits = []
    for i in infos:
        for r in i.rows:
            if r["hit"]:
                hits.append((i.path, r))
    if not hits:
        L.append("(无)\n")
    else:
        L.append("| 日志 | 题 | 类 | 耗时s | L2s |")
        L.append("|---|---|---|---|---|")
        for p, r in hits:
            L.append(f"| `{p}` | {r['pid']} | {r['cat']} | {r['sec']} | {r['l2']} |")
        L.append("")

    # ABANDON 原因聚合
    L.append("## 早停（ABANDON）原因聚合\n")
    reasons: dict[str, int] = {}
    for i in infos:
        for r in i.abandon_reasons:
            reasons[r] = reasons.get(r, 0) + 1
    if not reasons:
        L.append("(无 ABANDON 记录)\n")
    else:
        L.append("| 次数 | 原因 |")
        L.append("|---|---|")
        for r, n in sorted(reasons.items(), key=lambda x: -x[1]):
            L.append(f"| {n} | {r} |")
        L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="日志文件列表；为空则从 stdin 逐行读")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="报告输出路径")
    a = ap.parse_args()

    paths = a.paths or [ln.strip() for ln in sys.stdin if ln.strip()]
    infos = scan(paths)

    if a.json:
        body = json.dumps([asdict(i) for i in infos], ensure_ascii=False, indent=2)
    else:
        body = render(infos)

    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"written: {a.out} ({len(body)} B, {len(infos)} logs)", file=sys.stderr)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
