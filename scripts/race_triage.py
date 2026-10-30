#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""race_triage.py —— 开赛分诊表生成器（10 分钟内产出，按「已解出次数」升序）。

## 为什么存在（2026-10-24 羊城杯 0 分复盘）
那场 16 题，**开赛后 80 分钟才第一次解题**，其中一小时在追一个已知作废的令牌。
真正该在头 10 分钟做完的事只有一件：**把 16 题按「有几队解出」排好序**，
然后从 0 队解出的开始打。人工填板子（`runner_board.py` 的注释也写了：16 题只人工读了 1 题）
是纯人力瓶颈。

## 排序口径（可切换，默认 unsolved）
- `unsolved`：**已解出次数升序**（0 队 → 优先）。同次数时有直连靶机的排前、分值高的排前。
  依据：178 队解出的题基本等于已交，0~1 队解出的才可能贡献新分。
- `static`：**静态优先**（无靶机/只有附件的排前）。依据：容器题脆弱，
  一碰就 500，先吃静态分更稳。

## 用法
    python scripts/race_triage.py --from-json .workbuddy/tmp/ycb_details.json
    python scripts/race_triage.py --from-json x.json --sort static --out board.md
    python scripts/race_triage.py --from-json x.json --json     # 机器可读

支持三种输入形态（自动识别）：
  1. YCB/DASCTF 详情字典：`{"<id>": {"code": "00000", "data": {...}}}`
  2. CTF² 列表：`{"data": {"items": [...]}}`
  3. 裸列表：`[{...}, {...}]`（字段名兼容 title/name、score/points）

**不联网**：只读本地 JSON。要联网拉题请先用平台客户端导出，本脚本刻意不做鉴权，
避免把「拿不到令牌」变成「分诊表也做不出来」。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Iterable

# 「已答出66次，初始分值500.0，当前分值482.54，解出分值482.0」
_RE_SOLVED = re.compile(r"已答出\s*(\d+)\s*次")
_RE_CUR_SCORE = re.compile(r"当前分值\s*([\d.]+)")

# 视为「有直连靶机」的端口类型
_TARGET_PORT_TYPES = {"nc", "http", "https", "tcp"}


def parse_solved_count(value: Any) -> int | None:
    """从 score 字符串或数字里取「已解出次数」。取不到返回 None（不许瞎猜成 0）。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        m = _RE_SOLVED.search(value)
        if m:
            return int(m.group(1))
        # 纯数字串
        s = value.strip()
        if s.isdigit():
            return int(s)
    return None


def parse_current_score(value: Any) -> float | None:
    """取「当前分值」。YCB 是字符串里的「当前分值 482.54」；CTF² 直接是数字。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        m = _RE_CUR_SCORE.search(value)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                return None
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _endpoints(ch: dict) -> list[dict]:
    eps = ch.get("endpoints") or []
    return [e for e in eps if isinstance(e, dict)]


def has_direct_target(ch: dict) -> bool:
    """有公网直连地址 ⇒ 不需要平台令牌就能打（2026-10-24 最大教训）。"""
    for e in _endpoints(ch):
        ips = e.get("exposeIps") or []
        if not ips:
            continue
        if (e.get("status") or "").lower() in ("down", "stopped"):
            continue
        return True
    return False


def target_addrs(ch: dict) -> list[str]:
    out: list[str] = []
    for e in _endpoints(ch):
        for ip in (e.get("exposeIps") or []):
            if ip and ip not in out:
                out.append(ip)
    return out


def attachment_name(ch: dict) -> str:
    att = ch.get("attachment")
    if isinstance(att, dict):
        return str(att.get("name") or att.get("filename") or "")
    if isinstance(att, str):
        return att
    return ""


def _unwrap(raw: Any) -> Iterable[dict]:
    """把三种输入形态统一成「挑战字典」的可迭代序列。"""
    if isinstance(raw, list):
        yield from (x for x in raw if isinstance(x, dict))
        return
    if not isinstance(raw, dict):
        return
    # CTF²: {"data": {"items": [...]}}
    data = raw.get("data")
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        yield from (x for x in data["items"] if isinstance(x, dict))
        return
    if isinstance(raw.get("challenges"), list):
        yield from (x for x in raw["challenges"] if isinstance(x, dict))
        return
    # YCB: {"<id>": {"code":..., "data": {...}}}
    for _k, v in raw.items():
        if not isinstance(v, dict):
            continue
        inner = v.get("data")
        if isinstance(inner, dict) and ("name" in inner or "title" in inner):
            yield inner


def normalize(raw: Any) -> list[dict]:
    """统一成内部结构。字段缺失一律留 None/False，**不编造**。"""
    out: list[dict] = []
    for ch in _unwrap(raw):
        cid = ch.get("id")
        title = ch.get("title") or ch.get("name") or ""
        solved = parse_solved_count(
            ch.get("solved_count") if ch.get("solved_count") is not None else ch.get("score")
        )
        if solved is None and ch.get("solved") is not None:
            solved = parse_solved_count(ch.get("solved"))
        out.append({
            "id": str(cid) if cid is not None else "",
            "title": str(title),
            "category": str(ch.get("category") or ch.get("direction") or ""),
            "score": parse_current_score(ch.get("score") if ch.get("score") is not None
                                         else ch.get("points")),
            "solved_count": solved,
            "has_target": has_direct_target(ch),
            "addrs": target_addrs(ch),
            "attachment": attachment_name(ch),
            "solved_by_me": bool(ch.get("hasSolved") or ch.get("is_solved")),
        })
    return out


def _sort_key(mode: str):
    if mode == "static":
        # 静态优先：无直连靶机的排前；同组内 0 队解出优先，再按分值降序
        return lambda c: (
            c["has_target"],
            c["solved_count"] is None,
            c["solved_count"] if c["solved_count"] is not None else 10**9,
            -(c["score"] or 0.0),
        )
    # unsolved（默认）：已解出次数升序；同次数时有直连靶机优先、分值高的优先
    return lambda c: (
        c["solved_count"] is None,
        c["solved_count"] if c["solved_count"] is not None else 10**9,
        not c["has_target"],
        -(c["score"] or 0.0),
    )


def rank(challenges: list[dict], mode: str = "unsolved") -> list[dict]:
    return sorted(challenges, key=_sort_key(mode))


def advice(c: dict) -> str:
    """给一行可执行的建议——分诊表的价值就在这一列。"""
    n = c["solved_count"]
    if c["solved_by_me"]:
        return "已交"
    if n is None:
        return "解出数未知"
    if n == 0:
        return "🔥 优先（0 队）"
    if n <= 2:
        return "可打"
    if n <= 10:
        return "竞争激烈"
    return "大概率已交"


def summary(challenges: list[dict]) -> dict:
    total = len(challenges)
    zero = sum(1 for c in challenges if c["solved_count"] == 0)
    direct = sum(1 for c in challenges if c["has_target"])
    unknown = sum(1 for c in challenges if c["solved_count"] is None)
    return {"total": total, "zero_solved": zero, "direct_target": direct,
            "unknown_solved": unknown}


def render_markdown(challenges: list[dict], mode: str = "unsolved") -> str:
    s = summary(challenges)
    lines = [
        "# 开赛分诊表（自动生成）",
        "",
        f"> 排序口径：`{mode}`"
        + ("（已解出次数升序，0 队优先）" if mode == "unsolved" else "（静态优先，容器题排后）"),
        f"> 共 **{s['total']}** 题｜0 队解出 **{s['zero_solved']}** 题｜"
        f"有直连靶机 **{s['direct_target']}** 题"
        + (f"｜解出数未知 **{s['unknown_solved']}** 题" if s["unknown_solved"] else ""),
        "> 有直连靶机的题**不需要平台令牌就能打**；没地址的题必须先建环境。",
        "",
        "| # | id | 题名 | 分类 | 当前分值 | 已解出 | 直连靶机 | 附件 | 建议 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for i, c in enumerate(challenges, 1):
        score = f"{c['score']:.2f}" if c["score"] is not None else "—"
        solved = "?" if c["solved_count"] is None else str(c["solved_count"])
        addr = c["addrs"][0] if c["addrs"] else "—"
        att = c["attachment"] or "—"
        lines.append(
            f"| {i} | {c['id']} | {c['title'][:24]} | {c['category'] or '—'} | "
            f"{score} | {solved} | {addr} | {att[:22]} | {advice(c)} |"
        )
    return "\n".join(lines) + "\n"


def render_text(challenges: list[dict], mode: str = "unsolved") -> str:
    s = summary(challenges)
    lines = [
        f"分诊表（口径 {mode}）：{s['total']} 题 / 0 队解出 {s['zero_solved']} / "
        f"有直连靶机 {s['direct_target']}"
        + (f" / 解出数未知 {s['unknown_solved']}" if s["unknown_solved"] else ""),
        f"{'#':<3}{'id':<9}{'题名':<22}{'分值':>8}{'已解':>6}  {'建议'}",
    ]
    for i, c in enumerate(challenges, 1):
        score = f"{c['score']:.0f}" if c["score"] is not None else "—"
        solved = "?" if c["solved_count"] is None else str(c["solved_count"])
        lines.append(f"{i:<3}{c['id']:<9}{c['title'][:20]:<22}{score:>8}{solved:>6}  {advice(c)}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="开赛分诊表生成器（按已解出次数升序）")
    ap.add_argument("--from-json", required=True, help="平台导出的题目 JSON 路径")
    ap.add_argument("--sort", choices=("unsolved", "static"), default="unsolved")
    ap.add_argument("--out", help="把 Markdown 写到该路径（不写则只打印终端版）")
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    args = ap.parse_args(argv)

    try:
        raw = json.load(open(args.from_json, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[FAIL] 读取 {args.from_json} 失败：{exc}", file=sys.stderr)
        return 2

    chs = rank(normalize(raw), args.sort)
    if not chs:
        print("[FAIL] 没解析出任何题目——检查输入格式（支持 YCB 字典 / CTF² items / 裸列表）",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"mode": args.sort, "summary": summary(chs), "challenges": chs},
                         ensure_ascii=False, indent=2))
    else:
        print(render_text(chs, args.sort))

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_markdown(chs, args.sort))
        print(f"\n[OK] Markdown 已写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
