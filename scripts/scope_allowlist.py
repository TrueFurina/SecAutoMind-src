#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scope_allowlist.py — 范围边界准入清单的加载 / 校验 / 匹配（REA #169）

为什么需要这个小模块：`audit_scope_boundary.py` 是名字级初筛，命中不等于违规，
必须由人按**实际能力**裁定。裁定结果如果只活在会议纪要里，三个月后没人知道
某个名字为什么被放过、是谁签的字、什么时候该复核——这正是"豁免变成永久后门"
的标准过程。

本模块给准入清单加上四个字段（缺一即无效）：
  audited_on  审计日期（谁在什么时候看过）
  reason      准入理由（必须写实际能力与边界，不能写"业务需要"）
  reviewer    签字人
  expires_on  到期日（默认 90 天；过期后再用该名字 = 失效，重新审）

设计约束：
  * **只标注、不隐藏**：`decide()` 返回状态，调用方仍须把命中项全部列出。
  * **fail-closed**：清单文件不可解析 / 条目缺字段 → 该条目不生效，
    并把问题写进 `problems`，由调用方决定是否阻断。
  * **不猜默认值**：缺 `expires_on` 不得默认"永久有效"——那是后门。

用法（作为库）：
    from scope_allowlist import load, decide
    entries, problems = load(Path("config/scope_allowlist.json"))
    status, entry = decide("c2_payload", "C3_...", entries)

用法（自检 CLI）：
    python scripts/scope_allowlist.py --check      # 缺字段/过期 → exit 1
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = ROOT / "config" / "scope_allowlist.json"
REQUIRED = ("pattern", "category", "reason", "audited_on", "reviewer", "expires_on")
DEFAULT_TTL_DAYS = 90
# 这些"理由"等于没写，直接判无效（不是风格问题：它让复核无从下手）
_BANNED_REASONS = {"业务需要", "历史原因", "暂不清楚", "todo", "tbd", "-", ""}


def _parse_date(value: str) -> date | None:
    """接受 YYYY-MM-DD；其他形式一律无效（不做模糊解析）。"""
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def validate(entry: dict) -> list[str]:
    """返回该条目的问题列表；空列表 = 有效。"""
    problems: list[str] = []
    for field in REQUIRED:
        if not str(entry.get(field, "")).strip():
            problems.append(f"缺字段 {field}")
    if problems:
        return problems

    if str(entry["reason"]).strip().lower() in _BANNED_REASONS:
        problems.append(f"理由无效（{entry['reason']!r} 等于没写）")
    if len(str(entry["reason"]).strip()) < 8:
        problems.append("理由过短（<8 字，无法据此复核）")

    audited = _parse_date(entry["audited_on"])
    expires = _parse_date(entry["expires_on"])
    if audited is None:
        problems.append(f"audited_on 不是 YYYY-MM-DD：{entry['audited_on']!r}")
    if expires is None:
        problems.append(f"expires_on 不是 YYYY-MM-DD：{entry['expires_on']!r}")
    if audited and expires and expires <= audited:
        problems.append("expires_on 必须晚于 audited_on")
    ttl = audit_ttl_days(audited, expires)
    if ttl is not None and ttl > 180:
        problems.append("有效期超过 180 天（准入口径建议 ≤90 天，长期功能应走正式裁定）")
    return problems


def audit_ttl_days(audited: date | None, expires: date | None) -> int | None:
    if audited is None or expires is None:
        return None
    return (expires - audited).days


def load(path: Path | None = None) -> tuple[list[dict], list[str]]:
    """加载清单。返回 (有效条目, 问题列表)。文件缺失视为"无准入"而非错误。"""
    path = Path(path or DEFAULT_PATH)
    if not path.is_file():
        return [], []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [], [f"清单不可解析：{e}"]
    if not isinstance(doc, dict):
        return [], [f"清单顶层应为对象，实际是 {type(doc).__name__}"]
    entries = doc.get("entries")
    if not isinstance(entries, list):
        return [], ["entries 不是数组"]

    valid: list[dict] = []
    problems: list[str] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f"第 {i + 1} 条不是对象")
            continue
        issues = validate(entry)
        if issues:
            problems.append(f"第 {i + 1} 条（{entry.get('pattern', '?')}）：" + "；".join(issues))
            continue
        valid.append(entry)
    return valid, problems


def is_expired(entry: dict, today: date | None = None) -> bool:
    expires = _parse_date(entry.get("expires_on", ""))
    return bool(expires and expires < (today or date.today()))


def decide(name: str, category: str, entries: list[dict],
           today: date | None = None) -> tuple[str, dict | None]:
    """判定某个命中项的准入状态。

    返回 ("allowed" | "expired" | "none", 命中的条目)。
      allowed = 有效期内且类别匹配
      expired = 曾经准入但已过期（**不算准入**，报告里要显眼）
      none    = 没有对应裁定 → 仍需人工判定
    """
    today = today or date.today()
    match = None
    for entry in entries:
        pattern = str(entry.get("pattern", ""))
        if not pattern:
            continue
        if not fnmatch.fnmatch(name, pattern) and not fnmatch.fnmatch(name.lower(), pattern.lower()):
            continue
        # 类别必须一致：仅当条目声明了该类别（或用 * 表示不限）才生效，
        # 避免"上次为 A 类放行，这次 B 类也跟着过"。
        if entry.get("category") not in (category, "*"):
            continue
        match = entry
        break
    if match is None:
        return "none", None
    return ("expired" if is_expired(match, today) else "allowed"), match


def suggested_expiry(audited: date | None = None, days: int = DEFAULT_TTL_DAYS) -> str:
    return ((audited or date.today()) + timedelta(days=days)).isoformat()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="范围边界准入清单校验")
    ap.add_argument("--path", default=str(DEFAULT_PATH))
    ap.add_argument("--check", action="store_true", help="有问题（缺字段/过期）则 exit 1")
    args = ap.parse_args(argv)

    path = Path(args.path)
    entries, problems = load(path)
    print(f"清单：{path}")
    print(f"有效条目：{len(entries)}；问题：{len(problems)}")
    for e in entries:
        state = "已过期" if is_expired(e) else "有效"
        print(f"  [{state}] {e['pattern']} 类别={e['category']} "
              f"审计={e['audited_on']} 到期={e['expires_on']} 签字={e['reviewer']}")
    for p in problems:
        print(f"  ❌ {p}", file=sys.stderr)
    expired = [e for e in entries if is_expired(e)]
    if args.check and (problems or expired):
        print("\n[check] 清单存在无效或过期条目：过期条目等于没有准入，须重新审计。",
              file=sys.stderr)
        return 1
    print("\n✅ 清单可解析，无过期条目" if not expired else "\n⚠️ 存在过期条目（--check 下会阻断）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
