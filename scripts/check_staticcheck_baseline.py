#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""staticcheck 报告 vs 基线：只拦新增语义缺陷，风格/死代码只计量。

为什么不是"零告警即通过"
------------------------
首跑全仓 156 条，其中 U1000（未使用）110 条——那是死代码台账，不是本轮要清的
债；SA1019（上游 API 弃用）8 条要跟着 eino 的迁移节奏走。首日就把门禁设成
"零告警"，唯一的下场是被 `--no-verify` 绕过。所以分两档：

  * **阻断档**（blocking_codes）：SA4000 / SA4004 / SA4006 / SA5011 / SA9009 /
    ST1008——这批是**正确性**类，新增一条就是新缺陷（或新引入的死代码），必须红。
  * **观察档**（observed_codes）：风格类与死代码，只统计不阻断；数字变大要
    在 PR 里说明（--strict 会把它也变成红，供本地自查用）。

为什么键不用行号
----------------
基线键 = (code, 仓库相对路径)。**不含行号**：本轮实测，删掉两行循环后
U1000 的行号整体漂移，行号做键会凭空多出 2 条"新增告警"（REA #258 同款教训）。

fail-closed
-----------
报告缺失、为空、全部行都无法解析 → exit 2。"扫不到"不等于"干净"。

用法
----
    staticcheck -f json ./... > /tmp/sc.json          # 见 docs/ 复跑命令
    python scripts/check_staticcheck_baseline.py --report /tmp/sc.json
    python scripts/check_staticcheck_baseline.py --report /tmp/sc.json --strict
    python scripts/check_staticcheck_baseline.py --report /tmp/sc.json --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASELINE_PATH = HERE / "staticcheck_baseline.json"

#: 服务器上跑 staticcheck 时的仓库根（报告里是绝对路径，需要归一化）
_SCAN_ROOT_ENV = "SECAUTOMIND_STATICCHECK_ROOT"

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_UNVERIFIABLE = 2


def load_report(path: str) -> list[dict]:
    """逐行解析 staticcheck -f json。坏行单独计数，不静默丢弃。"""
    rows: list[dict] = []
    bad = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    return rows, bad


#: 仓库根（用于把报告里的绝对路径还原成相对路径）
REPO_ROOT = HERE.parent


def norm_path(raw: str, root: str | None = None, repo: Path = REPO_ROOT) -> str:
    """报告里的路径 → 仓库相对路径。

    坑（2026-10-21 实测）：报告在服务器上生成（`~/sm_dev_20261020/internal/...`），
    拿回 Windows 用 Git Bash 传 `SECAUTOMIND_STATICCHECK_ROOT=/home/user/...` 时，
    MSYS 会把它改写成 `D:/.../PortableGit/home/user/sm_dev_20261020`，env 前缀因此
    匹配不上。所以不能只靠 env：**再按"能在仓库里定位到的最长后缀"兜底**。
    """
    if not raw:
        return ""
    p = raw.replace("\\", "/")
    if root:
        r = root.replace("\\", "/").rstrip("/")
        if p.startswith(r + "/"):
            p = p[len(r) + 1:]
    if p.startswith("./"):
        p = p[2:]
    # 仍是绝对路径（POSIX 或盘符）→ 用仓库根做后缀匹配
    if p.startswith("/") or (len(p) > 1 and p[1] == ":"):
        parts = [x for x in p.split("/") if x]
        for i in range(len(parts) - 1, -1, -1):
            cand = "/".join(parts[i:])
            if (repo / cand).is_file():
                return cand
    return p


def normalize(rows: list[dict], root: str | None = None) -> list[dict]:
    out = []
    for r in rows:
        loc = r.get("location") or {}
        out.append({
            "code": r.get("code") or "?",
            "file": norm_path(loc.get("file") or "", root),
            "line": loc.get("line"),
            "message": (r.get("message") or "").strip(),
        })
    return out


def count_by_code(items: list[dict]) -> dict[str, int]:
    c: dict[str, int] = {}
    for it in items:
        c[it["code"]] = c.get(it["code"], 0) + 1
    return c


def load_baseline() -> dict:
    if not BASELINE_PATH.is_file():
        return {"blocking_codes": {}, "observed_codes": {}, "exemptions": []}
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def dead_code_reconcile(items: list[dict], root: str | None) -> dict:
    """U1000 与死代码台账对账。

    为什么要在**这里**再做一次：基线里 U1000 的 key 是 (code, 文件)，粒度只到
    文件；同一个文件里新增一个未使用函数，基线看不出来。台账的键精确到
    (文件, 符号)，两边必须对得上——**台账是 U1000 的唯一真源**。

    返回 {"missing": [...不在台账里的 key...], "extra": [...台账里有但报告没有...],
          "ledger_present": bool}
    """
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import dead_code_ledger as dcl

    if not dcl.LEDGER_PATH.is_file():
        return {"ledger_present": False, "missing": [], "extra": []}
    ledger = json.loads(dcl.LEDGER_PATH.read_text(encoding="utf-8"))
    ruled = {r.get("key") for r in ledger.get("rules", []) if r.get("key")}

    report_keys = set()
    for r in [x for x in items if x["code"] == "U1000"]:
        # 用 dead_code_ledger 的同款解析，避免两处各写一套符号提取逻辑
        kind, symbol = dcl.parse_symbol(r["message"])
        report_keys.add(f"{r['file']}::{symbol}")

    return {
        "ledger_present": True,
        "missing": sorted(report_keys - ruled),
        "extra": sorted(ruled - report_keys),
    }


def evaluate(items: list[dict], baseline: dict) -> dict:
    actual = count_by_code(items)
    blocking = baseline.get("blocking_codes") or {}
    observed = baseline.get("observed_codes") or {}

    blocking_new: list[dict] = []
    for code, limit in sorted(blocking.items()):
        got = actual.get(code, 0)
        if got > limit:
            for it in items:
                if it["code"] == code:
                    blocking_new.append(it)
    # 阻断档之外但属正确性前缀（SA4/SA5/SA9）的 code 若在基线里没登记 → 未知即红
    unknown_hard = sorted(c for c in actual
                          if c.startswith(("SA4", "SA5", "SA9"))
                          and c not in blocking and c not in observed)

    observed_delta = []
    for code, limit in sorted(observed.items()):
        got = actual.get(code, 0)
        if got != limit:
            observed_delta.append({"code": code, "baseline": limit, "actual": got})

    # 豁免条目是否 stale（登记了但报告里已经没有 → 那段代码可能被改写/删除）
    present = {(it["code"], it["file"]) for it in items}
    stale = [e for e in (baseline.get("exemptions") or [])
             if e.get("file") != "*"                      # "*" = 类级豁免，不做 stale 判定
             and (e.get("code"), e.get("file")) not in present]

    return {
        "actual": actual,
        "blocking_new": blocking_new,
        "unknown_hard_codes": unknown_hard,
        "observed_delta": observed_delta,
        "stale_exemptions": stale,
        "dead_code": dead_code_reconcile(items, None),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="staticcheck 报告与基线比对门禁")
    ap.add_argument("--report", required=True, help="staticcheck -f json 的输出文件")
    ap.add_argument("--strict", action="store_true",
                    help="观察档计数变化也判红（本地自查用，CI 不启用）")
    ap.add_argument("--json", action="store_true", help="输出 JSON 而不是人读文本")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.report):
        print(f"[fail-closed] 报告不存在：{args.report}", file=sys.stderr)
        return EXIT_UNVERIFIABLE

    rows, bad = load_report(args.report)
    if not rows:
        print("[fail-closed] 报告为空或全部行无法解析——扫不到不等于干净", file=sys.stderr)
        return EXIT_UNVERIFIABLE

    root = os.environ.get(_SCAN_ROOT_ENV)
    items = normalize(rows, root)
    baseline = load_baseline()
    res = evaluate(items, baseline)

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        print(f"告警总数：{len(items)}（解析失败行：{bad}）")
        print("按 code：" + ", ".join(f"{k}={v}" for k, v in sorted(res["actual"].items())))

    verdict = EXIT_OK
    if res["blocking_new"]:
        verdict = EXIT_BLOCKED
        print(f"\n[阻断] 新增语义类告警 {len(res['blocking_new'])} 条：", file=sys.stderr)
        for it in res["blocking_new"][:40]:
            print(f"  {it['code']} {it['file']}:{it['line']} {it['message'][:90]}",
                  file=sys.stderr)
    if res["unknown_hard_codes"]:
        verdict = EXIT_BLOCKED
        print(f"\n[阻断] 基线未登记的语义类 code：{', '.join(res['unknown_hard_codes'])}"
              f"——先裁定归属（阻断/观察）再登记基线，不得直接放行", file=sys.stderr)
    if res["observed_delta"]:
        print("\n[观察] 与基线计数不一致（不阻断，但需在 PR 说明）：")
        for d in res["observed_delta"]:
            print(f"  {d['code']}: 基线 {d['baseline']} → 实际 {d['actual']}")
        if args.strict:
            verdict = EXIT_BLOCKED
            print("  --strict 已开启：观察档变化判红", file=sys.stderr)
    if res["stale_exemptions"]:
        print("\n[提示] 以下豁免条目在当前报告里已不存在（代码可能被改写/删除，请清理基线）：")
        for e in res["stale_exemptions"]:
            print(f"  {e.get('code')} {e.get('file')} — {e.get('symbol') or ''}")

    dc = res["dead_code"]
    if not dc["ledger_present"]:
        print("\n[阻断] 死代码台账缺失（scripts/dead_code_ledger.json）——"
              "U1000 不接受 file:\"*\" 兜底", file=sys.stderr)
        verdict = EXIT_BLOCKED
    else:
        if dc["missing"]:
            verdict = EXIT_BLOCKED
            print(f"\n[阻断] {len(dc['missing'])} 条 U1000 未登记进死代码台账：",
                  file=sys.stderr)
            for k in dc["missing"][:40]:
                print(f"  {k}", file=sys.stderr)
            print("  处置二选一：修掉它，或在 dead_code_ledger.json 的 rules 里"
                  "登记 verdict + reason（不得用类级豁免糊过去）", file=sys.stderr)
        if dc["extra"]:
            print(f"\n[提示] 台账里 {len(dc['extra'])} 条在当前报告中已消失"
                  f"（可能已修复/删除，请用 --write 重建明细清理）：")
            for k in dc["extra"][:20]:
                print(f"  {k}")

    if bad:
        print(f"\n[提示] 报告中有 {bad} 行无法解析（不计入判定）")

    if verdict == EXIT_OK and not args.json:
        print("\n[gate] 无新增语义类告警")
    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
