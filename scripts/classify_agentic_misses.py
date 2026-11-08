#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 agentic 跑批的「未解」按**可归因性**拆开，而不是笼统算成「模型不会」。

## 为什么需要这个脚本（真实事故）

`docs/evidence/private_pool_v2_20261107/agentic_s{1,2,3}.result.json` 报 106/120 = 88.3%，
14 次未解里 13 次是 `tool_calls=0` + `got=""` + 18~25s 结束，看着像「模型放弃」。
但同一批结果文件**不含 `llm_rounds`**（每轮 finish_reason / reasoning_chars 都没落盘），
于是「预算被截断（engineering limit）」与「模型想不出（capability limit）」在这批数据里
**同形、不可区分**。把这种行读成能力边界，就是把工程上限记成模型上限。

本脚本做两件事：
  1. 对「字段齐全」的结果，按五类拆分未解（api_error / timeout / truncated / empty_no_tool / wrong_answer）；
  2. 对「字段缺失」（旧格式）的结果，**显式标 attributability=0**，并把「不得据此
     断言解码病理或能力边界」写在输出里 —— 治理手段是让不可归因可见，不是猜。

用法：
    python scripts/classify_agentic_misses.py docs/evidence/private_pool_v2_20261107/agentic_s1.result.json
    python scripts/classify_agentic_misses.py --dir docs/evidence/private_pool_v2_20261107
    python scripts/classify_agentic_misses.py --json  <同上>
    python scripts/classify_agentic_misses.py --selftest
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

# 判定顺序即优先级：先排除「根本没跑成」，再谈「跑了但没答」，最后才是「答了但错」。
# 顺序反了会把额度耗尽（api_error）记成「空答」，这正是 2026-11-07 qwen 403 事故的形态。
CATEGORIES = (
    "api_error",        # HTTP 4xx/5xx、连接失败 —— 分母污染，必须剔除而非计分
    "timeout",          # 服务端长尾 / 单题墙钟耗尽
    "truncated_budget", # finish_reason=length —— 输出预算不够，工程上限
    "empty_no_tool",    # 零工具调用且无任何候选 —— 需 llm_rounds 才能再细分
    "wrong_answer",     # 有候选但 sha256 不匹配 —— 真正的能力信号
    "other",
)

# 这些字段由 solve_one 在 agentic 分支写出（scripts/ctf_stepfun_orchestrator.py）。
# 缺任何一个都说明结果文件早于该埋点，未解行无法归因。
_REQUIRED = ("llm_rounds", "truncated_rounds", "api_error_rounds", "timeout_rounds")


def classify_row(row: dict) -> str:
    """单行未解归因。纯函数，便于变异验证。"""
    if row.get("solved"):
        return "solved"
    if (row.get("api_error_rounds") or 0) > 0:
        return "api_error"
    if row.get("error"):
        # error 非空但没有 api_error_rounds（旧格式）→ 保守归到 api_error，
        # 因为 error 只由异常路径写入，绝不代表「模型答了但答错」。
        return "api_error"
    if (row.get("timeout_rounds") or 0) > 0:
        return "timeout"
    if (row.get("truncated_rounds") or 0) > 0:
        return "truncated_budget"
    if not (row.get("got") or "").strip():
        return "empty_no_tool" if not row.get("tool_calls") else "other"
    return "wrong_answer"


def is_attributable(row: dict) -> bool:
    """该行是否带齐归因所需字段（旧格式结果文件不带）。"""
    return all(k in row for k in _REQUIRED)


def summarize(doc: dict) -> dict:
    details = doc.get("details") or doc.get("results") or []
    counts = {c: 0 for c in CATEGORIES}
    miss_rows, unattrib = [], 0
    for row in details:
        if row.get("solved"):
            counts["solved"] = counts.get("solved", 0) + 1
            continue
        if not is_attributable(row):
            unattrib += 1
        counts[classify_row(row)] += 1
        miss_rows.append({
            "id": row.get("id"),
            "bucket": classify_row(row),
            "attributable": is_attributable(row),
            "tool_calls": row.get("tool_calls"),
            "latency": row.get("latency"),
            "got_len": len((row.get("got") or "")),
            "finish_reasons": [r.get("finish_reason") for r in (row.get("llm_rounds") or [])],
            "error": (row.get("error") or "")[:120],
        })
    total = len(details)
    missed = total - counts.get("solved", 0)
    return {
        "file": None,
        "total": total,
        "solved": counts.get("solved", 0),
        "missed": missed,
        "rate": round(counts.get("solved", 0) / total, 4) if total else 0.0,
        "buckets": {k: v for k, v in counts.items() if k != "solved" and v},
        "unattributable_rows": unattrib,
        # 分母可信度：只要有一行不可归因，本批的"未解原因"就不能整体下结论。
        "attributable": unattrib == 0,
        "rows": miss_rows,
    }


def report(summ: dict, show_rows: bool = True) -> str:
    out = []
    head = "%-46s 总%-4d 解出%-3d 未解%-3d 率%.1f%%" % (
        os.path.basename(summ["file"] or "?"), summ["total"], summ["solved"],
        summ["missed"], summ["rate"] * 100)
    out.append(head)
    if summ["buckets"]:
        out.append("  归因：" + " ｜ ".join("%s=%d" % (k, v) for k, v in summ["buckets"].items()))
    if not summ["attributable"]:
        out.append("  🔴 可归因=否：%d/%d 行缺 %s（旧格式，埋点之前跑的）"
                   % (summ["unattributable_rows"], summ["missed"], "/".join(_REQUIRED)))
        out.append("     ⇒ 本批的未解**无法**区分「预算截断」与「模型放弃」，")
        out.append("        不得据此断言解码病理或能力边界；要归因必须重跑一次（字段已就位）。")
    if show_rows:
        for r in summ["rows"]:
            flag = "" if r["attributable"] else " (不可归因)"
            out.append("    %-32s %-16s tools=%-2s %.1fs got=%dB fr=%s%s" % (
                r["id"], r["bucket"], r["tool_calls"], r["latency"] or 0,
                r["got_len"], ",".join(str(x) for x in r["finish_reasons"]) or "-", flag))
    return "\n".join(out)


def selftest() -> int:
    """契约自测：判定顺序与可归因性都必须能变红。"""
    cases = [
        # (row, 期望桶, 说明)
        ({"solved": True}, "solved", "已解不参与归因"),
        ({"api_error_rounds": 1, "truncated_rounds": 1, "llm_rounds": [],
          "timeout_rounds": 0}, "api_error", "api_error 优先于截断（否则额度耗尽被记成空答）"),
        ({"error": "HTTP 403", "tool_calls": 0, "got": ""}, "api_error", "只有 error 字段也算 api_error"),
        ({"timeout_rounds": 1, "truncated_rounds": 0, "llm_rounds": [],
          "api_error_rounds": 0}, "timeout", "超时单独成桶"),
        ({"truncated_rounds": 2, "timeout_rounds": 0, "api_error_rounds": 0,
          "llm_rounds": []}, "truncated_budget", "length 归截断"),
        ({"tool_calls": 0, "got": "", "truncated_rounds": 0, "timeout_rounds": 0,
          "api_error_rounds": 0, "llm_rounds": []}, "empty_no_tool", "零工具零候选"),
        ({"tool_calls": 3, "got": "", "truncated_rounds": 0, "timeout_rounds": 0,
          "api_error_rounds": 0, "llm_rounds": []}, "other", "用了工具但没候选 → 其他"),
        ({"tool_calls": 1, "got": "flag{x}", "truncated_rounds": 0,
          "timeout_rounds": 0, "api_error_rounds": 0, "llm_rounds": []},
         "wrong_answer", "有候选但不匹配 = 真能力信号"),
    ]
    ok = 0
    for row, want, why in cases:
        got = classify_row(row)
        if got == want:
            ok += 1
            print("  [PASS] %-16s ← %s" % (want, why))
        else:
            print("  [FAIL] 期望 %-16s 实得 %-16s ← %s" % (want, got, why))
    # 可归因性：缺字段必须判 False
    full = {"llm_rounds": [], "truncated_rounds": 0, "api_error_rounds": 0, "timeout_rounds": 0}
    checks = [
        (full, True, "字段齐全 → 可归因"),
        ({"llm_rounds": []}, False, "只有 llm_rounds → 不可归因"),
        ({}, False, "空行 → 不可归因"),
    ]
    for row, want, why in checks:
        got = is_attributable(row)
        if got == want:
            ok += 1
            print("  [PASS] 可归因=%-5s ← %s" % (got, why))
        else:
            print("  [FAIL] 可归因 期望 %s 实得 %s ← %s" % (want, got, why))
    total = len(cases) + len(checks)
    print("结论：%s —— %d/%d" % ("PASS" if ok == total else "FAIL", ok, total))
    return 0 if ok == total else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--dir", default=None, help="扫描目录下的 *.result.json")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-rows", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    files = list(a.files)
    if a.dir:
        files += sorted(glob.glob(os.path.join(a.dir, "*.result.json")))
    if not files:
        print("没有输入文件；用 --dir 或直接给 result.json 路径", file=sys.stderr)
        return 2

    agg = []
    for f in files:
        try:
            doc = json.load(open(f, encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print("跳过 %s：%s" % (f, e), file=sys.stderr)
            continue
        s = summarize(doc)
        s["file"] = f
        agg.append(s)

    if a.json:
        print(json.dumps([{k: v for k, v in s.items() if k != "rows"} for s in agg],
                         ensure_ascii=False, indent=2))
        return 0

    for s in agg:
        print(report(s, show_rows=not a.no_rows))
        print()
    if len(agg) > 1:
        tot = sum(s["total"] for s in agg)
        sol = sum(s["solved"] for s in agg)
        un = sum(s["unattributable_rows"] for s in agg)
        print("合计 %d 题 / 解出 %d = %.1f%% ｜ 不可归因未解行 %d 条"
              % (tot, sol, (sol / tot * 100) if tot else 0, un))
        print("注：逐轮合计是把多轮重复跑当作独立样本，不等于「一题一次」的解出率。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
