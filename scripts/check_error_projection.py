#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_error_projection.py — 工具错误投影静态守卫（REA #10 / #176）

MCP 工具把失败写进**结果文本**而不是状态码，模型看到的就是一段话。若把
`err.Error()` 原样拼进去，`database is locked`、表名、SQL 片段、绝对路径会
被模型当成事实继续推理，甚至写进报告。

判据（写在 `internal/app/tool_error.go` 的函数注释里，这里只做机械执行）：

    err 来自**本项目入参校验**  → 直出（它就是可行动文案，模型靠它自我纠正）
    err 来自**数据库/驱动/序列化/作用域解析** → 必须走 `toolInternalError`

守卫生效方式：**存量登记基线，只拦新增**。2026-10-21 把 26 处直出收敛到 4 处
（全部是入参校验），基线即这 4 条；之后再出现任何一处新的 `err.Error()` 直出，
都要重新裁定一次——这正是守卫的价值：不是禁止，是**不让新增悄悄发生**。

基线键 = `文件 | 该行去空白后的文本`。用**行文本**而不是行号：行号随任何插入
漂移，一行文本变了说明代码真变了。条目对不上（那段代码被改写或删掉）时记
`stale` 并告警——**漂移要被人看见**，不能静默。

用法：
  python -X utf8 scripts/check_error_projection.py           # 报告
  python -X utf8 scripts/check_error_projection.py --gate    # 新增直出 exit 1
  python -X utf8 scripts/check_error_projection.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("SECAUTOMIND_ERROR_SCAN_ROOT")
            or Path(__file__).resolve().parent.parent)
SCAN_DIRS = [ROOT / "internal"]
BASELINE_PATH = Path(__file__).resolve().parent / "error_projection_baseline.json"

#: 命中条件：同一行里 textResult(...) 且把 err.Error() 拼进对外文案。
#: 只看 `err.Error()` 而不过度泛化（如 `err.Error()` 传给 `fmt.Errorf` 包一层是合法的）。
_HIT_RE = re.compile(r"textResult\([^\n]*err\.Error\(\)")

#: 已知安全的例外：进日志不进结果。出现这些调用的行不算直出。
_SAFE_RE = re.compile(r"toolInternalError|logger\.(Error|Warn|Info)\(|log\.Printf\(")


def _iter_lines():
    for base in SCAN_DIRS:
        if not base.is_dir():
            continue
        for path in base.rglob("*.go"):
            if path.name.endswith("_test.go"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                yield str(path.relative_to(ROOT)).replace("\\", "/"), i, line


def scan() -> list[dict]:
    hits: list[dict] = []
    for rel, lineno, line in _iter_lines():
        stripped = line.strip()
        # 注释里的示例不算：**要防的是会执行的代码行**。注释掉的反例本身
        # 不会泄漏，把它也计进来只会让基线里塞满噪音（tool_error.go 的函数
        # 文档就引用了反例写法）。
        if stripped.startswith("//"):
            continue
        if not _HIT_RE.search(line):
            continue
        if _SAFE_RE.search(line):
            continue
        hits.append({"file": rel, "line": lineno, "text": stripped})
    return hits


def load_baseline() -> dict:
    if not BASELINE_PATH.is_file():
        return {"entries": []}
    try:
        doc = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"entries": []}
    return doc if isinstance(doc, dict) and isinstance(doc.get("entries"), list) else {"entries": []}


def classify(hits: list[dict]) -> dict:
    """把命中分成 基线内 / 新增 / 基线已失效 三类。"""
    keys = {f"{e['file']}|{e['text']}" for e in load_baseline()["entries"]}
    fresh, known = [], []
    for h in hits:
        key = f"{h['file']}|{h['text']}"
        (known if key in keys else fresh).append(h)
    seen = {f"{h['file']}|{h['text']}" for h in hits}
    stale = [e for e in load_baseline()["entries"] if f"{e['file']}|{e['text']}" not in seen]
    return {"known": known, "fresh": fresh, "stale": stale}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="工具错误投影静态守卫")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--gate", action="store_true", help="出现基线外的新增直出时 exit 1")
    args = ap.parse_args(argv)

    hits = scan()
    # fail-closed：一个 textResult 都没扫到说明扫描面错了（目录改名/被 gitignore），
    # 此时"0 命中"是假绿——守卫自己先失效了。
    total_lines = sum(1 for _ in _iter_lines())
    if total_lines == 0:
        print("[fail-closed] internal/ 下没扫到任何 Go 行（扫描面为空不能当作干净）",
              file=sys.stderr)
        return 2
    res = classify(hits)

    if args.json:
        print(json.dumps({"scanned_files_ok": True, "hits": hits, **res},
                         ensure_ascii=False, indent=1))
    else:
        print(f"扫描 internal/ · 命中 err.Error() 直出 {len(hits)} 处"
              f"（基线内 {len(res['known'])} / 新增 {len(res['fresh'])}）")
        for h in res["fresh"]:
            print(f"  [新增] {h['file']}:{h['line']}  {h['text']}")
        if res["stale"]:
            print(f"基线失效条目 {len(res['stale'])} 条（对应代码已改写/删除，需清理）：")
            for e in res["stale"]:
                print(f"  [stale] {e['file']}  {e.get('text', '')}")
        if not hits:
            print("  （无直出；若这是假象请检查扫描根）")
        print("\n口径：直出≠必错——入参校验错误的 err 本就该直出；"
              "但**新增**的每一处都要重新裁定一次。")

    if args.gate:
        if res["fresh"]:
            print(f"\n[gate] 基线外新增 {len(res['fresh'])} 处 err.Error() 直出 →"
                  f" 请改走 toolInternalError，或确认属入参校验后登记基线",
                  file=sys.stderr)
            return 1
        print("\n[gate] 无新增直出（基线内的历史项不阻断）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
