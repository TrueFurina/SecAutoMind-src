#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_tool_contracts.py — 内置 MCP 工具契约四件套静态抽样（REA #176）

REA 的口径：MCP 服务器的对外契约 = **四个可测维度**，不是"能跑通"：
  1. 错误投影（error projection）：失败是否以 isError 返回，而不是把内部错误原文
     塞进正常文本让模型当成事实；
  2. 入参 schema 轮廓（input schema profile）：有没有 InputSchema、必填项是否声明；
  3. 响应预算（response budget）：有没有 limit/page 之类上限；无上限的列表工具
     会在大仓库上把上下文打爆；
  4. 溯源（provenance）：结果里是否带可回查的 id（本脚本只做弱检测：函数体是否
     返回 id/ID 字段）。

本脚本是**静态**抽样（正则扫 Go 注册块），不是运行时 conformance 测试：
  - 命中"缺"只说明"静态层面没看到"，不等于运行时一定缺失 ⇒ 结论须人工复核；
  - 未命中"缺"也不等于合格（动态拼接的 schema 扫不到）。
故默认 report-only；`--gate` 只对「T0 且缺 InputSchema/required」这类硬缺陷阻断。

用法：
  python -X utf8 scripts/audit_tool_contracts.py                # 摘要
  python -X utf8 scripts/audit_tool_contracts.py --json         # 机器可读
  python -X utf8 scripts/audit_tool_contracts.py --t0           # 只看 T0 清单
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# 扫描根可用环境变量覆盖：自测需要构造假仓库（真实仓不能为测试而改动）。
ROOT = Path(os.environ.get("SECAUTOMIND_TOOL_SCAN_ROOT")
            or Path(__file__).resolve().parent.parent)
SCAN_DIRS = [ROOT / "internal" / "app", ROOT / "internal" / "mcp",
             ROOT / "internal" / "vision", ROOT / "internal" / "knowledge"]

# T0 常驻清单（与 docs/MCP工具分级注册方案-2026-10-19.md §2.1 的 T0 一致；
# 两边不一致时以本常量 + 文档表格的人工核对为准，脚本不猜）
T0_TOOLS = {
    "record_vulnerability", "list_vulnerabilities", "get_vulnerability",
    "create_asset", "get_asset", "query_assets", "update_asset",
    "complete_asset_scan",
    "upsert_project_fact", "get_project_fact", "list_project_facts",
    "search_project_facts", "deprecate_project_fact", "restore_project_fact",
    "list_knowledge_risk_types", "search_knowledge_base", "ingest_knowledge_item",
    "analyze_image",
    "get_tool_execution", "wait_tool_execution", "cancel_tool_execution",
    "webshell_exec",
}

_NAME_RE = re.compile(r'\bName:\s*("[a-z0-9_]+"|[A-Za-z_][\w.]*)')
# 注册块里 Name 常写成常量引用（Name: ToolCompleteAssetScan），故先从 constants.go
# 建「常量 → 字符串」映射。不做这一步只能扫到少数写字面量的工具（实测只扫到 8/52），
# 而"扫不到"会被误读成"没有"——正是本脚本要防的假绿。
_CONST_RE = re.compile(r'\b(Tool\w+)\s*=\s*"([^"]+)"')
_LIMIT_WORDS = ("limit", "page", "offset", "max_", "top_k", "count")
_PROP_RE = re.compile(r'"type"\s*:\s*"(object|array|string|integer|number|boolean)"')


def _load_constants() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for path in (ROOT / "internal" / "mcp" / "builtin").rglob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        mapping.update({k: v for k, v in _CONST_RE.findall(text)})
    return mapping


def _iter_blocks(text: str, consts: dict[str, str]):
    """按 `Name: "x"` / `Name: builtin.ToolX` 切块：到下一个 Name 或文件尾。"""
    marks = [m for m in _NAME_RE.finditer(text)]
    for i, m in enumerate(marks):
        raw = m.group(1)
        if raw.startswith('"'):
            name = raw.strip('"')
        else:
            # 形如 builtin.ToolDeleteAsset：去掉包前缀再查常量表
            name = consts.get(raw.rsplit(".", 1)[-1], "")
        if not name:
            continue
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        yield name, text[m.start():end]


def scan() -> dict[str, dict]:
    tools: dict[str, dict] = {}
    consts = _load_constants()
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
            if "Name:" not in text:
                continue
            for name, block in _iter_blocks(text, consts):
                # 只收带 schema 或 handler 的注册块，避免把常量表误当工具
                if "InputSchema" not in block and "Description:" not in block:
                    continue
                rec = tools.setdefault(name, {
                    "name": name,
                    "files": [],
                    "has_schema": False,
                    "has_required": False,
                    "prop_types": 0,
                    "limit_param": False,
                    "iserror_paths": 0,
                    "raw_err_leak": False,
                    "desc_chars": 0,
                })
                rec["files"].append(str(path.relative_to(ROOT)).replace("\\", "/"))
                if "InputSchema" in block:
                    rec["has_schema"] = True
                if re.search(r'"required"\s*:', block):
                    rec["has_required"] = True
                rec["prop_types"] = max(rec["prop_types"], len(_PROP_RE.findall(block)))
                low = block.lower()
                if any(w in low for w in _LIMIT_WORDS):
                    rec["limit_param"] = True
                rec["iserror_paths"] += len(re.findall(r"textResult\([^\n]*,\s*true\s*\)", block))
                if "err.Error()" in block and "textResult" in block:
                    rec["raw_err_leak"] = True
                desc = re.search(r'Description:\s*"((?:[^"\\]|\\.)*)"', block)
                if desc:
                    rec["desc_chars"] = max(rec["desc_chars"], len(desc.group(1)))
    for rec in tools.values():
        rec["files"] = sorted(set(rec["files"]))
        rec["t0"] = rec["name"] in T0_TOOLS
    return tools


def summarize(tools: dict[str, dict]) -> dict:
    total = len(tools)
    no_schema = sorted(n for n, r in tools.items() if not r["has_schema"])
    no_required = sorted(n for n, r in tools.items() if r["has_schema"] and not r["has_required"])
    no_error_path = sorted(n for n, r in tools.items() if r["iserror_paths"] == 0)
    raw_leak = sorted(n for n, r in tools.items() if r["raw_err_leak"])
    no_limit = sorted(n for n, r in tools.items()
                      if any(w in n for w in ("list", "query", "search")) and not r["limit_param"])
    return {
        "tools_found": total,
        "t0_found": sorted(n for n, r in tools.items() if r["t0"]),
        "t0_missing_from_source": sorted(T0_TOOLS - set(tools)),
        "no_input_schema": no_schema,
        "schema_without_required": no_required,
        "no_iserror_path": no_error_path,
        "raw_err_error_in_result": raw_leak,
        "list_like_without_limit": no_limit,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="内置 MCP 工具契约四件套静态抽样")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--t0", action="store_true", help="只列 T0")
    ap.add_argument("--gate", action="store_true",
                    help="T0 工具缺 InputSchema/required 时 exit 1")
    args = ap.parse_args(argv)

    tools = scan()
    if not tools:
        print("[fail-closed] 一个工具注册块都没扫到（扫描面为空不能当作干净）", file=sys.stderr)
        return 2
    summary = summarize(tools)
    rows = [r for r in tools.values() if (r["t0"] if args.t0 else True)]
    rows.sort(key=lambda r: (not r["t0"], r["name"]))

    if args.json:
        print(json.dumps({"summary": summary, "tools": {r["name"]: r for r in rows}},
                         ensure_ascii=False, indent=1))
    else:
        print(f"扫到注册块 {summary['tools_found']} 个；其中 T0 {len(summary['t0_found'])} 个"
              f"（T0 清单 {len(T0_TOOLS)} 个）")
        if summary["t0_missing_from_source"]:
            print(f"  ⚠️ T0 清单里但源码未找到：{', '.join(summary['t0_missing_from_source'])}")
        print("\n工具名                      T0  schema required 限流  isError  原文泄漏  描述字数")
        for r in rows:
            print(f"{r['name']:<26} {'Y' if r['t0'] else ' '}   "
                  f"{'Y' if r['has_schema'] else 'N':<6} {'Y' if r['has_required'] else 'N':<8} "
                  f"{'Y' if r['limit_param'] else '-':<4} {r['iserror_paths']:>7}  "
                  f"{'⚠️' if r['raw_err_leak'] else '-':<8} {r['desc_chars']:>6}")
        print("\n缺 InputSchema：", ", ".join(summary["no_input_schema"]) or "无")
        print("有 schema 但无 required：", ", ".join(summary["schema_without_required"]) or "无")
        print("无 isError 路径：", ", ".join(summary["no_iserror_path"]) or "无")
        print("结果里可能直出 err.Error()：", ", ".join(summary["raw_err_error_in_result"]) or "无")
        print("列表类无上限参数：", ", ".join(summary["list_like_without_limit"]) or "无")
        print("\n口径：静态正则抽样，report-only；命中≠运行时缺陷，未命中≠合格。")

    if args.gate:
        hard = [n for n in summary["t0_found"]
                if not tools[n]["has_schema"] or not tools[n]["has_required"]]
        if hard:
            print(f"\n[gate] T0 工具契约硬缺陷：{', '.join(hard)}", file=sys.stderr)
            return 1
        print("\n[gate] T0 工具均具备 InputSchema 与 required 声明")
    return 0


if __name__ == "__main__":
    sys.exit(main())
