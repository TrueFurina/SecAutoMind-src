#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_yaml_tool_contracts.py — tools/*.yaml 工具配方契约抽样（REA #176 的 YAML 侧）

`audit_tool_contracts.py` 覆盖的是**内置 Go MCP 工具**（`internal/**` 里的
`Name:` 注册块，实测 47 块 / 52 工具）。本脚本覆盖**另一条完全不同的链路**：
`tools/*.yaml` 里的**外部命令行工具配方**（实测 89 份真声明），它们不经 MCP
注册，由 exec 层按 `command + parameters` 拼命令行。两条链路的契约维度**不能
照抄**——照抄会写出一个"看起来很严、实际判不到东西"的假门禁。

四维度映射（每条都注明了"为什么这么改"）：

  ① 入参轮廓（同 MCP 侧）
     parameters 非空；每项声明 name/type/description；整体是否声明过 required。
     YAML 侧尤其重要：参数表是**命令行拼接的唯一约束**，缺 type 意味着 exec 层
     只能按字符串处理，缺 description 意味着模型无从判断该填什么。

  ② 原样透传面（MCP 侧"错误投影"的等价物）
     MCP 侧能静态判"失败是否走 isError"，YAML 侧**判不到**（错误投影发生在
     exec 层，配方文件里没有错误处理代码）。强行照抄只会得到"全部未知"。
     改判这里**可静态判定**的真实风险：`additional_args` 这类"直接追加到命令行
     末尾"的参数。它把上面①建立的全部约束一次性作废——参数表声明得再细，
     调用方照样能追加任意 flag。实测 89 份里 80 份都有它（89%），所以它**不是
     缺陷而是既定设计**，本脚本只把它**计量并落档**，不进门禁（否则首日永久红，
     结局必然是 `--no-verify`）。

  ③ 响应预算（2026-10-21 从"不知道归谁"收敛为**已定位的实测归属**）
     配方文件里没有输出上限字段——上限由 exec 层统一截断，已定位到代码：
       internal/app/app.go:180  mcpServer.ConfigureToolResultMaxBytes(...)
       internal/app/app.go:186  executor.SetToolOutputMaxBytes(...)
       internal/app/app.go:205  externalMCPMgr.ConfigureToolResultMaxBytes(...)
     三者同源于 `MultiAgentEinoMiddleware.ReductionMaxLengthForTruncEffective()`
     （internal/config/config.go:438），配置项
     `multi_agent.eino_middleware.reduction_max_length_for_trunc`，**默认 12000**；
     超出的部分 spill 落盘（SetToolOutputSpillRoot / ReductionRootDir）。
     所以本脚本记 `budget_field_present: false` 且 `budget_owner = exec`，**不判定**。
     写"未知"比写"通过"诚实；把"未知"变成"归谁、默认值多少、在哪改"才算收敛完。

  ④ 溯源（同 MCP 侧，但字段不同）
     配方自称的来源必须可回查：`source ∈ {upstream, self}`；`source=upstream`
     时必须有 `upstream` URL；`trust` 只能在允许集内（当前仅 `builtin`）。
     `source=self` 却给 upstream/ 或 `source=upstream` 却没 URL，都是**自述与
     事实不符**——这类不一致是静态可判的硬缺陷。

口径对账（本脚本的第二个用途）：
     `count_stats.py` 的 `tools_yaml` 是**权威口径**，实测 90；本脚本按"顶层同时
     含 name+command"数出 89。差的 1 个是 `tools/_shared_args.yaml`——它登记在
     `count_stats.TOOLS_YAML_NOT_A_TOOL_BUT_COUNTED` 里（被各工具以 YAML anchor
     引用，属配方体系，故计入历史口径）。两个独立实现数出不同数字不是 bug，但
     **差值必须能被逐项解释**。本脚本把差值列出来；一旦未来有人往 tools/ 里塞
     非工具 YAML 却没登记，差值就不再等于那张名单 → `unreconciled` 非空 → 门禁红。
     这是"两个计数器互为校验"，比任何一方单独可信。

纪律：
  * 扫描面为空 → exit 2（照不到 ≠ 干净）；
  * 已知存量缺陷走 baseline 登记，只拦新增；
  * 静态判据 ≠ 运行时结论，命中须人工复核。

用法：
  python -X utf8 scripts/audit_yaml_tool_contracts.py           # 摘要
  python -X utf8 scripts/audit_yaml_tool_contracts.py --json    # 机器可读
  python -X utf8 scripts/audit_yaml_tool_contracts.py --gate    # 硬缺陷 exit 1
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# 扫描根可用环境变量覆盖：自测需要构造假仓库（真实仓不能为测试而改动）。
ROOT = Path(os.environ.get("SECAUTOMIND_YAML_TOOL_SCAN_ROOT")
            or Path(__file__).resolve().parent.parent)
TOOLS_DIR = ROOT / "tools"

#: 允许的 trust 取值。当前 89/89 都是 builtin；新增取值必须先有人裁定过它意味着
#: 什么（trust 决定 HITL 档位），故不在表内即硬缺陷，不做"未知也放行"。
TRUST_ALLOWED = {"builtin"}

#: 允许的 source 取值（上游移植 / 自研）。
SOURCE_ALLOWED = {"upstream", "self"}

#: 溯源缺口基线：`source=upstream` 却缺 `upstream` URL、且**仍在启用**的历史成员。
#: 当前为空——唯一命中的 `hashpump` 是 `enabled: false` 的置灰留档（上游仓库已消失、
#: 核实失败而留空，配方头有完整记录），按"置灰不判缺陷"处理，不再占用本表。
#: 表保留为空而非删掉：将来真出现启用态的溯源缺口时，仍要有"登记而不阻断"这条路。
BASELINE_PROVENANCE_GAPS: dict[str, str] = {}

#: 原样透传参数名：把调用方字符串直接拼进命令行末尾。
RAW_PASSTHROUGH_PARAMS = ("additional_args",)

#: 一份"像工具声明"的 YAML 至少要有这两个顶层键（与 count_stats 的守卫同判据）。
TOOL_TOP_KEYS = ("name", "command")


def _load_yaml():
    """导入 PyYAML；缺失时返回 None（由 main fail-closed，而不是静默当通过）。"""
    try:
        import yaml  # noqa: F401
        return yaml
    except Exception:
        return None


def _iter_docs(yaml_mod) -> list[dict]:
    """读 tools/*.yaml，返回 [{file, doc}]；坏文件单独留痕（不静默跳过）。"""
    out: list[dict] = []
    for path in sorted(TOOLS_DIR.glob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            out.append({"file": path.name, "doc": None, "error": f"读不出：{exc}"})
            continue
        try:
            doc = yaml_mod.safe_load(text)
        except Exception as exc:                      # YAMLError 等
            out.append({"file": path.name, "doc": None, "error": f"解析失败：{exc}"})
            continue
        out.append({"file": path.name, "doc": doc})
    return out


def reconcile_sets(all_yaml: set[str], exclude: set[str], counted_nontool: set[str],
                   declared_files: set[str]) -> dict:
    """纯函数：权威口径 vs 本脚本口径的差值归因（不碰文件系统，便于单测）。

    权威口径 = 目录内全部 yaml - 显式排除（与 `count_stats._count_files` 同判据）。
    差出来的每一份必须能在 `counted_nontool`（已登记的非工具成员）里找到解释，
    否则就是"有人往 tools/ 塞了非工具 YAML 却没登记" → unreconciled → 门禁红。
    """
    in_scope = set(all_yaml) - set(exclude)
    expected_nontool = in_scope - set(declared_files)
    return {
        "authoritative_tools_yaml": len(in_scope),
        "declared_tool_files": len(declared_files),
        "delta": len(in_scope) - len(declared_files),
        "counted_but_not_a_tool": sorted(expected_nontool & set(counted_nontool)),
        "unreconciled": sorted(expected_nontool - set(counted_nontool)),
    }


def _reconcile(declared_files: set[str]) -> dict:
    """与 count_stats 的权威口径对账。扫描根被覆盖（自测假仓）时如实标注不可比。"""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import count_stats  # noqa: WPS433
    except Exception as exc:
        return {"status": "unavailable", "reason": f"count_stats 不可导入：{exc}"}
    if Path(count_stats.ROOT).resolve() != ROOT.resolve():
        return {"status": "skipped",
                "reason": "扫描根被覆盖（自测假仓），与真实仓口径不可比"}
    return {
        "status": "ok",
        **reconcile_sets(
            all_yaml={p.name for p in TOOLS_DIR.glob("*.yaml")},
            exclude=set(getattr(count_stats, "TOOLS_YAML_EXCLUDE", set())),
            counted_nontool=set(getattr(count_stats, "TOOLS_YAML_NOT_A_TOOL_BUT_COUNTED", set())),
            declared_files=declared_files,
        ),
    }


def scan() -> dict:
    yaml_mod = _load_yaml()
    records: list[dict] = []
    declared: set[str] = set()
    for item in (_iter_docs(yaml_mod) if yaml_mod else []):
        name = item["file"]
        doc = item["doc"]
        rec = {
            "file": name,
            "tool": None,
            "is_tool": False,
            "error": item.get("error"),
            "has_command": False,
            # 置灰（enabled: false）的配方不对外可用：判它的契约缺陷只会制造噪音，
            # 而且会随每次新增置灰工具不断变长。故只计量、不进硬缺陷。
            "enabled": True,
            "param_count": 0,
            "required_declared": False,
            "params_missing_type": [],
            "params_missing_desc": [],
            "raw_passthrough": [],
            "budget_field_present": False,
            "source": None,
            "trust": None,
            "has_upstream": False,
            "provenance_gap": False,
        }
        records.append(rec)
        if not isinstance(doc, dict):
            continue
        keys = set(doc)
        rec["tool"] = doc.get("name") if isinstance(doc.get("name"), str) else None
        rec["is_tool"] = all(k in keys for k in TOOL_TOP_KEYS)
        if not rec["is_tool"]:
            continue
        declared.add(name)
        rec["has_command"] = bool(str(doc.get("command") or "").strip())
        rec["enabled"] = doc.get("enabled") is not False
        params = doc.get("parameters")
        if isinstance(params, list):
            for p in params:
                if not isinstance(p, dict):
                    continue
                rec["param_count"] += 1
                pname = str(p.get("name") or "")
                if not str(p.get("type") or "").strip():
                    rec["params_missing_type"].append(pname or "<无名>")
                if not str(p.get("description") or "").strip():
                    rec["params_missing_desc"].append(pname or "<无名>")
                if p.get("required"):
                    rec["required_declared"] = True
                if pname in RAW_PASSTHROUGH_PARAMS:
                    rec["raw_passthrough"].append(pname)
        rec["budget_field_present"] = any(
            str(k).lower() in ("output_limit", "max_output", "truncate", "response_budget")
            for k in keys)
        rec["source"] = doc.get("source")
        rec["trust"] = doc.get("trust")
        rec["has_upstream"] = bool(str(doc.get("upstream") or "").strip())
        rec["provenance_gap"] = (doc.get("source") == "upstream" and not rec["has_upstream"])
    return {"records": records, "declared_files": declared,
            "files_total": len(records), "yaml_available": yaml_mod is not None}


def summarize(result: dict) -> dict:
    recs = [r for r in result["records"] if r["is_tool"]]
    tools = {r["tool"] or r["file"]: r for r in recs}
    hard: list[dict] = []
    for key, r in tools.items():
        if not r["enabled"]:
            continue
        if not r["has_command"]:
            hard.append({"tool": key, "kind": "缺 command"})
        if r["param_count"] == 0:
            hard.append({"tool": key, "kind": "缺 parameters"})
        if r["params_missing_type"]:
            hard.append({"tool": key, "kind": "参数缺 type",
                         "detail": r["params_missing_type"]})
        if r["trust"] not in TRUST_ALLOWED:
            hard.append({"tool": key, "kind": "trust 不在允许集",
                         "detail": r["trust"]})
        if r["source"] not in SOURCE_ALLOWED:
            hard.append({"tool": key, "kind": "source 不在允许集",
                         "detail": r["source"]})
        if r["provenance_gap"]:
            hard.append({"tool": key, "kind": "source=upstream 但缺 upstream URL"})
    baselined = [h for h in hard
                 if h["kind"] == "source=upstream 但缺 upstream URL"
                 and h["tool"] in BASELINE_PROVENANCE_GAPS]
    fresh = [h for h in hard if h not in baselined]
    raw_pt = sorted(n for n, r in tools.items() if r["raw_passthrough"])
    return {
        "files_total": result["files_total"],
        "declared_tools": len(tools),
        "parse_errors": [{"file": r["file"], "error": r["error"]}
                         for r in result["records"] if r["error"]],
        "params_total": sum(r["param_count"] for r in tools.values()),
        "params_missing_desc": sorted({f"{n}:{p}" for n, r in tools.items()
                                       for p in r["params_missing_desc"]}),
        # ②：计量并落档，不进硬门禁（89% 命中 = 既定设计，非缺陷）
        "raw_passthrough_tools": raw_pt,
        "raw_passthrough_ratio": (f"{len(raw_pt)}/{len(tools)}" if tools else "0/0"),
        # ③：显式越界声明
        "budget_field_present_any": any(r["budget_field_present"] for r in tools.values()),
        "budget_out_of_scope_note": "响应预算归 exec 层（不在配方里），本脚本不判定",
        "budget_owner": "exec",
        "budget_config_key": "multi_agent.eino_middleware.reduction_max_length_for_trunc",
        "budget_default_bytes": 12000,
        "budget_applied_at": [
            "internal/app/app.go:180 mcpServer.ConfigureToolResultMaxBytes",
            "internal/app/app.go:186 executor.SetToolOutputMaxBytes",
            "internal/app/app.go:205 externalMCPMgr.ConfigureToolResultMaxBytes",
        ],
        "budget_overflow": "超出部分 spill 落盘（SetToolOutputSpillRoot / ReductionRootDir）",
        "tools_without_required": sorted(n for n, r in tools.items()
                                         if not r["required_declared"]),
        # 「无 required」是两回事，别混着报：真正零参（param_count=0）大概率是
        # "跑就完了"的扫描器；**有参数却一个必填都没有**的，才需要人工确认是不是
        # 漏标（这类才是可疑项）。2026-10-21 起分开计数。
        "tools_zero_param": sorted(n for n, r in tools.items()
                                   if not r["required_declared"] and r["param_count"] == 0),
        "tools_all_optional_params": sorted(n for n, r in tools.items()
                                            if not r["required_declared"]
                                            and r["param_count"] > 0),
        # 置灰留档：不对外可用，故不判缺陷，但要被看见（否则"89 份"里混着 10 份
        # 谁也调不动的，对外宣称工具数时容易虚报）。
        "disabled_tools": sorted(n for n, r in tools.items() if not r["enabled"]),
        "hard_defects": hard,
        "hard_defects_baselined": baselined,
        "hard_defects_fresh": fresh,
        "reconcile": _reconcile(result["declared_files"]),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="tools/*.yaml 工具配方契约抽样")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--gate", action="store_true",
                    help="硬缺陷（含口径不可对账）时 exit 1；baseline 内的不阻断")
    args = ap.parse_args(argv)

    if not TOOLS_DIR.is_dir():
        print(f"[fail-closed] 工具目录不存在：{TOOLS_DIR.name}/（扫描面为空不能当作干净）",
              file=sys.stderr)
        return 2
    if _load_yaml() is None:
        print("[fail-closed] 未安装 PyYAML，无法解析配方文件。"
              "请 `pip install pyyaml`（CI 见 ci.yml caliber-gate 的安装步）——"
              "按'未检查'处理，不得当作通过。", file=sys.stderr)
        return 2
    result = scan()
    # 注意：declared_files 是 set，`set() == 0` 恒为 False（首版就这么写的，
    # 空目录一路绿灯通过——被自测 test_empty_tools_dir_exits_2 逮到）。
    if not result["declared_files"]:
        print("[fail-closed] 一个工具声明都没扫到（扫描面为空不能当作干净）", file=sys.stderr)
        return 2
    summary = summarize(result)

    if args.json:
        print(json.dumps({"summary": summary,
                          "tools": {r["tool"] or r["file"]: r
                                    for r in result["records"] if r["is_tool"]}},
                         ensure_ascii=False, indent=1))
    else:
        print(f"tools/ 下 YAML 文件 {summary['files_total']} 份；"
              f"其中工具声明 {summary['declared_tools']} 份，参数 {summary['params_total']} 个")
        rec = summary["reconcile"]
        if rec["status"] == "ok":
            print(f"口径对账：count_stats.tools_yaml={rec['authoritative_tools_yaml']}，"
                  f"本脚本={rec['declared_tool_files']}，差 {rec['delta']} "
                  f"（登记的非工具成员：{', '.join(rec['counted_but_not_a_tool']) or '无'}）")
            if rec["unreconciled"]:
                print(f"  ⚠️ 差值无法解释：{', '.join(rec['unreconciled'])}")
        else:
            print(f"口径对账：{rec['status']}（{rec['reason']}）")
        print(f"\n② 原样透传参数（additional_args）：{summary['raw_passthrough_ratio']} 份工具"
              f"——属既定设计，仅计量")
        print(f"③ 响应预算：{summary['budget_out_of_scope_note']}")
        print(f"\n全无 required 声明的工具（{len(summary['tools_without_required'])}）："
              f"{', '.join(summary['tools_without_required']) or '无'}")
        print(f"  ├ 真·零参（跑就完了）：{len(summary['tools_zero_param'])} → "
              f"{', '.join(summary['tools_zero_param']) or '无'}")
        print(f"  └ 有参数却全可选（**需人工确认是否漏标必填**）："
              f"{len(summary['tools_all_optional_params'])} → "
              f"{', '.join(summary['tools_all_optional_params']) or '无'}")
        if summary["disabled_tools"]:
            print(f"置灰留档（enabled: false，不判缺陷但须被看见，"
                  f"{len(summary['disabled_tools'])} 份）："
                  f"{', '.join(summary['disabled_tools'])}")
        print(f"参数缺 description（{len(summary['params_missing_desc'])}）："
              f"{', '.join(summary['params_missing_desc']) or '无'}")
        if summary["parse_errors"]:
            print(f"\n⚠️ 解析失败 {len(summary['parse_errors'])} 份："
                  f"{', '.join(e['file'] for e in summary['parse_errors'])}")
        if summary["hard_defects"]:
            print(f"\n硬缺陷 {len(summary['hard_defects'])} 项"
                  f"（baseline {len(summary['hard_defects_baselined'])}）：")
            for h in summary["hard_defects"]:
                tag = " [baseline]" if h in summary["hard_defects_baselined"] else ""
                detail = f" → {h['detail']}" if "detail" in h else ""
                print(f"  - {h['tool']}: {h['kind']}{detail}{tag}")
        else:
            print("\n硬缺陷：无")
        print("\n口径：静态解析，配方文件的运行时行为须人工复核；"
              "未命中≠合格（拼接逻辑在 exec 层）。")

    if args.gate:
        blockers = summary["hard_defects_fresh"]
        if summary["parse_errors"]:
            print(f"\n[gate] {len(summary['parse_errors'])} 份配方解析失败（解析不了 ≠ 合规）",
                  file=sys.stderr)
            return 1
        rec = summary["reconcile"]
        if rec["status"] == "ok" and rec["unreconciled"]:
            print(f"\n[gate] 口径差值无法解释：{', '.join(rec['unreconciled'])}"
                  f"（新增非工具 YAML 须登记到 count_stats.TOOLS_YAML_EXCLUDE）",
                  file=sys.stderr)
            return 1
        if blockers:
            print(f"\n[gate] 新增硬缺陷：{len(blockers)} 项 → "
                  f"{', '.join(sorted({b['tool'] for b in blockers}))}", file=sys.stderr)
            return 1
        print("\n[gate] 无新增硬缺陷（baseline 内的历史项不阻断）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
