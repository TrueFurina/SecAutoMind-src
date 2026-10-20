#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_scope_boundary.py — SecAutoMind 能力面范围边界初筛（2026-10-20）

REA 映射 #178/#180/#181/#188（CONTRIBUTING.md Contribution scope）：
  按实际能力/副作用/默认/完整工作流评估贡献，不按名字；八类排除清单
  成文；移进可选依赖/插件不豁免；表单未勾选≠未发生。

本脚本是**名字级初筛**，不是门禁、不定罪：
  - 命中八类关键词 = 进「需人工判定」清单（按 #178 评实际能力）；
  - 未命中 = 初判不在八类，但**未命中≠不在**（#188），结论须人工签字；
  - WebShell/C2 等授权渗透管理功能命中关键词时标注为「合法功能待评」，
    不自动判违规。

三源合一（聚合既有真值源，不重造）：
  1. tools/*.yaml 的 name（YAML 安全工具声明）
  2. internal/mcp/builtin/constants.go 的 Tool* 常量（Go 内置 MCP 工具）
  3. count_stats.py --json（CTF 求解器计数，真值源口径）

用法：python -X utf8 scripts/audit_scope_boundary.py
输出：deliverables/scope-boundary-audit-<日期>.json + stdout 摘要
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "tools"
CONSTANTS = ROOT / "internal" / "mcp" / "builtin" / "constants.go"
DELIV = ROOT / "deliverables"

# 八类排除（REA CONTRIBUTING.md 120-127 的映射；第 1/2/3 组为名字可初筛组）
EXCLUDED_CATEGORIES = {
    "C1_商业保护破解与自动还原": [
        r"crack", r"keygen", r"unpack", r"脱壳", r"devirtual",
        r"vmp", r"themida", r"vmprotect", r"enigma", r"armadillo",
    ],
    "C2_反调试规避与DRM绕过": [
        r"bypass", r"anti.?debug", r"drm", r"license", r"anti.?cheat",
        r"tamper", r"patch", r"过宝典", r"风控绕过",
    ],
    "C3_利用载荷与凭证窃取与持久化": [
        r"exploit", r"payload", r"\bpwn\b", r"steal", r"credential",
        r"harvest", r"persistence", r"backdoor", r"rootkit", r"\brat\b",
        r"botnet", r"brute.?force", r"spray", r"批量攻击",
    ],
}

# 合法但需按 #178 评实际能力的功能族（命中上述词时的降噪标注）
LEGITIMATE_FAMILIES = {
    "webshell": "授权渗透管理（WebShell 管理助手/连接管理），评点：执行与写文件边界、目标授权依据",
    "c2": "授权渗透 C2 管理，评点：通信目标授权、持久化安装是否用户显式触发",
}

YAML_NAME = re.compile(r'^name:\s*"([^"]+)"', re.M)
GO_CONST = re.compile(r'^\s*Tool\w+\s*=\s*"([^"]+)"', re.M)


def collect() -> dict[str, list[str]]:
    sources: dict[str, list[str]] = {"yaml_tools": [], "go_builtin": [], "ctf_note": []}
    if TOOLS_DIR.is_dir():
        names = set()
        for f in sorted(TOOLS_DIR.glob("*.yaml")):
            if f.name.startswith("_"):
                continue
            m = YAML_NAME.search(f.read_text(encoding="utf-8", errors="replace"))
            if m:
                names.add(m.group(1))
        sources["yaml_tools"] = sorted(names)
    if CONSTANTS.is_file():
        sources["go_builtin"] = sorted(set(GO_CONST.findall(
            CONSTANTS.read_text(encoding="utf-8", errors="replace"))))
    # CTF：只取计数口径（名字级清单在 Go 注册表，按 count_stats 诚实口径引用）
    try:
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "count_stats.py"), "--json"],
                             capture_output=True, encoding="utf-8", timeout=300, cwd=str(ROOT))
        stats = json.loads(out.stdout)
        sources["ctf_note"] = [
            f"ctf_solvers={stats.get('ctf_solvers')}",
            f"ctf_real_solvers={stats.get('ctf_real_solvers')}",
            f"ctf_detectors={stats.get('ctf_detectors')}",
        ]
    except Exception as e:  # noqa: BLE001 —— 真值源不可用必须显式失败，不静默零
        print(f"WARN: count_stats 聚合失败（CTF 口径缺失，按 fail-closed 留痕）: {e}",
              file=sys.stderr)
        sources["ctf_note"] = ["ctf_counts=UNAVAILABLE"]
    return sources


def classify(name: str) -> list[tuple[str, str]]:
    low = name.lower()
    hits = []
    for cat, patterns in EXCLUDED_CATEGORIES.items():
        for p in patterns:
            if re.search(p, low):
                hits.append((cat, p))
                break
    return hits


def main() -> int:
    sources = collect()
    all_names = sorted(set(sources["yaml_tools"]) | set(sources["go_builtin"]))
    # 准入清单（REA #169）：只标注，不隐藏。清单为空是合法状态——
    # 没有裁定过就不该有准入；有裁定必须有审计日期/理由/到期日。
    try:
        from scope_allowlist import decide, load  # 同目录，脚本运行时 sys.path[0] 即 scripts/
    except ImportError:  # 以包方式导入时（tests/ 里）
        from scripts.scope_allowlist import decide, load  # type: ignore
    entries, allow_problems = load()

    flagged, clean = [], []
    for n in all_names:
        hits = classify(n)
        note = ""
        for fam, desc in LEGITIMATE_FAMILIES.items():
            if fam in n.lower():
                note = desc
                break
        item = {"name": n, "hits": [h[0] for h in hits],
                "patterns": [h[1] for h in hits], "note": note}
        if hits:
            status, entry = decide(n, item["hits"][0], entries)
            item["allowlist_status"] = status      # allowed / expired / none
            if entry:
                item["allowlist"] = {k: entry.get(k) for k in
                                     ("reason", "audited_on", "expires_on", "reviewer")}
            flagged.append(item)
        else:
            clean.append(item)

    stamp = datetime.now().strftime("%Y-%m-%d")  # 本地日期（报告按用户时区归档）
    report = {
        "tool": "audit_scope_boundary",
        "repo": str(ROOT),
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "sources": {k: v if k != "ctf_note" else v for k, v in sources.items()},
        "totals": {
            "names_screened": len(all_names),
            "flagged_for_human_review": len(flagged),
            "no_keyword_hit": len(clean),
        },
        "scope_note": (
            "名字级初筛，非门禁不定罪（REA #178/#188）：命中=需人工按实际能力判定；"
            "未命中≠不在八类；CTF 求解器按 count_stats 诚实口径（real/detector 分开）引用，"
            "未逐个名字筛查（181 项，P1 待办）。结论须人工签字后生效。"),
        "flagged": flagged,
        "clean": [c["name"] for c in clean],
        "allowlist": {
            "path": "config/scope_allowlist.json",
            "valid_entries": len(entries),
            "problems": allow_problems,
            "counts": {
                "allowed": sum(1 for f in flagged if f.get("allowlist_status") == "allowed"),
                "expired": sum(1 for f in flagged if f.get("allowlist_status") == "expired"),
                "pending": sum(1 for f in flagged if f.get("allowlist_status") == "none"),
            },
            "note": "准入只标注不隐藏；过期条目等于没有准入，须重新审计（REA #169）。",
        },
    }
    DELIV.mkdir(parents=True, exist_ok=True)
    out = DELIV / f"scope-boundary-audit-{stamp}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 68)
    print("  SecAutoMind · 能力面范围边界初筛（REA #178/#180/#188）")
    print(f"  筛查名字 {report['totals']['names_screened']} 个"
          f"（yaml {len(sources['yaml_tools'])} + builtin {len(sources['go_builtin'])}，取并集）")
    print(f"  CTF 口径: {', '.join(sources['ctf_note'])}")
    print("=" * 68)
    if flagged:
        print(f"\n  ⚠️ 需人工判定 {len(flagged)} 项（按 #178 评实际能力，不按名字定罪）：")
        for f in flagged:
            status = f.get("allowlist_status", "none")
            mark = {"allowed": "✅ 已准入", "expired": "⛔ 准入已过期", "none": "待裁"}[status]
            print(f"    - {f['name']:<40} 命中 {','.join(f['hits'])}  [{mark}]"
                  + (f"  [{f['note'][:40]}…]" if f["note"] else ""))
            if f.get("allowlist"):
                a = f["allowlist"]
                print(f"        准入依据：{a['reason']}（审计 {a['audited_on']}，"
                      f"到期 {a['expires_on']}，签字 {a['reviewer']}）")
    else:
        print("\n  ✅ 无名字级命中")

    al = report["allowlist"]
    print(f"\n  准入清单：有效 {al['valid_entries']} 条"
          f"（已准入 {al['counts']['allowed']} / 已过期 {al['counts']['expired']}"
          f" / 待裁 {al['counts']['pending']}）"
          + (f"；清单问题 {len(al['problems'])} 条" if al["problems"] else ""))
    for p in al["problems"]:
        print(f"    ❌ {p}")
    print(f"\n  未命中 {report['totals']['no_keyword_hit']} 项（未命中≠不在八类，#188）")
    print(f"  报告: {out.relative_to(ROOT)}")
    print("\n  边界声明: " + report["scope_note"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
