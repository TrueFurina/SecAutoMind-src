#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""资产元数据覆盖率盘点（P0 落地配套工具）。

定位：**盘点工具，不是门禁**。暂不接 CI。
      升级为门禁前必须补：回归测试 + 变异验证（见 AGENTS.md 第四条）。

口径：
  - 工具数沿用 scripts/count_stats.py 的 TOOLS_YAML_EXCLUDE（排除 risk_policy.yaml），
    并跳过无 name 字段的 _shared_args.yaml —— 与权威口径 91 一致。
  - version/source/trust 是**事实可判定**字段，要求 100% 覆盖，缺失即 rc=1。
  - license 允许 "unknown"：未逐个人工核实前不臆测，unknown 单列统计，不判失败。
  - skills 的 allowed-tools 覆盖率仅报告（当前为 0，属"能力有、资产没用"）。

用法：
  python scripts/audit_asset_metadata.py
  python scripts/audit_asset_metadata.py --check   # 硬指标不达标则 rc=1
"""
import argparse
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_EXCLUDE = {"risk_policy.yaml"}


def top_field(text, key):
    m = re.search(r"^" + re.escape(key) + r":\s*(.+)$", text, re.M)
    return m.group(1).strip().strip('"').strip("'") if m else ""


def audit_tools():
    files = [f for f in sorted(glob.glob(os.path.join(ROOT, "tools", "*.yaml")))
             if os.path.basename(f) not in TOOLS_EXCLUDE]
    tools = []
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        if not re.search(r"^name:", t, re.M):
            continue
        tools.append({
            "file": os.path.basename(f),
            "name": top_field(t, "name"),
            "version": top_field(t, "version"),
            "source": top_field(t, "source"),
            "license": top_field(t, "license"),
            "upstream": top_field(t, "upstream"),
            "trust": top_field(t, "trust"),
        })
    return tools


def audit_skills():
    files = sorted(glob.glob(os.path.join(ROOT, "skills", "*", "SKILL.md")))
    rows = []
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        rows.append({
            "dir": os.path.basename(os.path.dirname(f)),
            "allowed_tools": bool(re.search(r"^allowed-tools:", t, re.M)),
        })
    return rows


def pct(n, d):
    return "%.1f%%" % (100.0 * n / d) if d else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="硬指标不达标则 rc=1")
    args = ap.parse_args()

    tools = audit_tools()
    skills = audit_skills()
    total = len(tools)

    print("=" * 62)
    print("资产元数据覆盖率（盘点，非门禁）")
    print("=" * 62)
    print("工具总数: %d" % total)

    hard_ok = True
    for key in ("version", "source", "trust"):
        n = sum(1 for t in tools if t[key])
        print("  %-8s %3d/%d  %s" % (key, n, total, pct(n, total)))
        if n != total:
            hard_ok = False
            for t in tools:
                if not t[key]:
                    print("      缺: %s" % t["file"])

    lic_unknown = sum(1 for t in tools if t["license"].lower() == "unknown")
    lic_known = total - lic_unknown
    print("  %-8s %3d/%d  %s（其中 unknown=%d，已核实=%d）"
          % ("license", total - lic_unknown, total, pct(lic_known, total), lic_unknown, lic_known))

    # 一致性不变量（单向）：已核实许可证 ⇒ source=upstream 且 upstream 非空。
    # 防"有许可证却无来源"的死数据。刻意不做反向断言——"上游已核实、许可证未核实"
    # 是正当状态（如 gdb/objdump/strings：上游从 GNU 官方页确认，但该包混合
    # GPLv2/GPLv3/LGPL 且官方镜像被反爬拦截，逐文件许可未能核实）。
    bad = [t for t in tools
           if t["license"] and t["license"].lower() != "unknown"
           and (t["source"] != "upstream" or not t["upstream"])]
    if bad:
        hard_ok = False
        print("  %-8s %d 个工具有许可证却无来源，属死数据：" % "不一致", len(bad))
        for t in bad:
            print("      不一致: %s" % t["file"])
    else:
        print("  不一致     0  个（license 已核实的工具均标注 source=upstream 与 upstream）")

    n_up = sum(1 for t in tools if t["upstream"])
    print("  %-8s %3d/%d  %s" % ("upstream", n_up, total, pct(n_up, total)))

    src = {}
    for t in tools:
        src[t["source"] or "(空)"] = src.get(t["source"] or "(空)", 0) + 1
    print("  source 分布: %s" % ", ".join("%s=%d" % kv for kv in sorted(src.items())))

    print("-" * 62)
    print("技能总数: %d" % len(skills))
    n_at = sum(1 for s in skills if s["allowed_tools"])
    print("  allowed-tools %d/%d  %s（解析器已支持，资产未使用）"
          % (n_at, len(skills), pct(n_at, len(skills))))
    print("-" * 62)

    if args.check and not hard_ok:
        print("RESULT: FAIL（version/source/trust 未全覆盖）")
        return 1
    print("RESULT: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
