#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 ci.yml 自动派生门禁地图 docs/GATES.md。

为什么需要
----------
`ci.yml` 有 28 个 job。每个 job 的"为什么存在"只写在它上方那段注释里，而没人会
逐段读完 857 行 YAML。结果是：**新增门禁没人知道，失效门禁没人发现，同一件事
被两个 job 守也没人察觉**（复杂度单调增长，从不退休）。

本脚本把 ci.yml 当唯一真源，派生出可读地图；`check_agent_docs.py` 校验派生结果
与提交版本一致 —— 地图过期 = 门禁红，杜绝"改了 ci.yml 忘更新地图"。

用法：
  python scripts/gen_gates_map.py           # 打印到 stdout
  python scripts/gen_gates_map.py --write   # 写入 docs/GATES.md
  python scripts/gen_gates_map.py --check   # 与 docs/GATES.md 比对，不一致 rc=1
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI = os.path.join(ROOT, ".github", "workflows", "ci.yml")
OUT = os.path.join(ROOT, "docs", "GATES.md")

JOB_RE = re.compile(r"^  ([a-z0-9][a-z0-9-]*):\s*$")
STEP_NAME_RE = re.compile(r"^      - name:\s*(.+?)\s*$")
RUN_RE = re.compile(r"^        run:\s*(.+?)\s*$")

# 触发词：出现在 run 行里说明该 job 带自测/变异验证
MUTATION_HINTS = ("_test.py", "--self-test", "mutation")


def parse(path):
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    jobs = []
    # 只在 jobs: 段内识别 job，否则 on: 下的 push/pull_request 会被误当成 job
    try:
        start = next(i for i, x in enumerate(lines) if x.rstrip() == "jobs:")
    except StopIteration:
        return []
    for i, line in enumerate(lines[start + 1:], start=start + 1):
        m = JOB_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        # 向上收集紧邻的注释块（2 空格缩进的 "# ..."）
        why = []
        j = i - 1
        while j >= 0 and lines[j].strip().startswith("#"):
            why.append(lines[j].strip().lstrip("#").strip())
            j -= 1
        why.reverse()
        # 向下收集该 job 的 steps
        steps = []
        k = i + 1
        while k < len(lines) and not JOB_RE.match(lines[k]):
            sm = STEP_NAME_RE.match(lines[k])
            if sm:
                steps.append(sm.group(1))
            k += 1
        runs = [RUN_RE.match(x).group(1) for x in lines[i:k] if RUN_RE.match(x)]
        has_mutation = any(h in r for r in runs for h in MUTATION_HINTS)
        jobs.append({
            "name": name,
            "why": " ".join(why),
            "steps": steps,
            "runs": runs,
            "mutation": has_mutation,
        })
    return jobs


def _first_sentence(text, limit=110):
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "（无注释——需补：这个门禁守什么）"
    # 以中文句号/分号/英文句点切第一句
    for sep in ("。", "；", ";"):
        if sep in text:
            text = text.split(sep)[0]
            break
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text


def render(jobs):
    out = []
    out.append("# GATES · 门禁地图（自动派生，勿手改）")
    out.append("")
    out.append("> **真源**：`.github/workflows/ci.yml`。本文件由 `scripts/gen_gates_map.py` 生成，")
    out.append("> 手改会在 `agent-docs-gate` 里被判红。改门禁 → 改 ci.yml 注释 → 重跑 `--write`。")
    out.append(">")
    out.append("> 每行的\"守什么\"取自该 job 上方的注释首句；**没有注释的 job 会显示为待补**——")
    out.append("> 那本身就是缺陷：一个说不出自己守什么的门禁，无法判断它是否失效。")
    out.append("")
    out.append("共 **%d** 个 job（其中 **%d** 个带自测/变异验证）。"
               % (len(jobs), sum(1 for x in jobs if x["mutation"])))
    out.append("")
    out.append("| job | 守什么 | 步骤数 | 变异/自测 |")
    out.append("|---|---|---|---|")
    for x in jobs:
        out.append("| `%s` | %s | %d | %s |"
                   % (x["name"], _first_sentence(x["why"]).replace("|", "\\|"),
                      len(x["steps"]), "有" if x["mutation"] else "**无**"))
    out.append("")
    out.append("## 已知盲区（人工维护，不由 ci.yml 派生）")
    out.append("")
    out.append("> 这一节是唯一手写部分：**门禁守不到的地方**。新增门禁时如发现盲区，写在这里；")
    out.append("> 盲区被补上后，把该条删掉（不留\"已修复\"历史，历史在 git 里）。")
    out.append("")
    blind = [
        "`check_material_numbers.py` 的覆盖数为 0 时才 fail-closed；**部分覆盖下降不报警**"
        "（例如材料从 docs/ 顶层挪进子目录而扫描 glob 未跟进）。",
        "工具数存在两套口径（`tools_yaml` 文件计数 91 / `tools_declared` 真实工具 90）。"
        "2026-10-24 起由 `count_stats.py` 的不变量硬拦（91 == 90 + 1），但**材料仍可只写 91**"
        "而不解释 +1 是谁——文字层无法机验。",
        "`docs/` 顶层文档数量**只受\"不得增加\"约束**（见 `check_agent_docs.py` C5），"
        "存量 43 份尚未归档；历史快照与当前权威混在同一层，靠 `docs/INDEX.md` 标注区分。",
        "门禁地图只证明\"每个 job 有注释\"，**不证明该 job 真能变红**；只有标\"有\"的 job "
        "才做了变异验证，标\"无\"的 12 个 job 是否有效属未验证。",
    ]
    for b in blind:
        out.append("- %s" % b)
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(CI):
        print("[ERROR] 找不到 %s" % CI, file=sys.stderr)
        return 2
    text = render(parse(CI))

    if args.write:
        with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("已写入 %s" % os.path.relpath(OUT, ROOT))
        return 0
    if args.check:
        if not os.path.isfile(OUT):
            print("[FAIL] docs/GATES.md 不存在，先跑 --write", file=sys.stderr)
            return 1
        with open(OUT, encoding="utf-8") as fh:
            cur = fh.read()
        if cur != text:
            print("[FAIL] docs/GATES.md 与 ci.yml 不一致（门禁地图已过期），"
                  "重跑 python scripts/gen_gates_map.py --write", file=sys.stderr)
            return 1
        print("[PASS] 门禁地图与 ci.yml 一致")
        return 0

    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
