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
        "供应链门禁只保证 SBOM 与依赖树一致 + go.sum 覆盖，**不做 CVE 扫描**（离线无本地库，"
        "任何\"漏洞数=0\"都是假的）；`requirements.txt` 仍是 `>=` 浮动范围、无 lockfile，"
        "装到什么版本取决于当天 PyPI —— 这一条只有 G-02 的一半。",
        "2026-11-10 补：`check_docs_lint.py` 的 scripts 引用判据是**存在性**校验，"
        "而\"存在 ≠ 可用\"——根目录 `scripts/_audit_corpus_integrity_test.py` 是"
        "`7bf8ce3` 恢复入库的**已作废存根**（文件头自标\"请勿在此路径新增测试\"、0 用例），"
        "文档引用它照样过 lint，但读者按图索骥跑不到任何测试。现状无机验能区分"
        "\"活文件\"与\"作废存根\"（要判就得解析内容/计数用例，跨入语义分析）。"
        "本条由一次**错误归因**逼出：先前记成\"lint 漏检\"，复核后发现判据没错、"
        "错在对\"存在\"的解读（见 docs/收尾清单.md 2026-11-10 自我更正条）。",
        # 2026-11-09 补：secret_guard 的外形判据是自己量过盲区才写进来的，不是"觉得应该写"。
        "`secret_guard.py` 的明文**外形**判据（`FLAG_CAND_RE`）有四处明示盲区：正文含空格、"
        "含冒号/分号、前缀只有 1 个字符、正文短于 4。答案**在题库里**时不受影响"
        "（`check_redaction_consistency.py` 的已知哈希通道不看外形）；残余风险是"
        "「**尚未进题库**的新答案恰好长成这四种样子」，此时全仓没有任何判据看得见它。"
        "2026-11-09 实测（提交态 87a34c2 前后、4200+ 已跟踪文件）：现状对仓内真实存在的答案明文"
        "覆盖率 **100%（41 个豁免文件，0 处看不见）**；放宽到「放行空格」已跟踪命中 "
        "2087→2409（+322 处），再放行冒号分号→3514（+1427 处，增量绝大多数是 Go 结构体字面量）；"
        "收紧 body 下限 4→8 则 2087→1493（-594 处），而丢掉的部分里 **26 处哈希命中题库真值**。"
        "⚠️ 这些绝对处数**会随题库与工作树增长而漂**（前一日读数 2077 / 123 处，今日 2087 / 125 处），"
        "所以覆盖率断言只钉**不变量**（0 处看不见 + 至少捞到 1 处），不写死处数；"
        "趋势（放宽=误报洪水、收紧=丢真答案）不随树变。"
        "结论：现状是这条判据的最优点，**不放宽也不收紧**；两端由 "
        "`scripts/secret_guard_flag_test.py` 的 `TestShapeBlindSpotLocked` 钉死"
        "（谁要改，先重测上面这组数字并同步本节）。",
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
