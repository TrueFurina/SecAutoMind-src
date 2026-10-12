#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地复刻 CI 门禁 —— CI 不可用时的唯一安全网。

为什么需要它
------------
2026-09-30 起本仓 GitHub Actions 因**账号计费**被拦：11 个 job 全部 `steps=0`
秒失败，注解原文 "The job was not started because recent account payments have
failed or your spending limit needs to be increased"。恢复前，"改完必验"只能靠本地。

但**手工抄一遍 CI 命令是错的**：抄的时候会漏、之后会过时，而"本地绿"会被当成
"CI 会绿"的依据。所以本脚本**直接从 `.github/workflows/ci.yml` 解析 `run:` 行**，
不维护第二份命令清单 —— 命令清单只有一处真值源，永不漂移。

用法：
    python scripts/local_gate_check.py                 # 跑全部 python 门禁
    python scripts/local_gate_check.py --list          # 只列不跑
    python scripts/local_gate_check.py --only caliber-gate
    python scripts/local_gate_check.py --full          # 连 data/ 下的重基准一起跑
退出码：0 = 全绿；1 = 有失败；2 = 解析不出命令（fail-closed）

注意（**不静默跳过**）：go / pip / linux-only 步骤会被明确列出并标注跳过原因，
它们的结果仍需以 CI 为准。本脚本只回答"python 侧门禁是否全绿"。
"""
import argparse
import os
import re
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CI = os.path.join(ROOT, ".github", "workflows", "ci.yml")

# 这些步骤会改仓库状态或非常慢，默认不跑（--full 才跑）
HEAVY = ("regen_exec_fixtures.py", "run_all_benchmarks.py")


def parse_ci():
    """从 ci.yml 解析 [(job, step_name, command)]，顺序即文件顺序。

    ⚠️ 多行 run（YAML 块标量 `run: |` / `run: >`）必须**显式收集**：
    只取 `run:` 那一行，拿到的是字面量 "|"，而 classify 会把它归为"非 python 命令"
    静默跳过。于是哪天有人把一条 python 门禁改写成多行脚本，本地复刻就会**悄悄漏掉它** ——
    "本地 17/17 全绿"不再等于"CI 会绿"，安全网本身就失效了（fail-open）。
    这里把块内容拼成一条 [BLOCK] 记录交给 classify 显式处置。
    """
    if not os.path.isfile(CI):
        raise SystemExit("[FAIL-CLOSED] 找不到 %s" % CI)
    with open(CI, "r", encoding="utf-8", errors="ignore") as fh:
        lines = [ln.rstrip("\n") for ln in fh]

    job, step, out, i = None, None, [], 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m and not line.startswith("    "):
            job = m.group(1)
            i += 1
            continue
        m = re.match(r"^\s+-\s+name:\s*(.+?)\s*$", line)
        if m:
            step = m.group(1).strip().strip('"\'')
            i += 1
            continue
        # 块标量：run: | / run: > / run: |- 等（冒号后只有标量指示符）
        m = re.match(r"^(\s+)run:\s*[|>][-+]?\s*$", line)
        if m:
            base = len(m.group(1))
            block, j = [], i + 1
            while j < len(lines):
                nxt = lines[j]
                if nxt.strip() == "":
                    block.append("")
                    j += 1
                    continue
                if len(nxt) - len(nxt.lstrip()) <= base:
                    break
                block.append(nxt.strip())
                j += 1
            out.append((job, step or "(unnamed)",
                        "[BLOCK] " + " ; ".join(x for x in block if x.strip())))
            i = j
            continue
        m = re.match(r"^\s+run:\s*(.+?)\s*$", line)
        if m:
            out.append((job, step or "(unnamed)", m.group(1).strip().strip('"\'')))
        i += 1
    return out


def classify(cmd):
    """-> ('python'|'heavy'|'skip', 原因)

    跳过一律**带原因**（不静默）：本脚本的结论只覆盖它真的跑过的那些命令。
    """
    # 多行 run 块（见 parse_ci）：解析器不拆 shell 语法，但**必须**把藏在块里的
    # python 门禁显式点出来 —— 否则它会被"非 python 命令"这条兜底规则静默吞掉，
    # 而"本地全绿"就会变成一个假信号。
    if cmd.startswith("[BLOCK] "):
        inner = cmd[len("[BLOCK] "):]
        py_calls = sorted(set(re.findall(r"\bpython3?\s+(\S+\.py)", inner)))
        if py_calls:
            return "skip", ("⚠️ 多行 run 内含 python 门禁 %s —— 解析器不自动拆分，请人工复刻"
                            % ", ".join(py_calls[:3]))
        return "skip", "多行 shell 脚本（%s）" % (inner[:70] + ("…" if len(inner) > 70 else ""))
    # 含 ${{ }} 的步骤只在 PR/特定事件下有意义，本地跑会把表达式当字面量传进去，
    # 跑出来的结果没有意义 —— 宁可不跑，也不要拿一个"假装跑过"的红/绿。
    if "${{" in cmd:
        return "skip", "含 GitHub 表达式（${{ }}），仅特定事件触发，本地无法等价复现"
    if "pip install" in cmd or cmd.startswith("python -m pip"):
        return "skip", "依赖安装步骤（本机已具备）"
    if "apt-get" in cmd:
        return "skip", "Linux 系统依赖安装（本机非 Linux）"
    if re.search(r"(^|\s)go\s", cmd):
        return "skip", 'go 步骤：本机需先 export APPDATA="$USERPROFILE/AppData/Roaming"（见 MEMORY §5）'
    if cmd.startswith(("bash ", "./", "sh ")):
        return "skip", "shell 步骤"
    if not cmd.startswith("python "):
        return "skip", "非 python 命令"
    if any(h in cmd for h in HEAVY):
        return "heavy", "会改仓库状态/耗时（--full 才跑）"
    return "python", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", default=None, help="只跑某个 job")
    ap.add_argument("--full", action="store_true", help="连 heavy 步骤一起跑")
    args = ap.parse_args()

    steps = parse_ci()
    if not steps:
        raise SystemExit("[FAIL-CLOSED] ci.yml 未解析出任何 run: 步骤（格式可能已改）")

    selected, skipped = [], []
    for job, name, cmd in steps:
        if args.only and job != args.only:
            continue
        kind, why = classify(cmd)
        if kind == "skip" or (kind == "heavy" and not args.full):
            skipped.append((job, name, cmd, why))
        else:
            selected.append((job, name, cmd))

    jobs = sorted({j for j, _, _ in steps})
    print("=" * 78)
    print("本地复刻 CI 门禁 · 命令来源 .github/workflows/ci.yml（%d 个 job）" % len(jobs))
    print("=" * 78)

    if args.list:
        for job, name, cmd in selected:
            print("  [RUN ] %-20s %s" % (job, cmd))
        for job, name, cmd, why in skipped:
            print("  [SKIP] %-20s %s   <- %s" % (job, cmd, why))
        return 0

    rows = []
    for job, name, cmd in selected:
        t0 = time.time()
        p = subprocess.run(cmd, cwd=ROOT, shell=True, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=1800)
        dt = time.time() - t0
        rows.append((job, cmd, p.returncode, dt))
        print("  %-4s %-22s %-56s %s (%.1fs)"
              % ("OK" if p.returncode == 0 else "FAIL", job, cmd, p.returncode, dt), flush=True)

    print("-" * 78)
    for job, name, cmd, why in skipped:
        print("  [SKIP] %-22s %-56s %s" % (job, cmd, why))

    bad = [r for r in rows if r[2] != 0]
    print("=" * 78)
    print("python 侧：跑 %d 条，失败 %d 条，跳过 %d 条" % (len(rows), len(bad), len(skipped)))
    if bad:
        for job, cmd, rc, _ in bad:
            print("  *** FAIL %s  rc=%d" % (cmd, rc))
    print("结论：%s" % ("全部通过 ✅（go 步骤仍需以 CI 为准）" if not bad else "有失败 ❌"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
