#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""HITL 失效边界实证（规划 §4.2）—— 可复现实验脚本。

背景：HITL 是赛题「决策逻辑与可解释性」评分维的直接回应，也是 9-12 标记的
「唯一真正可随机化的子研究」。§4.2 要求做失效边界实证，产出
`docs/hitl_failure_boundary.md` + 可复现实验脚本。

**本脚本的诚实边界（务必先读）**：
  §4.2 原文的失效模式矩阵含多类，其中 false-approve / false-block 依赖
  **≥8 名外部导师的 randomized 评测**——这不是脚本能替代的。因此本脚本把模式分为三档：

    machine  确定性失效模式：用 Go 测试真跑，逐条判定 PASS/FAIL；
    human    需真人在环随机化评测：脚本只声明阈值与夹具，标 **OPEN**，不伪造数据；
    n/a      本项目不存在该机制，如实标 **不适用**（不硬凑满分）。

  任何把 human 档改写成 PASS 的行为都是造假；脚本结构上禁止这么做。

  每个 machine 模式可含多个 spec（不同包的主路径 / 桥接路径），全部 spec 通过才算该模式 PASS。

用法:
    python scripts/run_hitl_boundary.py            # 真跑 machine 档 + 写声明文档
    python scripts/run_hitl_boundary.py --check    # 只真跑 machine 档，不写文件（CI 用）
    python scripts/run_hitl_boundary.py --list     # 只列模式矩阵，不跑测试
"""

from __future__ import annotations

import argparse
import datetime
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DECL = REPO / "docs" / "hitl_failure_boundary.md"

PASS, FAIL, OPEN, NA = "PASS", "FAIL", "OPEN", "N/A"


def spec(pkg: str, tests: list[str]) -> dict:
    return dict(pkg=pkg, tests=tests)


# ---------------------------------------------------------------------------
# 失效模式矩阵
#   machine：由 Go 测试锁死（含 handler 主路径 + app 的 C2 桥接路径）。
#   human  ：需外部导师随机化评测，脚本只声明阈值，结果标 OPEN。
#   n/a    ：本项目不存在该机制。
# ---------------------------------------------------------------------------
MACHINE_MODES = [
    dict(
        id="timeout_hang", name="审批超时挂死",
        mechanism="审批未在超时窗口内到达 → 自动拒绝（fail-safe），并留审计痕迹",
        code="hitl.go waitDecision 超时分支 / c2_hitl_bridge.go deadline 分支",
        specs=[
            spec("./internal/handler/", ["TestHITLWaitDecision_TimeoutAutoRejects"]),
            spec("./internal/app/", ["TestC2HITLBridge_TimeoutAutoRejects"]),
        ],
        mutation="超时分支 reject→approve 后 handler 侧测试 FAIL（已实测）",
    ),
    dict(
        id="persist_failure", name="决策落库失败",
        mechanism="审批/超时/取消任一分支落库失败 → fail-closed（拒绝放行 + 上报错误）",
        code="hitl.go waitDecision / c2_hitl_bridge.go RequestApproval",
        specs=[
            spec("./internal/handler/", [
                "TestHITLWaitDecisionFailsClosedOnPersistError_Decided",
                "TestHITLWaitDecisionFailsClosedOnPersistError_Timeout",
                "TestHITLWaitDecisionFailsClosedOnPersistError_Cancelled",
                "TestHITLWaitDecisionPassesWhenPersisted",
            ]),
            spec("./internal/app/", ["TestC2HITLBridge_FailsClosedWhenPersistFails"]),
        ],
        mutation="未单独变异（含反向对照 PassesWhenPersisted 防误修为一律拒绝）",
    ),
    dict(
        id="override_conflict", name="覆盖冲突（重复裁决 / 双击 / 并发）",
        mechanism="first-writer-wins：后到的裁决必须被拒，首个决策不得被翻盘",
        code="hitl.go ResolveInterrupt（非阻塞 channel send + pending 映射）",
        specs=[
            spec("./internal/handler/", [
                "TestHITLResolveInterrupt_RejectsSecondDecision",
                "TestHITLResolveInterrupt_RejectsAfterResolved",
            ]),
        ],
        mutation="决策通道缓冲 1→2 后 RejectsSecondDecision FAIL（已实测）",
    ),
    dict(
        id="out_of_bounds", name="越界裁决",
        mechanism="不存在的中断 / 非法决策值 → 明确报错，不得静默接受",
        code="hitl.go ResolveInterrupt（决策值校验 + pending 存在性校验）",
        specs=[
            spec("./internal/handler/", [
                "TestHITLResolveInterrupt_RejectsUnknownInterrupt",
                "TestHITLResolveInterrupt_RejectsInvalidDecision",
            ]),
        ],
        mutation="未单独变异（直接断言守卫返回值，含合法值反向对照）",
    ),
    dict(
        id="param_tampering", name="参数篡改（审批被偷换为改参放行）",
        mechanism="非 review_edit 模式必须剥离 editedArguments",
        code="hitl.go waitDecision（p.Mode != review_edit → EditedArguments=nil）",
        specs=[
            spec("./internal/handler/", [
                "TestHITLWaitDecision_StripsEditedArgsOutsideReviewEdit",
                "TestHITLWaitDecision_KeepsEditedArgsInReviewEdit",
            ]),
        ],
        mutation="删除剥离语句后 StripsEditedArgs FAIL、Peer(review_edit) 仍 PASS（已实测）",
    ),
]

HUMAN_MODES = [
    dict(id="false_approve", name="人工误批（放行本应拦截的高危操作）",
         threshold="false-approve 率 < X%（阈值待 MPU-2 定）",
         fixture="≥8 名外部导师（跨校随机招募）对同一批高危/安全请求做 blinded 裁决，"
                 "统计「高危被判放行」占比"),
    dict(id="false_block", name="人工误拒（阻断本应放行的安全操作）",
         threshold="false-block 率 < Y%（阈值待 MPU-2 定）",
         fixture="同上批次，统计「安全操作被判拒绝」占比（过阻会反噬可用性）"),
]

NA_MODES = [
    dict(id="consensus_split", name="多 agent 共识分裂",
         reason="本项目多 agent 为「规划/执行/审计/复盘」流水线编排，**非投票集成**，"
                "不存在可分裂的多数表决 → 该失效模式不适用（不硬凑模式）。"),
]


def run_go_tests(pkg: str, tests: list[str]) -> tuple[bool, str]:
    pattern = "^(" + "|".join(tests) + ")$"
    cmd = ["go", "test", pkg, "-run", pattern, "-count=1", "-v"]
    p = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (p.stdout or "") + (p.stderr or "")
    ok = (p.returncode == 0) and ("FAIL" not in out)
    return ok, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只真跑 machine 档，不写文件（CI）")
    ap.add_argument("--list", action="store_true", help="只列模式矩阵")
    args = ap.parse_args()

    if args.list:
        print("== 确定性（machine）==")
        for m in MACHINE_MODES:
            print("  - %-18s %s" % (m["id"], m["name"]))
        print("== 需真人评测（human）==")
        for m in HUMAN_MODES:
            print("  - %-18s %s" % (m["id"], m["name"]))
        print("== 不适用（n/a）==")
        for m in NA_MODES:
            print("  - %-18s %s" % (m["id"], m["name"]))
        return 0

    results = []
    fails = []
    print("=== HITL 失效边界实证（规划 §4.2）===")
    for m in MACHINE_MODES:
        ok_all = True
        tails = []
        for sp in m["specs"]:
            ok, out = run_go_tests(sp["pkg"], sp["tests"])
            ok_all = ok_all and ok
            if not ok:
                tails.append("%s: %s" % (sp["pkg"], " | ".join(out.strip().splitlines()[-3:])))
        status = PASS if ok_all else FAIL
        if not ok_all:
            fails.append(m["id"])
        results.append((m, status, " || ".join(tails)))
        print("  [%-4s] %-16s %s" % (status, m["id"], m["name"]))

    print("  [%-4s] %-16s (需外部导师 randomized 评测，本脚本不伪造数据)"
          % (OPEN, "false_approve/false_block"))
    print("  [%-4s] %-16s (本项目无投票集成)" % (NA, "consensus_split"))

    overall = "FAIL" if fails else "PASS(machine) + OPEN(human)"
    print("\n结论：%s" % overall)
    if fails:
        print("未通过：%s" % ", ".join(fails))

    if args.check:
        return 1 if fails else 0

    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "# HITL 失效边界报告（规划 §4.2）",
        "",
        "> 本文件由 `scripts/run_hitl_boundary.py` 生成（**勿手改**；改模式/测试请改脚本后重跑）。",
        "> 生成时间：%s ｜ 结论：**%s**" % (stamp, overall),
        "",
        "## 0. 为什么这份报告分三档而不是「全绿」",
        "",
        "§4.2 的施工动机是「HITL 失效边界未实证」。但『失效边界』里有一半（人工误批/误拒）",
        "**本质上需要真人在环的 randomized 评测**，代码测试替代不了。若把这几项也标 PASS，",
        "就是把『没测』伪装成『测过』——这正是本项目最忌的失信形态。故按可验证性分三档，",
        "**machine 档逐条真跑，human 档如实标 OPEN，n/a 档如实标不适用**。",
        "",
        "## 1. 失效模式矩阵",
        "",
        "| 模式 | 类型 | 机制 | 机验/评审证据 |",
        "|---|---|---|---|",
    ]
    for m, status, _ in results:
        alltests = " / ".join(t for sp in m["specs"] for t in sp["tests"])
        lines.append("| %s | `machine`(`%s`) | %s | `%s` |" % (m["name"], status, m["mechanism"], alltests))
    for m in HUMAN_MODES:
        lines.append("| %s | `human`(`%s`) | 需真人在环随机化评测 | %s |"
                     % (m["name"], OPEN, m["threshold"]))
    for m in NA_MODES:
        lines.append("| %s | `n/a`(%s) | %s | — |" % (m["name"], NA, m["reason"]))

    lines += [
        "",
        "## 2. machine 档逐条结果",
        "",
        "| id | 模式 | 结论 | 证据（测试） | 变异验证 |",
        "|---|---|---|---|---|",
    ]
    for m, status, _ in results:
        alltests = " / ".join(t for sp in m["specs"] for t in sp["tests"])
        lines.append("| `%s` | %s | **%s** | `%s` | %s |"
                     % (m["id"], m["name"], status, alltests, m["mutation"]))
    lines += [
        "",
        "> 主路径在 `internal/handler`（waitDecision / ResolveInterrupt）；危险任务 C2 桥接路径在",
        "> `internal/app`（c2_hitl_bridge.go）—— 两路径均已在 `timeout_hang` / `persist_failure` 模式加锁。",
    ]
    if fails:
        lines += ["", "🔴 本次存在未通过项：%s（详见运行输出）" % ", ".join(fails)]

    lines += [
        "",
        "## 3. human 档（OPEN，阈值待定）",
        "",
        "以下两项**未闭环**，需按 §4.2 招募 ≥8 名外部导师做 randomized 评测后回填：",
        "",
    ]
    for m in HUMAN_MODES:
        lines += ["- **%s**（`%s`）" % (m["name"], m["id"]),
                  "  - 阈值：%s" % m["threshold"],
                  "  - 夹具：%s" % m["fixture"]]
    lines += [
        "",
        "> 阈值 X/Y 由 MPU-2 依「安全优先但不至于过阻」的判据确定；本报告**不预设**，",
        "> 以免出现「先射箭后画靶」。",
        "",
        "## 4. n/a 档（如实记录，不硬凑）",
        "",
    ]
    for m in NA_MODES:
        lines += ["- **%s**（`%s`）：%s" % (m["name"], m["id"], m["reason"])]

    lines += [
        "",
        "## 5. 覆盖边界（不夸大）",
        "",
        "- machine 档覆盖 HITL **主路径**（`internal/handler` 的 waitDecision / ResolveInterrupt）",
        "  与**危险任务 C2 桥接路径**（`internal/app` 的 c2_hitl_bridge.go RequestApproval）。",
        "- **未覆盖**：真机/真导师条件下的 false-approve / false-block 率（见 §3，OPEN）。",
        "- 复现命令：`python scripts/run_hitl_boundary.py`（本地）｜ `--check`（CI，只跑 machine 档）。",
        "",
    ]
    DECL.parent.mkdir(parents=True, exist_ok=True)
    DECL.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("报告已写入: %s" % DECL)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
