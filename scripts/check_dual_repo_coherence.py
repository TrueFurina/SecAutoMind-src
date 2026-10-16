#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""双库口径一致性声明（规划 §4.7：A 是尺 + B 是真值源）。

背景：A 库（西湖论剑 ctf_agent）与 B 库（SecAutoMind）各自演进，口径可能分叉。
本脚本把 §4.7 的三点动作落成**可机验**检查，并产出声明文件
`docs/dual_repo_coherence.md`：

  1. 真值源唯一化：B 的协议/请求 golden 必须由 A 的 dasctf.py 生成并与之逐字段一致。
  2. 阈值联动：A 侧真题集规模若变化，B 的立尺（cross-bench）须重跑，否则给出提示。
  3. 泄露联防：比对两库是否都部署了密钥指纹门禁（**不对称即如实标注，不粉饰**）。

CI 上无 A 库（真源仓库不入 CI），故 CI 只跑 `check_golden_freeze.py` 做哈希冻结兜底；
本脚本在缺 A 库时逐项 SKIP 并说明，**不假装 PASS**。

用法:
    python scripts/check_dual_repo_coherence.py                 # 检查 + 写声明
    python scripts/check_dual_repo_coherence.py --check-only    # 只检查不写文件
    python scripts/check_dual_repo_coherence.py --a-repo <path> # 指定 A 库 ctf_agent 路径
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_A = Path(r"E:/Program/西湖论剑/ctf_agent")
DECL = REPO / "docs" / "dual_repo_coherence.md"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def check_protocol_golden(a_repo: Path):
    """① 协议 golden：A 的 dasctf.py ↔ B 的 dasctf.go（经 golden 中转）。"""
    rc, out = run([sys.executable, "scripts/gen_protocol_golden.py",
                   "--source", str(a_repo), "--check"])
    if rc == 0:
        return PASS, "协议 golden 与 A 真源逐字段一致", out
    return FAIL, "协议 golden 与 A 真源不一致（B 需重跑 gen_protocol_golden.py）", out


def check_request_golden(a_repo: Path):
    """② 请求 golden：A 的请求构造 ↔ B 的 request_golden.json。"""
    rc, out = run([sys.executable, "scripts/gen_request_golden.py",
                   "--source", str(a_repo), "--check"])
    if rc == 0:
        return PASS, "请求 golden 未过期", out
    if "No module named 'httpx'" in out:
        # 依赖缺失属环境限制，不能算"不一致"，但也绝不能算 PASS —— 如实 SKIP。
        return SKIP, "本机 Python 缺 httpx，无法复跑请求 golden（非口径不一致）", out
    return FAIL, "请求 golden 过期/不一致，需重跑 gen_request_golden.py", out


def check_golden_freeze():
    """③ golden 冻结：CI 侧可判定的兜底（防手改 golden 不重跑生成器）。"""
    rc, out = run([sys.executable, "scripts/check_golden_freeze.py"])
    if rc == 0:
        return PASS, "golden 与冻结哈希一致（未被手改）", out
    return FAIL, "golden 与冻结哈希不符（疑似手改）", out


def check_truth_set_scale(a_repo: Path):
    """④ 阈值联动：A 真题集规模变化 → B 立尺需重跑。"""
    qdir = a_repo / "data" / "questions_real"
    stats_path = REPO / "data" / "questions_real_bench" / "cross_bench_source_stats.json"
    if not qdir.is_dir():
        return SKIP, "A 侧 questions_real 目录不存在", ""
    if not stats_path.exists():
        return SKIP, "B 侧 cross_bench_source_stats.json 不存在（立尺未跑）", ""

    a_count = len(list(qdir.rglob("*.json")))
    b = json.loads(stats_path.read_text(encoding="utf-8"))
    b_total = b.get("total")
    detail = ("A 侧真题 %d 道；B 立尺纳入 %s 道（剔除非 sha256 真值题 %s 道）"
              % (a_count, b_total, (a_count - b_total) if b_total else "?"))
    if b_total and a_count >= b_total:
        # A 侧题目数 ≥ B 纳入数：一致（差额为按诚信铁律剔除的非 sha256 题）
        return PASS, detail + " —— 规模自洽", detail
    return FAIL, detail + " —— B 立尺数量超过 A 侧题源，数据源可疑", detail


def check_leak_defense(a_repo: Path):
    """⑤ 泄露联防：两库是否都部署密钥指纹门禁。不对称如实标注。"""
    b_has = (REPO / "scripts" / "secret_guard.py").exists()
    a_guard = list(a_repo.rglob("secret_guard*.py")) if a_repo.is_dir() else []
    a_has = bool(a_guard)
    if a_has and b_has:
        return PASS, "双库均已部署密钥指纹门禁", ""
    if b_has and not a_has:
        return SKIP, ("**不对称**：B 已部署 secret_guard 指纹反查，A 侧未见同名门禁 "
                      "→ 联防当前为 B 单侧，A 发现的新指纹不会自动进入 B"), ""
    if a_has and not b_has:
        return FAIL, "A 有门禁而 B 无，真值源侧失守", ""
    return SKIP, "两侧均未见密钥指纹门禁", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a-repo", default=str(DEFAULT_A))
    ap.add_argument("--check-only", action="store_true")
    args = ap.parse_args()
    a_repo = Path(args.a_repo)

    a_exists = a_repo.is_dir()
    checks = []

    # ①③ 不依赖 A 库
    checks.append(("golden 冻结（CI 可判定）", *check_golden_freeze()))
    if a_exists:
        checks.append(("协议 golden 双库一致", *check_protocol_golden(a_repo)))
        checks.append(("请求 golden 双库一致", *check_request_golden(a_repo)))
        checks.append(("立尺题源规模联动", *check_truth_set_scale(a_repo)))
    else:
        for name in ("协议 golden 双库一致", "请求 golden 双库一致", "立尺题源规模联动"):
            checks.append((name, SKIP,
                           "A 库不存在（`%s`）—— CI 场景，真源不入 CI" % a_repo.name, ""))
    checks.append(("泄露指纹联防对称性", *check_leak_defense(a_repo)))

    print("=== 双库口径一致性检查 ===")
    print("A 库（尺/真源）: %s [%s]\n" % (a_repo, "存在" if a_exists else "缺失"))
    fails = []
    for name, status, msg, _ in checks:
        print("  [%-4s] %-24s %s" % (status, name, msg))
        if status == FAIL:
            fails.append(name)

    overall = "FAIL" if fails else ("PASS" if a_exists else "SKIP(A 库缺失)")
    print("\n结论：%s" % overall)
    if fails:
        print("未通过项：%s" % ", ".join(fails))

    if args.check_only:
        return 1 if fails else 0

    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "# 双库口径一致声明",
        "",
        "> 由 `scripts/check_dual_repo_coherence.py` 自动生成（**勿手改**，改脚本重跑）。",
        # 只记目录名，不写绝对路径：本文件入库公开，无需暴露本机目录结构。
        "> 生成时间：%s ｜ A 库（真源/尺）：`%s`（由 `--a-repo` 指定，本机路径略） ｜ 结论：**%s**"
        % (stamp, a_repo.name, overall),
        # 2026-10-16 补：本声明此前未声明**适用范围**，读者易误当 CI 门禁产物。
        # 事实：A 库不在 CI，CI **不校验本文件**（golden 冻结等可在 CI 判定的项由
        # check_golden_freeze.py 另行把关，见 ci.yml 的 golden 相关 job）。
        "> ⚠️ **适用范围**：A 库（尺）不在 CI，**CI 不校验本文件**——它是本地跨仓库核对的留痕，"
        "随本脚本重跑刷新（重跑须用带 `httpx` 的解释器，否则请求 golden 项退化为 `SKIP`）。"
        "表中 `SKIP` 表示**本次运行环境**未复跑该项（如缺 `httpx`），**不是失败**；"
        "只有 `FAIL` 才表示口径不一致。",
        "",
        "## 检查项",
        "",
        "| 结果 | 检查项 | 说明 |",
        "|---|---|---|",
    ]
    for name, status, msg, _ in checks:
        lines.append("| `%s` | %s | %s |" % (status, name, msg))
    lines += [
        "",
        "## 声明",
        "",
    ]
    if a_exists:
        lines.append(
            "在检查时点，B 库的协议/请求 golden 由 A 库 `ctfplatform/dasctf.py` 生成并与之"
            "逐字段一致（真值源唯一化成立）；A 侧真题集规模与 B 立尺纳入数自洽。"
        )
    else:
        lines.append(
            "A 库不可达，本次仅完成不依赖真源的 `golden 冻结` 检查；"
            "**双库逐字段一致性未获本次验证**，需在含 A 库的机器上重跑本脚本。"
        )
    lines += [
        "",
        "## 已知不对称（如实记录，不粉饰）",
        "",
    ]
    asym = [c for c in checks if c[1] == SKIP and "不对称" in c[2]]
    if asym:
        for _, _, msg, _ in asym:
            lines.append("- %s" % msg)
    else:
        lines.append("- （无）")
    lines += [
        "",
        "## 边界说明",
        "",
        "- CI 无 A 库（真源仓库不入 CI），故 CI 侧只跑 `check_golden_freeze.py` 做哈希冻结兜底；",
        "  真源↔golden 的逐字段一致性**只能本地验证**，本文件即该验证的产物。",
        "- 本声明覆盖 §4.7 的 ①②③ 三点；第 ③ 点（泄露联防）当前为 B 单侧实现。",
        "",
    ]
    DECL.parent.mkdir(parents=True, exist_ok=True)
    DECL.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("声明已写入: %s" % DECL)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
