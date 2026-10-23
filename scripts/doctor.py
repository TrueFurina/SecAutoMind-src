#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""doctor.py — SecAutoMind 一键健康自检（只读聚合，不新增门禁语义）

用法:
    python scripts/doctor.py            # 快速档（真值源 + 门禁在位 + 仓库卫生，秒级）
    python scripts/doctor.py --full     # 追加 go build ./...（分钟级，需 go 工具链）
    python scripts/doctor.py --json     # 机器可读输出
    python scripts/doctor.py --strict   # unknown 计失败

设计纪律（来自 REA 调研最佳实践映射，2026-10-19）:
    1. 只读：不写、不改、不删任何文件；
    2. 证据分级：每条结果带 observed（直接测得）/ derived（推导）/ unknown（未能确认），
       unknown 显式输出，不静默省略；
    3. fail-closed：退出码 0 = 全部通过，1 = 存在 FAIL（--strict 下 unknown 也计失败）；
    4. 聚合而非重造：调用既有真值源（count_stats.py）与门禁脚本，不复制其逻辑。

数字唯一真值源 = scripts/count_stats.py（AGENTS.md 铁律）；本脚本只核对不裁决。
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FULL = "--full" in sys.argv
JSON_MODE = "--json" in sys.argv
STRICT = "--strict" in sys.argv

results = []  # (name, status, level, detail)；status ∈ PASS/FAIL/WARN(unknown)


def record(name, ok, level, detail=""):
    status = "PASS" if ok is True else "FAIL" if ok is False else "WARN"
    results.append({"name": name, "status": status, "level": level, "detail": detail})


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", **kw)


def _git_head() -> str:
    """执行基线：pin 仓库 HEAD，供 CI 归因与历史对比（REA #134）。失败不炸，记 unknown。"""
    try:
        r = run(["git", "rev-parse", "HEAD"])
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    except OSError:
        return "unknown"


# ---------- 1. 真值源（count_stats.py） ----------
def check_truth_source():
    r = run([sys.executable, "-X", "utf8", "scripts/count_stats.py", "--json"])
    if r.returncode != 0:
        record("count_stats 真值源可运行", False, "observed", f"退出码 {r.returncode}: {(r.stderr or r.stdout)[:200]}")
        return None
    try:
        # count_stats 的 [WARN] 行混在 stdout，截取首个 '{' 起解析
        data = json.loads(r.stdout[r.stdout.index("{"):])
    except Exception as e:  # noqa: BLE001
        record("count_stats 输出可解析", False, "observed", str(e))
        return None

    builtin = data.get("builtin_tools")
    yaml_n = data.get("tools_yaml")
    runtime = data.get("runtime_tools")
    record(f"内置工具数 = {builtin}（期望 52）", builtin == 52, "observed",
           "" if builtin == 52 else "constants.go 的 GetAllBuiltinTools 数量已变，需同步 AGENTS.md 与分级方案")
    record(f"YAML 工具数 = {yaml_n}，运行时合计 = {runtime}（期望 90 + 52 = 142）",
           yaml_n == 90 and runtime == 142, "observed",
           "" if (yaml_n == 90 and runtime == 142) else "AGENTS.md 记 91/143，以 count_stats 实测为准")

    if data.get("go_packages") is None:
        record("go_packages 统计", None, "unknown",
               "go 可执行文件缺失（count_stats [WARN]）——Go 包口径未确认，非内容问题；装 go 或忽略")
    head = data.get("head", "?")
    exe = data.get("exe") or {}
    record(f"HEAD = {head}，exe = v{exe.get('mod_version', '?').lstrip('v')}", True, "observed",
           f"exe md5={exe.get('md5', '?')} size={exe.get('size_mb', '?')}MB")
    return data


# ---------- 2. 内置工具数独立复核（不信任何单一来源） ----------
def check_builtin_count_independent():
    consts = ROOT / "internal" / "mcp" / "builtin" / "constants.go"
    if not consts.exists():
        record("constants.go 在位", False, "observed", str(consts))
        return
    text = consts.read_text(encoding="utf-8")
    block = text.split("func GetAllBuiltinTools()")[-1]
    # 统计返回体中的 Tool 常量引用行
    n = sum(1 for line in block.splitlines() if line.strip().startswith("Tool"))
    record(f"constants.go GetAllBuiltinTools 独立计数 = {n}（期望 52）", n == 52, "derived",
           "" if n == 52 else "与 count_stats 口径不一致，以代码为准并排查 count_stats")


# ---------- 3. 关键门禁脚本在位 ----------
GATE_SCRIPTS = [
    "scripts/count_stats.py",
    "scripts/audit_benchmark_validity.py",
    "scripts/_audit_truth_sources.py",
    "scripts/check_artifact_numbers.py",
    "scripts/check_doc_port_consistency.py",
    "scripts/check_binary_version.py",
]


def check_gate_scripts():
    missing = [p for p in GATE_SCRIPTS if not (ROOT / p).exists()]
    record(f"关键门禁脚本 {len(GATE_SCRIPTS) - len(missing)}/{len(GATE_SCRIPTS)} 在位",
           not missing, "observed", f"缺失: {missing}" if missing else "")


# ---------- 4. 仓库卫生 ----------
def check_git():
    b = run(["git", "branch", "--show-current"])
    name = (b.stdout or "").strip()
    if name:
        record(f"Git 分支 = {name}", True, "observed")
    else:
        c = run(["git", "branch", "--contains", "HEAD"])
        holders = [l.strip().lstrip("* ").strip() for l in (c.stdout or "").splitlines() if l.strip()]
        record("Git HEAD = detached（可恢复）", None, "observed",
               f"被分支包含（{', '.join(holders)}）——建议切回分支" if holders else "孤儿 HEAD——先建分支")
    st = run(["git", "status", "--porcelain"])
    lines = [l for l in (st.stdout or "").splitlines() if l.strip()]
    untracked = sum(1 for l in lines if l.startswith("??"))
    record(f"工作区 {len(lines) - untracked} 改 / {untracked} 未跟踪", True, "observed",
           "AGENTS.md 铁律：动 registry 前备份，编号用 next_nr.py 原子取号" if lines else "")


# ---------- 5. --full：编译门禁 ----------
def run_full():
    go = run(["go", "version"])
    if go.returncode != 0:
        record("go build ./...", None, "unknown", "go 工具链缺失——编译未验证")
        return
    record(f"go 工具链：{(go.stdout or '').strip()}", True, "observed")
    b = run(["go", "build", "./..."])
    record("go build ./...", b.returncode == 0, "observed",
           "" if b.returncode == 0 else (b.stderr or b.stdout)[-400:])


def main():
    data = check_truth_source()
    check_builtin_count_independent()
    check_gate_scripts()
    check_git()
    if FULL:
        run_full()

    fails = sum(1 for r in results if r["status"] == "FAIL")
    warns = sum(1 for r in results if r["status"] == "WARN")
    failed = fails + (warns if STRICT else 0)

    if JSON_MODE:
        print(json.dumps({"tool": "doctor", "full": FULL, "strict": STRICT,
                          "head": _git_head(), "ran_at": datetime.now(timezone.utc).isoformat(),
                          "results": results,
                          "summary": {"pass": len(results) - fails - warns, "fail": fails, "warn": warns}},
                         ensure_ascii=False, indent=2))
    else:
        mark = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}
        print("=" * 68)
        print("  SecAutoMind · 健康自检（doctor）" + (" · --full" if FULL else " · 快速档"))
        print(f"  基线 HEAD: {_git_head()}  运行时刻: {datetime.now(timezone.utc).isoformat()}")
        print("=" * 68)
        for r in results:
            print(f"  {mark[r['status']]} {r['name']:<44} [{r['level']}]" + (f" — {r['detail']}" if r["detail"] else ""))
        print("-" * 68)
        print(f"  汇总: {len(results) - fails - warns} 通过 / {fails} 失败 / {warns} 警告"
              + (f"（--strict: {warns} 个 WARN 计失败）" if STRICT else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
