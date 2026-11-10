#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Skill 元数据完整性门禁（2026-11-11 新增）。

背景
----
`SkillManager.discover()`（tools/skill_manager.py）扫描 `skills/*.py` 并逐个
建立 SkillMeta；`_load_meta()` 在缺 `.json` 时**静默用默认值**（空 purpose/
categories），不报错、不跳过。但 MainAgent 在 prompt 中靠 `purpose`/`categories`
决定何时调用（core/prompts.py）。**缺 json = 模型看不到用途 = 与 legendre
同源的「看不见」缺陷**。

`9d15a62` 仅修了 `crypto_legendre_phi` 一个；本门禁发现同口径下仍有 14 个真
skill（均含 `def run`）缺 json。本门禁将其变为机器可验证的 fail-closed 防线，
防止回归。

检查项
------
R1  真 skill（顶层 `def run(`）必须存在同名 `.json`，否则模型看不见用途。
R2  `.json` 若存在必须可被 json.load 解析（捕获 skill_manager 的 except:pass
    静默吞错）。
R3  `.json` 解析后 `purpose` 非空、且 `categories` 为非空 list（空元数据=看不见）。

退出码：发现任一违规则 rc!=0（fail-closed）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile


def _repo_root() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return os.getcwd()


def _default_skills_dir() -> str:
    return os.path.join(
        _repo_root(), "CTF-Agent_融合", "ctf_agent", "skills"
    )


_RUN_RE = re.compile(r"^\s*def\s+run\s*\(", re.M)


def _has_run(source: str) -> bool:
    """是否含顶层 def run(（真 skill 契约）。"""
    try:
        # 仅在模块级作用域判定；简化：整文件搜 def run( 即可，
        # 辅助模块通常不定义 run。
        return bool(_RUN_RE.search(source))
    except Exception:
        return False


def check_skill(name: str, skills_dir: str) -> list[str]:
    """返回该 skill 的违规列表（空=通过）。"""
    violations: list[str] = []
    py_path = os.path.join(skills_dir, name + ".py")
    json_path = os.path.join(skills_dir, name + ".json")

    source = ""
    try:
        with open(py_path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as exc:
        # 文件读不了属于其他门禁职责，这里跳过（discover 也会记 failure）
        return violations

    is_real_skill = _has_run(source)
    if not is_real_skill:
        # 辅助/库模块：不要求 json（与 SkillManager 语义一致）
        return violations

    # R1：真 skill 必须有同名 json
    if not os.path.exists(json_path):
        violations.append(
            f"[{name}] 真 skill（含 def run）缺元数据 .json "
            f"→ 模型在 prompt 中看不到用途（与 legendre 同源缺陷）"
        )
        return violations

    # R2：json 必须可解析（捕获 _load_meta 的 except:pass 静默吞错）
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        violations.append(f"[{name}] .json 解析失败（静默吞错风险）: {exc}")
        return violations

    if not isinstance(data, dict):
        violations.append(f"[{name}] .json 顶层不是对象")
        return violations

    # R3：purpose / categories 非空
    purpose = data.get("purpose", "")
    if not isinstance(purpose, str) or not purpose.strip():
        violations.append(f"[{name}] .json purpose 为空 → 模型看不到用途描述")
    cats = data.get("categories", [])
    if not isinstance(cats, list) or len(cats) == 0:
        violations.append(
            f"[{name}] .json categories 为空 list → can_handle 恒 True（任何题型都接）"
        )
    return violations


def run_checks(skills_dir: str) -> tuple[list[str], int]:
    """扫描全部 skill，返回 (violations, skill_count)。"""
    violations: list[str] = []
    count = 0
    if not os.path.isdir(skills_dir):
        print(f"[WARN] skills 目录不存在: {skills_dir}", file=sys.stderr)
        return violations, 0
    for fname in sorted(os.listdir(skills_dir)):
        if not fname.endswith(".py"):
            continue
        name = fname[:-3]
        if name == "__init__":
            continue
        count += 1
        violations.extend(check_skill(name, skills_dir))
    return violations, count


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Skill 元数据完整性门禁")
    ap.add_argument("--skills-dir", default=None,
                    help="skills 目录（默认推导仓库内路径）")
    ap.add_argument("--self-test", action="store_true",
                    help="运行变异自测后退出（不扫描真实仓库）")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    skills_dir = args.skills_dir or _default_skills_dir()
    violations, count = run_checks(skills_dir)
    print(f"扫描 skill 数: {count}")
    if violations:
        print(f"发现违规 {len(violations)} 项:")
        for v in violations:
            print(f"  ✗ {v}")
        return 1
    print("✓ 所有真 skill 元数据完整（purpose/categories 非空且可解析）")
    return 0


# ── 变异自测 ──────────────────────────────────────────────────────────
def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _self_test() -> int:
    cases = []

    def add(desc, expect_violation, build):
        cases.append((desc, expect_violation, build))

    # 1) 正常真 skill：py 有 run + json 完整 → 应通过
    def c_ok(d):
        _write(f"{d}/ok_skill.py", "def run(params):\n    return 'x'\n")
        _write(f"{d}/ok_skill.json",
               json.dumps({"purpose": "demo", "categories": ["crypto"]}))
    add("正常真 skill（py+完整json）→ PASS", False, c_ok)

    # 2) 真 skill 缺 json → 应 R1 违规
    def c_missing(d):
        _write(f"{d}/missing_skill.py", "def run(params):\n    return 'x'\n")
    add("真 skill 缺 json → FAIL(R1)", True, c_missing)

    # 3) 坏 json → 应 R2 违规
    def c_bad_json(d):
        _write(f"{d}/bad_skill.py", "def run(params):\n    return 'x'\n")
        _write(f"{d}/bad_skill.json", "{ this is not json ")
    add("真 skill 坏 json → FAIL(R2)", True, c_bad_json)

    # 4) 空 purpose → 应 R3 违规
    def c_empty_purpose(d):
        _write(f"{d}/empty_purpose_skill.py", "def run(params):\n    return 'x'\n")
        _write(f"{d}/empty_purpose_skill.json",
               json.dumps({"purpose": "", "categories": ["crypto"]}))
    add("真 skill 空 purpose → FAIL(R3)", True, c_empty_purpose)

    # 5) 空 categories → 应 R3 违规
    def c_empty_cats(d):
        _write(f"{d}/empty_cats_skill.py", "def run(params):\n    return 'x'\n")
        _write(f"{d}/empty_cats_skill.json",
               json.dumps({"purpose": "demo", "categories": []}))
    add("真 skill 空 categories → FAIL(R3)", True, c_empty_cats)

    # 6) 辅助模块（无 run）缺 json → 应通过（不要求 json）
    def c_helper(d):
        _write(f"{d}/helper_mod.py",
               "def _internal():\n    return 1\n")
    add("辅助模块（无run）缺 json → PASS", False, c_helper)

    passed = 0
    for desc, expect_violation, build in cases:
        with tempfile.TemporaryDirectory() as td:
            build(td)
            # 仅扫该临时目录
            v, _ = run_checks(td)
            got_violation = len(v) > 0
            ok = (got_violation == expect_violation)
            status = "✓" if ok else "✗"
            print(f"  {status} {desc}  (violations={len(v)})")
            if not ok:
                for x in v:
                    print(f"      实际: {x}")
            if ok:
                passed += 1

    total = len(cases)
    print(f"\n自测: {passed}/{total} 通过")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
