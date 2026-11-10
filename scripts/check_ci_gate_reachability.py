#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_ci_gate_reachability.py —— 门禁脚本必须能从 CI 可达（2026-11-10）。

## 背景：一条长期挂账其实是度量口径错误

项目长期记忆写着「约 20 个门禁脚本仍未接 CI」。用「ci.yml 里有没有
scripts/xxx.py 字符串」去数，确实得到 20 个；但那是**假阳性**：

- `capability_caliber_test.py`（ci.yml:1148）import 并断言
  `verify_verdict_chain.check()` / `verify_capability_evidence.check()` 等
  ⇒ 这些脚本**间接可达**；
- `check_workflows_yaml.py` 在 `ci_lint.yml`，`check_question_truth_test.py`
  在 ci.yml（只是路径写法不带 `scripts/` 前缀，被窄正则漏掉）；
- 多数 `audit_*` 的 docstring 明写「盘点工具，不是门禁」「一次性归类器」。

按「CI 根入口 + Python import/字符串引用」的传递闭包重算：**54 个门禁类
脚本里 43 个可达，剩 11 个全是工具 / 本机专用 / 当前稳定判红**（逐个实跑
核实，见 `docs/evidence/CI门禁可达性覆盖矩阵_20261110.md`）。所以本门禁不是
去「把 20 个都接上」，而是把**可达性本身**变成可机器验证的判据：新增一个
门禁类脚本却不接 CI、也不登记豁免理由 ⇒ 立刻判红。

## 判据（全部结构化，不受注释骗）

R1 根入口：只从 workflow 的 `run`/`python`/`entry` 命令里提取 .py；
   整行注释与行内 `#` 之后的内容一律不算。
R2 依赖边：`ast.parse` 提取同目录 import 与**非 docstring 的字符串常量**
   里的 `scripts/xxx.py`；注释、docstring 里的示例命令都不构成边。
R3 扫描集（`check_/verify_/audit_` 开头、非 `_test.py`）必须可达或在豁免表。
R4 豁免表每个键必须真实存在于扫描集（防手打错字 / 文件删除后悬空）；
   理由必须具体（>= 20 字且不含 TODO/待定）；数量不得超过 MAX_EXEMPT。
R5 防缩水：根入口 >= MIN_ROOTS、可达门禁 >= MIN_REACHABLE。

## 用法

    python scripts/check_ci_gate_reachability.py              # 0/1/2
    python scripts/check_ci_gate_reachability.py --stats
    python scripts/check_ci_gate_reachability.py --selftest   # 变异自测

退出码：0 全绿 / 1 判据红 / 2 结构错误（fail-closed）。
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
WORKFLOW_GLOB = REPO_ROOT / ".github" / "workflows"
EXTRA_DRIVERS = (
    REPO_ROOT / ".pre-commit-config.yaml",
    REPO_ROOT / "scripts" / "_ci_local.sh",
)

PY_RE = re.compile(r"([A-Za-z0-9_\-]+\.py)\b")
PATH_RE = re.compile(r"scripts/([A-Za-z0-9_\-]+\.py)\b")

MIN_ROOTS = 100
MIN_REACHABLE = 40
MAX_EXEMPT = 15

GATE_PREFIXES = ("check_", "verify_", "audit_")

# 豁免 = 经过逐个实跑定性后的**记账**，不是「遇到红就划掉」。
# 每条理由都写清「为什么不能/不该在干净检出的 CI 上跑」，且由 R4 锁住不腐化。
EXEMPT: dict[str, str] = {
    'audit_asset_metadata.py':
        "docstring 明写「盘点工具，不是门禁，暂不接 CI」；升级为门禁前须补回归+变异验证。实测默认调用只出盘点表。",
    'audit_public_flag_leak.py':
        "需联网抓取公开仓库真值，本机实测 40s 超时；属一次性外部真值审计，不是稳定 CI 判据。",
    'audit_read_attachment.py':
        "必须传日志路径参数，无参默认调用 RC=2；服务器跑批日志一次性归类器，干净检出无日志可归类。",
    'audit_run_logs.py':
        "服务器散落 .log/.jsonl 的一次性归类器，干净检出无日志可归类；实测输出「无 ABANDON 记录」。",
    'audit_scope_boundary.py':
        "docstring 明写「名字级初筛，非门禁不定罪」；只输出需人工判定的候选，不产生判定结论。",
    'audit_static_miss.py':
        "无 __main__ 入口，只打印 MISS 描述长度统计；是数据脚本，不产生任何判定。",
    'check_dual_repo_coherence.py':
        "需要外部 A 库（西湖论剑 ctf_agent）副本，本机实测 40s 超时；CI 干净检出没有该副本。",
    'verify_deleted_disposition.py':
        "核对工作树 D 状态是删除还是移动，依赖本机未跟踪文件；干净检出没有 D 状态可判定。",
    'verify_demo_readiness.py':
        "决赛演示就绪度一键闸门，依赖本机演示材料；实测 0/2 通过 RC=1，接 CI 即永久红。",
    'verify_live_contract.py':
        "仿真平台契约探针，实测 BLOCK（业务码 40001 非字符串）RC=1；属赛时现场校验非 CI 判据。",
    'verify_skill_wiring.py':
        "Runner v4 运行时接线探针，需可选依赖与运行时环境；实测输出依赖缺失告警，不适合干净检出。",
}


def extract_ci_roots(text: str) -> set[str]:
    """从 CI 驱动文本里提取「会被执行」的 .py 文件名。

    注释整行、行内 `#` 之后的内容都不算——否则在注释里写一句
    `python scripts/foo.py` 就能把 foo 伪装成已接 CI（本项目反复踩过的坑）。
    """
    roots: set[str] = set()
    for raw in text.splitlines():
        code = raw.split("#", 1)[0]
        if not code.strip():
            continue
        low = code.lower()
        if not any(tok in low for tok in ("python", "run:", "entry:", "bash ", "node ")):
            continue
        for m in PY_RE.finditer(code):
            roots.add(m.group(1))
    return roots


def extract_script_deps(src: str, known: set[str]) -> set[str]:
    """一个 scripts/*.py 依赖哪些同目录脚本（import 或真实字符串常量里的路径）。

    docstring 里的「用法：python scripts/xxx.py」是说明文字，不是调用 ⇒ 排除；
    注释更不会进 AST。只有真正的字符串常量（例如 REQUIRED_GATE_ARGV 里的
    元组）才算边。
    """
    deps: set[str] = set()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return deps
    doc_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                doc_ids.add(id(body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0] + ".py"
                if name in known:
                    deps.add(name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                name = node.module.split(".")[0] + ".py"
                if name in known:
                    deps.add(name)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in doc_ids):
            for m in PATH_RE.finditer(node.value):
                deps.add(m.group(1))
    return deps


def scan_gate_names(scripts_dir: Path) -> set[str]:
    return {
        p.name for p in scripts_dir.glob("*.py")
        if p.name.startswith(GATE_PREFIXES) and not p.name.endswith("_test.py")
    }


def build_reachable(driver_texts: list[str], scripts_dir: Path) -> tuple[set[str], set[str], dict]:
    """返回 (roots, reachable, deps_map)。"""
    known = {p.name for p in scripts_dir.glob("*.py")}
    roots: set[str] = set()
    for text in driver_texts:
        roots |= extract_ci_roots(text)
    deps_map = {
        p.name: extract_script_deps(p.read_bytes().decode("utf-8", errors="replace"), known)
        for p in scripts_dir.glob("*.py")
    }
    reachable = set(roots)
    stack = list(roots)
    while stack:
        cur = stack.pop()
        for dep in deps_map.get(cur, ()):
            if dep not in reachable:
                reachable.add(dep)
                stack.append(dep)
    return roots, reachable, deps_map


def check(scan_names: set[str], reachable: set[str], exempt: dict[str, str]) -> list[str]:
    """R3/R4：纯函数，便于变异自测注入。"""
    errors: list[str] = []
    for name in sorted(exempt):
        if name not in scan_names:
            errors.append("R4 豁免键不在扫描集（手打错字或文件已删）: %r" % name)
        reason = exempt[name]
        if len(reason) < 20 or any(tok in reason for tok in ("TODO", "待定", "TBD", "以后再说")):
            errors.append("R4 豁免理由不具体（必须写清为何不能进 CI）: %s" % name)
    for name in sorted(scan_names):
        if name in reachable or name in exempt:
            continue
        errors.append("R3 门禁类脚本不在 CI 可达图且未登记豁免: %s" % name)
    if len(exempt) > MAX_EXEMPT:
        errors.append("R4 豁免 %d 条 > 上限 %d（禁止遇红就加豁免）" % (len(exempt), MAX_EXEMPT))
    return errors


def check_numbers(n_roots: int, n_reachable: int, scan_names: set[str],
                  reachable: set[str], min_roots: int = MIN_ROOTS,
                  min_reachable: int = MIN_REACHABLE) -> list[str]:
    """R5：纯函数，防根入口/可达集被静默清空。

    下限可注入，方便变异自测用小规模合成集合验证判据本身而不依赖仓库规模。
    """
    errors: list[str] = []
    if n_roots < min_roots:
        errors.append("R5 CI 根入口仅 %d < %d（驱动文件被删或提取口径失效）" % (n_roots, min_roots))
    n_gate_reachable = len(scan_names & reachable)
    if n_gate_reachable < min_reachable:
        errors.append("R5 可达门禁仅 %d < %d（CI 链路被大改，判据已失效）"
                      % (n_gate_reachable, min_reachable))
    return errors


def check_repo() -> tuple[list[str], dict]:
    if not SCRIPTS_DIR.is_dir() or not WORKFLOW_GLOB.is_dir():
        return ["STRUCT scripts/ 或 .github/workflows 不存在"], {}
    driver_texts: list[str] = []
    for f in sorted(WORKFLOW_GLOB.glob("*.y*ml")) + list(EXTRA_DRIVERS):
        if f.is_file():
            driver_texts.append(f.read_bytes().decode("utf-8", errors="replace"))
    if not driver_texts:
        return ["STRUCT 没读到任何 CI 驱动文件"], {}

    scan_names = scan_gate_names(SCRIPTS_DIR)
    roots, reachable, _ = build_reachable(driver_texts, SCRIPTS_DIR)
    errors = check(scan_names, reachable, EXEMPT)
    errors += check_numbers(len(roots), len(reachable), scan_names, reachable)
    stats = {
        "ci_roots": len(roots),
        "gate_candidates": len(scan_names),
        "gate_reachable": len(scan_names & reachable),
        "exempt": len(EXEMPT),
        "unreachable_not_exempt": len([
            e for e in errors if e.startswith("R3 ")
        ]),
        "min_roots": MIN_ROOTS,
        "min_reachable": MIN_REACHABLE,
        "max_exempt": MAX_EXEMPT,
    }
    return errors, stats


def selftest() -> int:
    """变异自测：先证明「判据能变红」，再允许用它判仓库绿。"""
    cases: list[tuple[str, bool, int]] = []

    def case(name: str, errs: list[str], expect_red: bool) -> None:
        cases.append((name, bool(errs) == expect_red, len(errs)))

    scan = {"check_a.py", "check_b.py"}
    reach = {"check_a.py"}
    exempt = {"check_b.py": "一次性盘点工具，实测 40s 超时且 docstring 明写非门禁，不进 CI。"}
    case("B0 合成基线全绿", check(scan, reach, exempt), False)

    # R4：豁免键悬空 / 理由空洞 / 数量超限
    bad_key = dict(exempt)
    bad_key["check_ghost_typo.py"] = "理由写得很长很长，用来验证悬空键会被判红，防止手打错字。"
    case("M1 手打错字造成豁免悬空必须判红", check(scan, reach, bad_key), True)
    case("M2 豁免理由空洞必须判红", check(scan, reach, {"check_b.py": "TODO"}), True)
    over = {("fake_%d.py" % i): "理由具体：一次性工具，实测超时且需本机材料，不在干净检出跑。" for i in range(MAX_EXEMPT + 1)}
    case("M3 豁免数量超限必须判红", check(scan, reach, over), True)
    # R3：新增不可达且未登记的门禁
    case("M4 新增门禁不接 CI 必须判红", check(scan | {"check_new.py"}, reach, exempt), True)

    # R1：注释伪造 CI 接线
    case("M5 整行注释里的 python 调用不算根入口",
         [] if not extract_ci_roots("# python scripts/check_ghost.py\n") else ["X"], False)
    inline = extract_ci_roots("run: echo ok  # python scripts/check_ghost.py\n")
    case("M6 行内注释里的 python 调用不算根入口",
         ["X"] if "check_ghost.py" in inline else [], False)
    real = extract_ci_roots("        run: python scripts/check_dep_guard.py\n")
    case("M7 真实 run 行必须能提取", [] if "check_dep_guard.py" in real else ["X"], False)

    # R2：docstring / 注释里的路径不构成依赖边
    known = {"check_dep_guard.py", "verify_capability_evidence.py"}
    doc_src = '"""用法：python scripts/check_dep_guard.py --check"""\n'
    case("M8 docstring 示例不构成依赖边",
         ["X"] if extract_script_deps(doc_src, known) else [], False)
    comment_src = 'x = 1  # scripts/verify_capability_evidence.py\n'
    case("M9 注释里的路径不构成依赖边",
         ["X"] if extract_script_deps(comment_src, known) else [], False)
    real_src = 'ARGV = ("scripts/verify_capability_evidence.py", "--check")\n'
    case("M10 真实字符串常量必须构成依赖边",
         [] if "verify_capability_evidence.py" in extract_script_deps(real_src, known) else ["X"], False)

    # R5：防缩水
    case("M11 根入口塌陷必须判红",
         check_numbers(3, 200, scan, reach, min_roots=100, min_reachable=1), True)
    case("M12 可达门禁塌陷必须判红",
         check_numbers(200, 5, scan, reach, min_roots=1, min_reachable=2), True)
    case("B1 数量达标时不误报",
         check_numbers(144, 193, scan, reach | {"check_b.py"},
                       min_roots=1, min_reachable=2), False)

    # 真实仓库基线
    repo_errs, _ = check_repo()
    case("B2 真实仓库基线全绿", repo_errs, False)

    passed = 0
    for name, ok, n in cases:
        print("[%s] %s (n=%s)" % ("PASS" if ok else "FAIL", name, n))
        passed += int(ok)
    print("selftest: %d/%d PASS" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true", help="变异自测（判据必须能变红）")
    ap.add_argument("--stats", action="store_true", help="打印覆盖计数")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    errors, stats = check_repo()
    if args.stats or errors:
        print("stats: %s" % stats)
    if errors:
        for err in errors:
            print("RED: %s" % err)
        return 2 if any(e.startswith("STRUCT") for e in errors) else 1
    print("OK: 门禁类脚本均在 CI 可达图内或有具名豁免 %s" % stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
