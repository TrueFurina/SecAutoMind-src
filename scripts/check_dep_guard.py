#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_dep_guard.py —— 依赖守卫可达性 + 导入失败告警通道门禁（2026-11-10）。

## 为什么存在

`skills/misc_grid_resample.py` 把 numpy / PIL 放在模块级**硬导入**，又在 try 里
重复 import 一次只为设 `HAS_DEPS`。结果：缺依赖时模块在导入阶段就抛 ImportError，
根本走不到 `HAS_DEPS = False`；依赖齐全时该标志恒 True，于是 `run()` 里的
`if not HAS_DEPS` 是**永不可达的死分支**。调用方（`core/presolve.py` 网格重采样
通道）只拿到一条 debug 日志 + None，与「试过了没解出」完全同形。

这是 `skills/rsa_fermat_factor.py` 静默降级（2026-11-08 修）的更隐蔽变体：
那次是「标志生效但没有告警」，这次是「标志和守卫都写了，但守卫永远走不到」。

同一份审计还发现 `core/presolve.py` 有 9 处「导入失败即 return None」的分支只留
debug 日志（其中 1 处连日志都没有），而项目早就有 `_warn_import_once` 统一通道。
继续扩到全仓后又发现 `agents/math_engine.py` 2 处、`core/fallbacks.py` 3 处同类
静默放弃，一并收口并抽出共享告警模块 `core/import_alert.py`。

## 判据（全部 AST，不看文字、不受注释或字符串骗）

C0  声明了 HAS_DEPS 的 skill，`run()` 内必须真的存在 `if not HAS_DEPS` 分支。
C1  这类模块的所有第三方 import 必须在 try 内（模块级裸导入集合必须为空），
    且 try 内必须至少有一个第三方 import（守卫不能架空）。
C2  presolve.py 里「try 体只有 skills.* import」且「handler 以 return None 放弃
    整条通道」的分支，handler 必须调用 `_warn_import_once`，第一参数点名该模块。
C3  全仓其余活跃代码（除 presolve.py / tests）里的同类「纯导入探测 + 静默放弃」
    分支，必须有 warning 级告警且点名模块。handler 里有实质回退实现
    （例如 `agents/crypto_toolkit.py` 的内联完整摩斯码表）属「能力替代」，
    自动豁免、不计入 C3 分母。
C2-COVERAGE  这类分支数不得低于 MIN_PURE_IMPORT_GUARDS（防判据缩水）。
C3-COVERAGE  C3 分支数不得低于 MIN_C3_GUARDS（防判据缩水）。
C1-COVERAGE  扫描集里至少要有一个声明守卫的 skill（防扫描集被清空）。

**作用域外**：try 体含实际求解调用（超时/求解异常分支）、handler 用 continue
跳过当前附件、以及本来就没放弃整条通道的分支——都不强制告警，避免误报。

## 用法

    python scripts/check_dep_guard.py              # 0=绿 / 1=红 / 2=结构错误
    python scripts/check_dep_guard.py --stats      # 额外打印覆盖计数
    python scripts/check_dep_guard.py --selftest   # 变异自测：判据必须能变红

退出码：0 = 全绿；1 = 判据红；2 = 结构错误（fail-closed，文件缺失 / 语法错）。
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "CTF-Agent_融合" / "ctf_agent" / "skills"
PRESOLVE = REPO_ROOT / "CTF-Agent_融合" / "ctf_agent" / "core" / "presolve.py"

# 本地包与标准库都不是「可选第三方依赖」，不计入守卫覆盖范围。
LOCAL_PACKAGES = frozenset({
    "skills", "tools", "core", "agents", "ctf_agent", "__future__",
})
STDLIB = frozenset(getattr(sys, "stdlib_module_names", ()))

# 防缩水下限：比实测值留一档余量，避免正常重构误红；低于它说明扫描集或
# 对应文件的导入结构被大改，判据本身已经失效。
MIN_PURE_IMPORT_GUARDS = 18
MIN_GUARDED_SKILLS = 2
MIN_C3_GUARDS = 4

GUARD_FLAG = "HAS_DEPS"
WARN_FN = "_warn_import_once"

# C3 扫描集：活跃副本下全部 .py，排除 tests 与 presolve.py（后者由更严格的 C2 覆盖）。
CALLER_ROOT = REPO_ROOT / "CTF-Agent_融合" / "ctf_agent"
C2_EXCLUDED_CALLERS = frozenset({"core/presolve.py"})
CALLER_SKIP_PARTS = frozenset({"tests", "__pycache__", ".pytest_cache"})


def read_lf(path: Path) -> str:
    """按字节读并归一为 LF：工作树在 core.autocrlf=true 下是 CRLF，git blob 是 LF。

    归一后 AST 行号与变异字符串都与仓库内容一致，不受本机检出设置影响。
    """
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def _top_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [a.name.split(".")[0] for a in node.names if a.name]
    if isinstance(node, ast.ImportFrom):
        if node.level or not node.module:
            return []
        return [node.module.split(".")[0]]
    return []


def _full_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [a.name for a in node.names if a.name]
    if isinstance(node, ast.ImportFrom):
        return [node.module] if node.module else []
    return []


def _third_party(name: str) -> bool:
    return name not in STDLIB and name not in LOCAL_PACKAGES


def _assigns_flag(tree: ast.AST, flag: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == flag and isinstance(node.ctx, ast.Store):
            return True
    return False


def _run_has_guard(tree: ast.AST, flag: str) -> bool:
    """run() 内必须真的有 `if not HAS_DEPS` 分支——注释里写不算。"""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == "run"):
            continue
        for sub in ast.walk(node):
            if not isinstance(sub, ast.If):
                continue
            test = sub.test
            if (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
                    and isinstance(test.operand, ast.Name)
                    and test.operand.id == flag):
                return True
    return False


def _import_sets(tree: ast.Module) -> tuple[set[str], set[str]]:
    """(模块级裸导入顶层包, try 内导入顶层包)。只看 tree.body 直接子节点。"""
    bare: set[str] = set()
    guarded: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bare.update(m for m in _top_modules(node) if m)
        elif isinstance(node, ast.Try):
            for sub in node.body:
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    guarded.update(m for m in _top_modules(sub) if m)
    return bare, guarded


def check_skill_source(src: str, label: str = "<skill>") -> tuple[list[str], bool]:
    """返回 (errors, applicable)。applicable=False 表示该模块没声明守卫，不纳入判据。"""
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return ["PARSE_FAIL %s: %s" % (label, exc)], True
    if not _assigns_flag(tree, GUARD_FLAG):
        return [], False

    errors: list[str] = []
    if not _run_has_guard(tree, GUARD_FLAG):
        errors.append("C0 %s: 声明 %s 但 run() 内没有真实守卫分支" % (label, GUARD_FLAG))
    bare, guarded = _import_sets(tree)
    bare_third = sorted(m for m in bare if _third_party(m))
    guarded_third = sorted(m for m in guarded if _third_party(m))
    if bare_third:
        errors.append(
            "C1 %s: 模块级裸导入第三方 %s → 缺依赖时模块加载即崩，守卫不可达"
            % (label, bare_third))
    if not guarded_third:
        errors.append("C1 %s: try 内没有任何第三方 import → 守卫没有覆盖任何依赖" % label)
    return errors, True


def _returns_none(handler: ast.ExceptHandler) -> bool:
    for stmt in handler.body:
        if isinstance(stmt, ast.Return) and (
                stmt.value is None
                or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)):
            return True
    return False


def check_presolve_source(src: str, label: str = "<presolve>") -> tuple[list[str], int]:
    """返回 (errors, checked)。checked = 纳入 C2 的「纯导入探测 + 失败即放弃」分支数。"""
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return ["PARSE_FAIL %s: %s" % (label, exc)], 0

    errors: list[str] = []
    checked = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or not node.body:
            continue
        mods: list[str] = []
        pure_import = True
        for stmt in node.body:
            if isinstance(stmt, ast.ImportFrom) and stmt.module and stmt.module.startswith("skills."):
                mods.extend(m for m in _full_modules(stmt) if m)
            elif isinstance(stmt, ast.Import) and all(a.name.startswith("skills.") for a in stmt.names):
                mods.extend(a.name for a in stmt.names)
            else:
                pure_import = False
                break
        if not pure_import or not mods:
            continue
        for handler in node.handlers:
            if not _returns_none(handler):
                continue
            checked += 1
            calls = [
                c for c in ast.walk(handler)
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                and c.func.id == WARN_FN
            ]
            if not calls:
                errors.append(
                    "C2 %s:%d: 纯导入探测分支 [%s] 失败即 return None，却没有 %s（静默降级）"
                    % (label, handler.lineno, ",".join(mods), WARN_FN))
                continue
            first = calls[0].args[0] if calls[0].args else None
            named = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
            if named not in mods:
                errors.append(
                    "C2 %s:%d: %s 第一参数 %r 未点名模块 %s"
                    % (label, handler.lineno, WARN_FN, named, mods))
    if checked < MIN_PURE_IMPORT_GUARDS:
        errors.append(
            "C2-COVERAGE %s: 纯导入探测分支仅 %d 条 < %d（判据缩水或导入结构被大改）"
            % (label, checked, MIN_PURE_IMPORT_GUARDS))
    return errors, checked


def _is_warning_call(call: ast.Call) -> bool:
    """warning 级调用：函数名含 warn（`_warn_import_once` / `warn_import_once`），
    或属性为 warning/warn（logger.warning / warnings.warn）。"""
    f = call.func
    if isinstance(f, ast.Name):
        return "warn" in f.id.lower()
    if isinstance(f, ast.Attribute):
        return f.attr.lower() in ("warning", "warn")
    return False


def _is_lowlevel_log(call: ast.Call) -> bool:
    f = call.func
    return isinstance(f, ast.Attribute) and f.attr in ("debug", "info")


def _first_str_arg(call: ast.Call) -> str | None:
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return None


def _classify_handler(handler: ast.ExceptHandler):
    """判定 handler 形态。

    返回 (has_warning, named_module) 表示「静默放弃」，纳入 C3；
    返回 None 表示判据不适用：要么没放弃整条通道（如 continue），
    要么有实质回退实现（能力替代，应豁免，不计入分母）。
    """
    if not _returns_none(handler):
        return None
    has_warning = False
    named = None
    for stmt in handler.body:
        if isinstance(stmt, (ast.Return, ast.Pass)):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if _is_warning_call(call):
                has_warning = True
                named = _first_str_arg(call) or named
                continue
            if _is_lowlevel_log(call):
                continue
            return None
        return None
    return has_warning, named


def check_caller_source(src: str, label: str = "<caller>") -> tuple[list[str], int, int]:
    """C3：返回 (errors, checked, skipped_fallbacks)。"""
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return ["PARSE_FAIL %s: %s" % (label, exc)], 0, 0

    errors: list[str] = []
    checked = 0
    skipped = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or not node.body:
            continue
        mods: list[str] = []
        pure_import = True
        for stmt in node.body:
            if (isinstance(stmt, ast.ImportFrom) and stmt.module
                    and stmt.module.startswith(("skills.", "agents."))):
                mods.extend(m for m in _full_modules(stmt) if m)
            elif (isinstance(stmt, ast.Import)
                  and all(a.name.startswith(("skills.", "agents.")) for a in stmt.names)):
                mods.extend(a.name for a in stmt.names)
            else:
                pure_import = False
                break
        if not pure_import or not mods:
            continue
        for handler in node.handlers:
            classified = _classify_handler(handler)
            if classified is None:
                skipped += 1
                continue
            checked += 1
            has_warning, named = classified
            if not has_warning:
                errors.append(
                    "C3 %s:%d: 纯导入探测分支 [%s] 失败即 return None，却无 warning 级告警（静默降级）"
                    % (label, handler.lineno, ",".join(mods)))
            elif named not in mods:
                errors.append(
                    "C3 %s:%d: 告警第一参数 %r 未点名模块 %s"
                    % (label, handler.lineno, named, mods))
    return errors, checked, skipped


def _c3_coverage_errors(checked: int, label: str) -> list[str]:
    if checked < MIN_C3_GUARDS:
        return ["C3-COVERAGE %s: 静默放弃类分支仅 %d 条 < %d（判据缩水或导入结构被大改）"
                % (label, checked, MIN_C3_GUARDS)]
    return []


def check_repo(skills_dir: Path = SKILLS_DIR,
               presolve: Path = PRESOLVE) -> tuple[list[str], dict]:
    errors: list[str] = []
    stats: dict = {}
    if not skills_dir.is_dir():
        return ["STRUCT 扫描目录不存在: %s" % skills_dir], stats
    if not presolve.is_file():
        return ["STRUCT presolve.py 不存在: %s" % presolve], stats
    if not CALLER_ROOT.is_dir():
        return ["STRUCT C3 扫描目录不存在: %s" % CALLER_ROOT], stats

    files = sorted(skills_dir.glob("*.py"))
    guarded = 0
    for path in files:
        errs, applicable = check_skill_source(read_lf(path), path.name)
        if applicable:
            guarded += 1
        errors.extend(errs)
    stats["skill_files"] = len(files)
    stats["guarded_skills"] = guarded
    if guarded < MIN_GUARDED_SKILLS:
        errors.append(
            "C1-COVERAGE 声明守卫的 skill 仅 %d 个 < %d（扫描集被清空或守卫被摘掉）"
            % (guarded, MIN_GUARDED_SKILLS))

    perrs, checked = check_presolve_source(read_lf(presolve), presolve.name)
    errors.extend(perrs)
    stats["pure_import_guards"] = checked
    stats["min_pure_import_guards"] = MIN_PURE_IMPORT_GUARDS

    c3_checked = 0
    c3_skipped = 0
    c3_candidates = 0
    for caller in sorted(CALLER_ROOT.rglob("*.py")):
        rel = caller.relative_to(CALLER_ROOT)
        if any(part in CALLER_SKIP_PARTS for part in rel.parts[:-1]):
            continue
        if rel.as_posix() in C2_EXCLUDED_CALLERS:
            continue
        # 字节预筛只为加速（900+ 文件不必全 parse）；判据本身仍全部走 AST。
        raw = caller.read_bytes()
        if not any(tok in raw for tok in (b"from skills.", b"from agents.",
                                          b"import skills.", b"import agents.")):
            continue
        c3_candidates += 1
        cerrs, cch, csk = check_caller_source(read_lf(caller), rel.as_posix())
        errors.extend(cerrs)
        c3_checked += cch
        c3_skipped += csk
    errors.extend(_c3_coverage_errors(c3_checked, "全仓"))
    stats["c3_candidates"] = c3_candidates
    stats["c3_guards"] = c3_checked
    stats["c3_fallbacks_skipped"] = c3_skipped
    stats["min_c3_guards"] = MIN_C3_GUARDS
    return errors, stats


def selftest() -> int:
    """变异自测：先证明「判据能变红」，再允许用它下结论。"""
    skill = read_lf(SKILLS_DIR / "misc_grid_resample.py")
    pre = read_lf(PRESOLVE)
    cases: list[tuple[str, bool, int]] = []

    def case(name: str, errs: list[str], expect_red: bool) -> None:
        ok = bool(errs) == expect_red
        cases.append((name, ok, len(errs)))

    base_skill, applicable = check_skill_source(skill, "baseline")
    case("B0 基线 skill 全绿且判据适用",
         base_skill if applicable else ["NOT_APPLICABLE"], False)
    base_pre, checked = check_presolve_source(pre, "baseline")
    case("B1 基线 presolve 全绿", base_pre, False)
    cases.append(("B2 基线覆盖数 >= 下限", checked >= MIN_PURE_IMPORT_GUARDS, checked))

    # M1：还原修复前形态——第三方 import 挪到模块级，守卫变成死分支。
    old1 = "try:\n    import numpy as np\n    from PIL import Image\n    HAS_DEPS = True"
    new1 = "import numpy as np\nfrom PIL import Image\ntry:\n    HAS_DEPS = True"
    assert old1 in skill, "M1 锚点失效，变异自测必须 fail-closed"
    e1, _ = check_skill_source(skill.replace(old1, new1, 1), "M1")
    case("M1 模块级裸导入第三方必须判红", e1, True)

    # M2：守卫架空——try 里一个第三方 import 都没有。
    new2 = "try:\n    HAS_DEPS = True"
    e2, _ = check_skill_source(skill.replace(old1, new2, 1), "M2")
    case("M2 守卫不覆盖任何依赖必须判红", e2, True)

    # M3：注释里写 `if not HAS_DEPS`、真实分支换成 if False。
    # 正则类判据会被注释骗成绿；AST 判据必须红。
    old3 = "    if not HAS_DEPS:"
    new3 = "    # if not HAS_DEPS:\n    if False:"
    assert old3 in skill, "M3 锚点失效，变异自测必须 fail-closed"
    e3, _ = check_skill_source(skill.replace(old3, new3, 1), "M3")
    case("M3 注释伪造守卫必须判红", e3, True)

    anchor4 = '_warn_import_once("skills.misc_grid_resample", exc)'
    assert anchor4 in pre, "M4 锚点失效，变异自测必须 fail-closed"
    # M4：告警换回 debug 日志。
    m4 = pre.replace(anchor4, 'logger.debug("[presolve:grid_resample] import failed: %s", exc)', 1)
    e4, _ = check_presolve_source(m4, "M4")
    case("M4 仅 debug 日志的失败分支必须判红", e4, True)
    # M5：告警点名不对（少 skills. 前缀）。
    m5 = pre.replace(anchor4, '_warn_import_once("misc_grid_resample", exc)', 1)
    e5, _ = check_presolve_source(m5, "M5")
    case("M5 未点名模块的告警必须判红", e5, True)
    # M6：把调用塞进注释，正文只剩 debug —— 同样针对「正则被注释骗」。
    m6 = pre.replace(anchor4, 'logger.debug("x")  # _warn_import_once("skills.misc_grid_resample", exc)', 1)
    e6, _ = check_presolve_source(m6, "M6")
    case("M6 注释里的告警调用不算数（必须判红）", e6, True)
    # M7：扫描集整体缩水（所有 skills 导入改名）。
    m7 = pre.replace("from skills.", "from elsewhere.")
    e7, checked7 = check_presolve_source(m7, "M7")
    case("M7 覆盖数塌陷必须判红", e7, True)
    cases.append(("M8 塌陷后覆盖数确实归零", checked7 == 0, checked7))

    # ---- C3：全仓判据 ----
    me = read_lf(CALLER_ROOT / "agents" / "math_engine.py")
    ct = read_lf(CALLER_ROOT / "agents" / "crypto_toolkit.py")
    e_b3, ch_b3, _ = check_caller_source(me, "baseline math_engine")
    case("B3 基线 math_engine 全绿", e_b3, False)
    cases.append(("B4 math_engine 两条分支均纳入 C3", ch_b3 == 2, ch_b3))
    _, _, sk_ct = check_caller_source(ct, "baseline crypto_toolkit")
    cases.append(("B5 内联码表回退被识别为能力替代而豁免", sk_ct >= 1, sk_ct))

    anchor9 = 'warn_import_once("skills.misc_bigfile_analysis", exc)'
    assert anchor9 in me, "M9 锚点失效，变异自测必须 fail-closed"
    m9 = me.replace(anchor9, 'logger.debug("import failed: %s", exc)', 1)
    e9, _, _ = check_caller_source(m9, "M9")
    case("M9 C3 仅 debug 日志必须判红", e9, True)
    m10 = me.replace(anchor9,
                     'logger.debug("x")  # warn_import_once("skills.misc_bigfile_analysis", exc)', 1)
    e10, _, _ = check_caller_source(m10, "M10")
    case("M10 C3 注释伪造告警必须判红", e10, True)
    m12 = me.replace(anchor9, 'warn_import_once("misc_bigfile_analysis", exc)', 1)
    e12, _, _ = check_caller_source(m12, "M12")
    case("M12 C3 告警不点名模块必须判红", e12, True)

    # M11：能力替代的豁免不是无条件——把内联回退换成 return None 就必须判红。
    syn_alt = '''def f():
    try:
        from skills.morse_decoder import MORSE_TABLE
    except Exception as e:
        MORSE_TABLE = {".-": "a"}
'''
    syn_abandon = syn_alt.replace('        MORSE_TABLE = {".-": "a"}\n', "        return None\n")
    e_alt, ch_alt, sk_alt = check_caller_source(syn_alt, "M11-alt")
    e_ab, _, _ = check_caller_source(syn_abandon, "M11-abandon")
    cases.append(("M11 能力替代形态豁免（不判红、不入分母）",
                  (not e_alt) and ch_alt == 0 and sk_alt == 1, ch_alt))
    case("M11 同一分支改成静默放弃必须判红", e_ab, True)
    cases.append(("M13 C3 覆盖数塌陷必须判红", bool(_c3_coverage_errors(0, "M13")), 0))
    cases.append(("M14 C3 覆盖数达标时不误报",
                  not _c3_coverage_errors(5, "M14"), 5))

    passed = 0
    for name, ok, n in cases:
        print("[%s] %s (n=%s)" % ("PASS" if ok else "FAIL", name, n))
        passed += int(ok)
    total = len(cases)
    print("selftest: %d/%d PASS" % (passed, total))
    return 0 if passed == total else 1


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
        if any(e.startswith(("PARSE_FAIL", "STRUCT")) for e in errors):
            return 2
        return 1
    print("OK: 守卫可达性 / presolve + 全仓导入失败告警通道全绿 %s" % stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
