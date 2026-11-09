#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""守「可选依赖不得静默缩小 pytest 收集集」（2026-11-09 实锤倒逼）。

背景
----
两端 CI 口径全量门禁曾长期报两个不同的数：本机 2153 passed / 89 deselected、
服务器 2169 passed / 90 deselected。当时写的解释是「Python 3.14 / 3.12 与
deselect 记账表的既有差异」——**没量过，而且是错的**。

实测：两端 `_ci_pytest_deselect.json` 只差行尾（LF 归一化后 sha 相同），
node 集合逐条比对后发现 11 条用例**在本机根本没被收集**，全部来自
`tests/test_crypto_knapsack_mhk.py:53` 的

    flint = pytest.importorskip("flint", reason="格后端 python-flint 未安装")

`importorskip` 在模块级 ⇒ 整个模块在 collect 阶段静默消失，pytest 报告里
连一行 skip 都看不到，门禁照样绿。根因链：

  · `requirements.txt` 声明了 `python-flint==0.9.0`；
  · `ci.yml` 的 pytest job 用**显式清单**装 15 个包，漏了它；
  · 「装完立刻自检」的 `need` 列表同样漏了它；
  · ⇒ 格基 LLL 背包密码的 11 条能力用例**从未在 CI 跑过**。

本机补装 `python-flint 0.9.0`（有 cp314 wheel）后收集数立刻变成
2203/2293 (90 deselected)，与服务器逐项一致 —— 差异 100% 来自这个包，
与 Python 版本、deselect 表都无关。

守什么
------
只补 `ci.yml` 里一个包名，治的是这一次；下次谁再加一个 `importorskip`
（或某个包在 CI 上装失败），同样会静默缩小覆盖面。本脚本改成从
`tests/**/*.py` 的 **AST** 自动抽出所有 `pytest.importorskip()` 目标，
逐个 `find_spec` 验证，缺一个就点名报红。

用 AST 不用正则：注释/字符串里的 `pytest.importorskip("x")` 不该被当真
（同族前科：`_registry_threaded_proven` 被注释骗成假阳性）。
非字面量参数一律 fail-closed（RC=2）——静态判不了就不许报绿。

退出码：0 全过 / 1 有缺失 / 2 无法判定（非字面量 / 解析失败）
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TESTS_DIR = ROOT / "tests"


def _scan(tests_dir):
    """返回 (targets, nonliteral, unparsable)。

    targets: [(relpath, lineno, 完整模块名, 顶层模块名)]
    """
    targets, nonliteral, unparsable = [], [], []
    for path in sorted(Path(tests_dir).rglob("*.py")):
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except SyntaxError as exc:
            unparsable.append((str(path), str(exc)))
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and fn.attr == "importorskip"):
                continue
            rel = str(path.relative_to(tests_dir)) if str(path).startswith(str(tests_dir)) else str(path)
            if not node.args:
                nonliteral.append((rel, node.lineno, "无位置参数"))
                continue
            arg = node.args[0]
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                nonliteral.append((rel, node.lineno, ast.unparse(arg)[:80]))
                continue
            full = arg.value
            top = full.split(".")[0]
            if not top:
                nonliteral.append((rel, node.lineno, repr(full)))
                continue
            targets.append((rel, node.lineno, full, top))
    return targets, nonliteral, unparsable


def _resolvable(full):
    """`find_spec` 对完整路径的判定。返回 (True/False/None, 异常说明)。

    None = 判不了 ⇒ fail-closed。注意两种「找不到」形态不同：
      · 顶层包在、子模块不在（PIL.DefinitelyMissing）→ find_spec 返回 None；
      · 顶层包就不在（no_such_pkg.Sub）→ 抛 ModuleNotFoundError。
    `importorskip` 对两者都会跳过整块用例，故都必须算缺失。
    """
    try:
        return importlib.util.find_spec(full) is not None, ""
    except (ImportError, ModuleNotFoundError):
        return False, ""
    except Exception as exc:  # 判不了不许报绿
        return None, "%s: %s" % (type(exc).__name__, str(exc)[:120])


def check(tests_dir=TESTS_DIR, quiet=False):
    """返回退出码。0 全过 / 1 有缺失 / 2 无法判定。"""
    targets, nonliteral, unparsable = _scan(tests_dir)
    # 🔴 2026-11-09 二次修：第一版只验顶层模块，等于判据只做了一半 ——
    # importorskip("PIL.Image") 真正要的是子模块，PIL 在但 PIL.Image 挂了
    # 照样整块跳过。改为对**完整模块路径**逐个 find_spec。
    fulls = sorted({t[2] for t in targets})
    tops = sorted({t[3] for t in targets})
    missing, unknown = [], []
    for full in fulls:
        ok, why = _resolvable(full)
        if ok is None:
            unknown.append((full, why))
        elif not ok:
            missing.append(full)

    if not quiet:
        print("=== 可选依赖：importorskip 目标必须在当前环境可导入 ===")
        print("  扫描 %d 处 importorskip，涉及 %d 个模块路径 / %d 个顶层包"
              % (len(targets), len(fulls), len(tops)))
        for m in missing:
            sites = ["%s:%d" % (r, ln) for r, ln, full, top in targets if full == m]
            print("  ❌ 缺 %s ⇒ 以下模块会在 collect 阶段静默消失：%s"
                  % (m, "; ".join(sites[:4])))
        for full, why in unknown:
            print("  ⚠️ 无法判定 %s：%s" % (full, why))
        for rel, ln, expr in nonliteral:
            print("  ⚠️ 非字面量 importorskip，静态无法判定：%s:%d %s" % (rel, ln, expr))
        for path, exc in unparsable:
            print("  ⚠️ 无法解析：%s %s" % (path, exc))
    if nonliteral or unparsable or unknown:
        if not quiet:
            print("结论：FAIL（无法判定，fail-closed）")
        return 2
    if missing:
        if not quiet:
            print("结论：FAIL（%d 个模块缺失）" % len(missing))
        return 1
    if not quiet:
        print("结论：PASS（%d 个模块路径齐全，收集集不会被可选依赖缩小）" % len(fulls))
    return 0


def selftest():
    """变异验证：缺包必红、注释/字符串诱饵不误判、非字面量必 fail-closed。"""
    import tempfile

    cases = []

    def run(files):
        with tempfile.TemporaryDirectory() as d:
            td = Path(d) / "tests"
            td.mkdir()
            for name, body in files.items():
                (td / name).write_text(body, encoding="utf-8", newline="\n")
            return check(td, quiet=True), td

    # ① 原件：只有真实存在的模块 ⇒ 绿
    rc, _ = run({"ok.py": 'import pytest\npytest.importorskip("pytest")\n'})
    cases.append(("原件：已装模块 ⇒ 绿", rc, 0))
    # ② 注入一个不存在的包 ⇒ 必红
    rc, _ = run({"bad.py": 'import pytest\npytest.importorskip("definitely_missing_pkg_xyz")\n'})
    cases.append(("变异：缺一个包 ⇒ 红", rc, 1))
    # ③ 注释与字符串诱饵 ⇒ 不误判（AST 判据的意义）
    rc, _ = run({"decoy.py": '# pytest.importorskip("fake_in_comment")\n'
                             'MSG = "pytest.importorskip(\'fake_in_string\')"\n'})
    cases.append(("注释/字符串诱饵不误判", rc, 0))
    # ④ 非字面量 ⇒ fail-closed RC=2
    rc, _ = run({"dyn.py": 'import pytest\nname = "pytest"\npytest.importorskip(name)\n'})
    cases.append(("非字面量 ⇒ fail-closed", rc, 2))
    # ⑤ 完整路径都存在 ⇒ 绿（PIL.Image / Crypto.Cipher.AES）
    rc, _ = run({"dotted.py": 'import pytest\npytest.importorskip("PIL.Image")\n'
                              'pytest.importorskip("Crypto.Cipher.AES")\n'})
    cases.append(("完整模块路径齐全 ⇒ 绿", rc, 0))
    # ⑤b 只验顶层会漏：父包在、子模块不在 ⇒ 必须红。
    # 这是第一版判据的真实缺陷，注入它必须变红，否则「完整路径」是空话。
    rc, _ = run({"sub.py": 'import pytest\npytest.importorskip("PIL.DefinitelyMissing")\n'})
    cases.append(("变异：父包在但子模块缺 ⇒ 红", rc, 1))
    # ⑤c 顶层包不存在且带子路径 ⇒ find_spec 抛 ModuleNotFoundError，也必须红
    rc, _ = run({"sub2.py": 'import pytest\n'
                            'pytest.importorskip("definitely_missing_pkg_xyz.Sub")\n'})
    cases.append(("变异：顶层缺失的带点路径 ⇒ 红", rc, 1))
    # ⑥ 反向：把缺包那行改成已装模块 ⇒ 回绿（证明因果方向，不是恒红）
    rc, _ = run({"bad.py": 'import pytest\npytest.importorskip("pytest")\n'})
    cases.append(("反向：换回已装模块 ⇒ 回绿", rc, 0))
    # ⑦ 解析失败 ⇒ fail-closed
    rc, _ = run({"broken.py": 'def f(:\n    pass\n'})
    cases.append(("语法坏文件 ⇒ fail-closed", rc, 2))

    failed = 0
    for label, got, want in cases:
        ok = got == want
        print("  [%s] %-36s got=%s want=%s" % ("OK" if ok else "FAIL", label, got, want))
        failed += 0 if ok else 1
    print("可选依赖门禁变异自测：%d/%d" % (len(cases) - failed, len(cases)))
    return 0 if failed == 0 else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="importorskip 可选依赖不得静默缩小收集集")
    ap.add_argument("--selftest", action="store_true", help="跑变异验证并退出")
    ap.add_argument("--list", action="store_true", help="只列目标模块，不判环境")
    ap.add_argument("--tests-dir", default=str(TESTS_DIR))
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.list:
        targets, _, _ = _scan(args.tests_dir)
        for rel, ln, full, top in targets:
            print("%s:%d\t%s\t%s" % (rel, ln, full, top))
        return 0
    return check(args.tests_dir)


if __name__ == "__main__":
    sys.exit(main())
