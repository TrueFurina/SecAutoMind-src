#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_docs_lint.py 的回归 + 变异验证（不依赖 pytest，纯 stdlib）。

门禁自身必须有回归测试；关键判据必须有**变异验证**——
故意注入坏文档，门禁必须变红；否则它只是个摆设。

覆盖用例（每条都在独立 tempfile 夹具根上跑真实门禁子进程）：
    T1 合规文档（围栏闭合 / 链接有效 / 脚本引用存在）        → exit 0
    T2 变异：代码块缺开头围栏                                  → exit 1 且点名该文件
    T3 变异：本地链接指向不存在文件                            → exit 1
    T4 变异：引用不存在的 scripts/xxx.sh                       → exit 1
    T5 脚本引用真实存在（夹具内造 scripts/foo.sh）             → exit 0
    T6 英文文档有同名中文对应                                  → exit 0
    T7 变异：英文文档无中文对应                                → exit 1
    T8 历史档豁免：带 CALIBER-SNAPSHOT 的文档引用失踪脚本      → exit 0（引用不查历史档）
    T9 fail-closed：--root 指向不存在目录                      → exit 2（绝不当"通过"）
    T10 真实仓库当前状态（回归基线，防夹具与真库脱节）         → exit 0

用法：
    python scripts/check_docs_lint_test.py
    echo $?     # 0 = 全部通过
"""
import os
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECKER = os.path.join(HERE, "check_docs_lint.py")

_results = []


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def _run(root):
    proc = subprocess.run(
        [sys.executable, CHECKER, "--root", root],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _mkroot():
    return tempfile.mkdtemp(prefix="docslint_")


def _compliant(root):
    """写一份完全合规的最小文档树。"""
    _write(root, "docs/a.md", "# A\n\n```bash\necho hi\n```\n\n见 [B](b.md)。\n")
    _write(root, "docs/b.md", "# B\n")


def check(name, cond, detail=""):
    _results.append((name, bool(cond), detail))


def main():
    # T1 合规 → 0
    r = _mkroot()
    try:
        _compliant(r)
        rc, _ = _run(r)
        check("T1 合规文档 → exit 0", rc == 0, f"rc={rc}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T2 变异：缺开头围栏 → 1 且点名
    r = _mkroot()
    try:
        _write(r, "docs/a.md", "# A\n\necho hi\n```\n")
        rc, out = _run(r)
        check("T2 变异：围栏不闭合 → exit 1 且点名",
              rc == 1 and "a.md" in out and "闭合" in out, f"rc={rc}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T2B 变异：多出一个错位结尾围栏（实测 runbook 形态，表面平衡但围栏数为奇数）→ 1
    r = _mkroot()
    try:
        _write(r, "docs/a.md", "# A\n\necho hi\n```\n```bash\necho x\n```\n")
        rc, out = _run(r)
        check("T2B 变异：错位结尾围栏 → exit 1 且点名",
              rc == 1 and "a.md" in out and "奇数" in out, f"rc={rc}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T3 变异：断链 → 1
    r = _mkroot()
    try:
        _write(r, "docs/a.md", "# A\n\n见 [X](nope.md)。\n")
        rc, out = _run(r)
        check("T3 变异：本地链接断裂 → exit 1 且点名",
              rc == 1 and "不存在的路径" in out, f"rc={rc}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T4 变异：引用不存在的脚本 → 1
    r = _mkroot()
    try:
        _compliant(r)
        _write(r, "docs/c.md", "# C\n\n运行 `bash scripts/ghost.sh`。\n")
        rc, out = _run(r)
        check("T4 变异：引用失踪脚本 → exit 1 且点名",
              rc == 1 and "ghost.sh" in out, f"rc={rc}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T5 脚本引用真实存在 → 0
    r = _mkroot()
    try:
        _compliant(r)
        _write(r, "scripts/foo.sh", "#!/usr/bin/env bash\necho ok\n")
        _write(r, "docs/c.md", "# C\n\n运行 `bash scripts/foo.sh`。\n")
        rc, out = _run(r)
        check("T5 脚本引用存在 → exit 0", rc == 0, f"rc={rc} {out[-120:]}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T6 英文有中文对应 → 0
    r = _mkroot()
    try:
        _compliant(r)
        _write(r, "docs/zh-CN/g.md", "# G\n")
        _write(r, "docs/en-US/g.md", "# G\n")
        rc, _ = _run(r)
        check("T6 英文有中文对应 → exit 0", rc == 0, f"rc={rc}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T7 变异：英文无中文对应 → 1
    r = _mkroot()
    try:
        _compliant(r)
        _write(r, "docs/en-US/orphan.md", "# Orphan\n")
        rc, out = _run(r)
        check("T7 变异：英文缺中文 → exit 1 且点名",
              rc == 1 and "orphan.md" in out, f"rc={rc}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T8 历史档豁免：带 SNAPSHOT 标记 + 失踪脚本引用 → 0
    r = _mkroot()
    try:
        _compliant(r)
        _write(r, "docs/old.md",
               "> CALIBER-SNAPSHOT 时点快照\n\n# 旧记录\n\n当时用 `scripts/legacy.sh`。\n")
        rc, out = _run(r)
        check("T8 历史档豁免脚本引用 → exit 0", rc == 0, f"rc={rc} {out[-160:]}")
    finally:
        shutil.rmtree(r, ignore_errors=True)

    # T9 fail-closed：root 不存在 → 2
    rc, _ = _run(os.path.join(tempfile.gettempdir(), "docslint_definitely_missing_xyz"))
    check("T9 root 不存在 → exit 2（fail-closed）", rc == 2, f"rc={rc}")

    # T10 真实仓库回归基线 → 0
    rc, out = _run(ROOT)
    check("T10 真实仓库当前 → exit 0", rc == 0, f"rc={rc} {out[-200:]}")

    # 汇总
    print("=" * 70)
    print("check_docs_lint.py 回归 + 变异验证")
    print("=" * 70)
    failed = 0
    for name, ok, detail in _results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + ("" if ok else f"   ({detail})"))
        if not ok:
            failed += 1
    print("=" * 70)
    print(f"结论：{'PASS' if failed == 0 else 'FAIL'} —— "
          f"{len(_results) - failed}/{len(_results)} 通过。")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
