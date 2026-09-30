#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_line_endings.py 的回归 + 变异验证（不依赖 pytest，纯 stdlib）。

门禁自身必须有回归测试，关键门禁必须有**变异验证**：
    —— 故意注入坏行尾，门禁必须变红；否则它只是个摆设。

覆盖用例：
    T1 目录内 .sh=LF / .bat=CRLF（合规）        → exit 0
    T2 变异：.sh 写成 CRLF                      → exit 1 且点名该文件
    T3 变异：.bat 写成 LF                       → exit 1
    T4 变异：.sh 为混合行尾（CRLF+孤立LF）      → exit 1
    T5 目录不存在                               → exit 2（fail-closed，绝不当"通过"）
    T6 二进制 .sh（含 NUL）                     → 跳过，exit 0（不误报也不崩）
    T7 真实仓库（git 工作树）当前行尾           → exit 0
    T8 .gitattributes 与内置规则表一致          → exit 0
    T9 变异：篡改 .gitattributes 的 eol 值      → --check-attr-sync 必须 exit 1（随后恢复并复验）

用法：
    python scripts/check_line_endings_test.py
    echo $?     # 0 = 全部通过
"""
import os
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECKER = os.path.join(HERE, "check_line_endings.py")
GITATTRIBUTES = os.path.join(ROOT, ".gitattributes")

_results = []


def run(args):
    """跑门禁，返回 (exit_code, stdout)。"""
    proc = subprocess.run(
        [sys.executable, CHECKER] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def check(name, cond, detail=""):
    _results.append((name, bool(cond), detail))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name,
                         "" if cond else "  <- " + detail))


LF_SH = b"#!/bin/sh\r\nset -e\r\necho hi\r\n".replace(b"\r\n", b"\n")
CRLF_SH = b"#!/bin/sh\r\nset -e\r\necho hi\r\n"
LF_BAT = b"@echo off\necho hi\n"
CRLF_BAT = b"@echo off\r\necho hi\r\n"


def case_compliant(base):
    d = os.path.join(base, "ok")
    write_bytes(os.path.join(d, "run.sh"), LF_SH)
    write_bytes(os.path.join(d, "start.bat"), CRLF_BAT)
    rc, out = run(["--dir", d])
    check("T1 合规目录 → exit 0", rc == 0, "rc=%d\n%s" % (rc, out))


def case_bad_sh(base):
    d = os.path.join(base, "badsh")
    write_bytes(os.path.join(d, "run.sh"), CRLF_SH)
    rc, out = run(["--dir", d])
    check("T2 变异：.sh=CRLF → exit 1 且点名",
          rc == 1 and "run.sh" in out, "rc=%d\n%s" % (rc, out))


def case_bad_bat(base):
    d = os.path.join(base, "badbat")
    write_bytes(os.path.join(d, "start.bat"), LF_BAT)
    rc, out = run(["--dir", d])
    check("T3 变异：.bat=LF → exit 1",
          rc == 1 and "start.bat" in out, "rc=%d\n%s" % (rc, out))


def case_mixed(base):
    d = os.path.join(base, "mixed")
    write_bytes(os.path.join(d, "a.sh"), b"#!/bin/sh\r\n# x\necho hi\n")
    rc, out = run(["--dir", d])
    check("T4 变异：混合行尾 → exit 1",
          rc == 1 and "混合行尾" in out, "rc=%d\n%s" % (rc, out))


def case_missing(base):
    rc, out = run(["--dir", os.path.join(base, "does-not-exist")])
    check("T5 目录不存在 → exit 2（fail-closed）", rc == 2, "rc=%d" % rc)


def case_binary(base):
    d = os.path.join(base, "bin")
    write_bytes(os.path.join(d, "weird.sh"), b"\x00\x01\x02\r\n\x00junk")
    rc, out = run(["--dir", d])
    check("T6 二进制 .sh → 跳过且 exit 0", rc == 0 and "跳过二进制" in out,
          "rc=%d\n%s" % (rc, out))


def case_repo():
    rc, out = run([])
    check("T7 真实仓库当前行尾 → exit 0", rc == 0, "rc=%d\n%s" % (rc, out))


def case_attr_ok():
    rc, out = run(["--check-attr-sync"])
    check("T8 .gitattributes 与规则表一致 → exit 0", rc == 0,
          "rc=%d\n%s" % (rc, out))


def case_attr_mutation():
    """变异：把 .gitattributes 里 *.sh 的 eol 改成 crlf，门禁必须变红；随后恢复并复验。"""
    if not os.path.exists(GITATTRIBUTES):
        check("T9 变异：篡改 .gitattributes → exit 1", False, "缺少 .gitattributes")
        return
    with open(GITATTRIBUTES, "rb") as fh:
        backup = fh.read()
    try:
        tampered = backup.replace(b"*.sh    text eol=lf", b"*.sh    text eol=crlf")
        if tampered == backup:
            check("T9 变异：篡改 .gitattributes → exit 1", False,
                  "未找到可篡改的 '*.sh    text eol=lf' 行（规则写法变了？）")
            return
        with open(GITATTRIBUTES, "wb") as fh:
            fh.write(tampered)
        rc, out = run(["--check-attr-sync"])
        check("T9 变异：篡改 .gitattributes → exit 1", rc == 1 and "*.sh" in out,
              "rc=%d\n%s" % (rc, out))
    finally:
        with open(GITATTRIBUTES, "wb") as fh:
            fh.write(backup)
    rc2, out2 = run(["--check-attr-sync"])
    check("T9b 恢复后复验 → exit 0", rc2 == 0, "rc=%d\n%s" % (rc2, out2))


def main():
    print("=" * 62)
    print("check_line_endings 回归 + 变异验证")
    print("=" * 62)
    with tempfile.TemporaryDirectory(prefix="le_test_") as base:
        case_compliant(base)
        case_bad_sh(base)
        case_bad_bat(base)
        case_mixed(base)
        case_missing(base)
        case_binary(base)
    case_repo()
    case_attr_ok()
    case_attr_mutation()

    failed = [n for n, ok, _ in _results if not ok]
    print("-" * 62)
    print("  合计 %d 用例，通过 %d，失败 %d" % (len(_results),
                                              len(_results) - len(failed), len(failed)))
    if failed:
        for n in failed:
            print("  [FAIL] %s" % n)
        return 1
    print("  [PASS] 门禁回归 + 变异验证全过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
