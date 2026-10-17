#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_binary_version 门禁回归测试 —— 防「查不到就报绿」与「落后也报绿」。

背景（2026-10-18 实测）：交付包里躺着三份互不相同的 exe，没有一份是当前 HEAD
构建（09-04 的 74abc04+dirty、09-07 的 4eb753a、09-30 的 344e5bd），
单看文件名/大小完全看不出来 —— 只能从二进制内嵌的 Go buildinfo 读出来。

本测试锁三面：
  · 正向：commit == HEAD、无 dirty → 必须 rc=0；
  · 反向变异：旧提交 / +dirty / tag 版（无 commit）/ 无 buildinfo / 安装包解不出 payload
    → 必须 rc=1（防"改成恒绿"）；
  · 空洞绿：受管目录为空时，缺省只允许 rc=0 且**必须显式声明未核验**；
    打包链路带 --require-binaries 时必须 rc=1。

用法：
    python scripts/check_binary_version_test.py
退出码：0 = 门禁健康；1 = 门禁退化（有变异没被抓住）
"""
import contextlib
import io
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
GATE = os.path.join(HERE, "check_binary_version.py")

HEAD = "7d325df1dc9c9a0e1f2b3c4d5e6f7a8b9c0d1e2f"
OLD = "344e5bd7ddf61234567890abcdef1234567890ab"


def fake_exe(commit, dirty=False, tag=None):
    """构造一个只含 Go buildinfo 模块行的假二进制（解析器只认字节模式，够用）。"""
    if tag:
        ver = tag
    else:
        ver = "v1.7.28-0.20261017232921-%s%s" % (commit[:12], "+dirty" if dirty else "")
    return (b"\x7fELF\xff Go buildinf:\x08\x02" +
            b"path\tsecautomind-ai/cmd/server\n" +
            b"mod\tsecautomind-ai\t" + ver.encode() + b"\n")


def run(args, cwd=None):
    r = subprocess.run([sys.executable, GATE] + args, capture_output=True,
                       text=True, cwd=cwd)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


def make_root(files):
    root = tempfile.mkdtemp(prefix="binver_case_")
    for rel, data in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
    return root


@case("T1 当前 HEAD 构建 → PASS")
def t1():
    root = make_root({"installer/secautomind-ai.exe": fake_exe(HEAD)})
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 0, out
    assert "PASS" in out and "1 / 1" in out, out


@case("T2 旧提交（落后于源码）→ BLOCK")
def t2():
    root = make_root({"installer/secautomind-ai.exe": fake_exe(OLD)})
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 1, out
    assert "落后于源码" in out, out


@case("T3 脏树构建 +dirty → BLOCK")
def t3():
    root = make_root({"installer/secautomind-ai.exe": fake_exe(HEAD, dirty=True)})
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 1, out
    assert "dirty" in out, out


@case("T4 tag 版（无 commit，无法对齐）→ BLOCK")
def t4():
    root = make_root({"installer/secautomind-ai.exe": fake_exe(HEAD, tag="v1.7.28")})
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 1, out
    assert "伪版本" in out, out


@case("T5 解析不到 buildinfo（来路不明）→ BLOCK")
def t5():
    root = make_root({"installer/secautomind-ai.exe": b"MZ\x90\x00 not a go binary"})
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 1, out
    assert "buildinfo" in out, out


@case("T6 无受管二进制（缺省）→ SKIP 且显式声明未核验")
def t6():
    root = make_root({"README.md": b"x"})
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 0, out
    assert "SKIP" in out and "未核验" in out, out
    assert "PASS" not in out, out


@case("T7 无受管二进制 + --require-binaries → BLOCK")
def t7():
    root = make_root({"README.md": b"x"})
    rc, out = run(["--root", root, "--head", HEAD, "--require-binaries"])
    assert rc == 1, out
    assert "不能报通过" in out, out


@case("T8 历史快照（提交包_日期）旧提交 → 只登记不判")
def t8():
    root = make_root({
        "installer/secautomind-ai.exe": fake_exe(HEAD),
        "SecAutoMind_提交包_20260905/01_程序材料/secautomind-ai.exe": fake_exe(OLD, dirty=True),
    })
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 0, out
    assert "[HIST]" in out, out


@case("T9 安装包解不出 payload → 未核验即红（防假绿）")
def t9():
    # 文件名命中 Setup 约定但不是合法 NSIS 包：7z 解不出 → 无一项核验 → 必须红
    root = make_root({
        "installer/SecAutoMind-Setup-1.7.28-x64.exe": fake_exe(OLD),
    })
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 1, out
    assert "未核验" in out, out


@case("T10 裸 exe 新、安装包旧（本次事故形态）→ BLOCK")
def t10():
    # 用 shell 复制一个真实存在的旧 Setup 无法保证环境，这里用"两个受管件"表达同一语义：
    # 一个 HEAD、一个旧提交 —— 只要有一个落后就必须红。
    root = make_root({
        "installer/secautomind-ai.exe": fake_exe(HEAD),
        "installer/other-tool.exe": fake_exe(OLD),
    })
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 1, out
    assert "落后于源码" in out, out


@case("T11 --strict-unchecked：部分未能核验 → BLOCK（打包链路用）")
def t11():
    root = make_root({
        "installer/secautomind-ai.exe": fake_exe(HEAD),
        "installer/SecAutoMind-Setup-1.7.28-x64.exe": fake_exe(OLD),
    })
    rc, out = run(["--root", root, "--head", HEAD])
    assert rc == 0, out           # 缺省放过（裸 exe 已核验）
    rc2, out2 = run(["--root", root, "--head", HEAD, "--strict-unchecked"])
    assert rc2 == 1, out2         # 打包链路不放行
    assert "未能核验" in out2, out2


def main():
    failures = []
    for name, fn in CASES:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                fn()
            print("  [ok] %s" % name)
        except AssertionError as exc:
            failures.append((name, str(exc)[:400]))
            print("  [FAIL] %s" % name)
        except Exception as exc:  # noqa: BLE001
            failures.append((name, "%s: %s" % (type(exc).__name__, exc)))
            print("  [FAIL] %s（异常）" % name)

    print("\n二进制来源门禁自测：%d/%d 通过" % (len(CASES) - len(failures), len(CASES)))
    if failures:
        for name, msg in failures:
            print("\n--- %s\n%s" % (name, msg))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
