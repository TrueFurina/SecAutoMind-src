#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecAutoMind 权威计数口径 · 单一真值源（Single Source of Truth）

背景（2026-09-06 教训）：
1. 当天计数口径漂移 3 次——ctfplatform P13→P14→P15 连续扩量，手工同步永远追不上。
2. 手工 grep 曾把 `RegisterSolver` 的**注释行**与**函数定义行**也计入求解器数：
   全包出现 137 次，其中真实注册调用只有 **135** 次（另 1 行注释 + 1 行 func 定义），
   导致 commit 宣称"137 求解器"实为虚报 2 个。

本脚本固化正确口径，杜绝这两类错误。

用法：
    python scripts/count_stats.py            # 人类可读
    python scripts/count_stats.py --json     # 机器可读（供 CI/文档生成）

铁律：所有对外材料（PPT / 速查卡 / 质检报告 / MEMORY.md）的数字必须来自本脚本输出，
禁止手写、禁止凭记忆。改代码后重跑本脚本刷新口径。
"""
import os
import re
import sys
import json
import subprocess
import hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 必须排除：.git/.workbuddy 内有 3 万+ 假 .go 副本，不排除会严重高估
EXCLUDE = {".git", ".workbuddy", "node_modules", "vendor", "dist", "build", "installer"}


def _sh(cmd):
    try:
        r = subprocess.run(cmd, cwd=ROOT, shell=True, capture_output=True,
                           text=True, timeout=120)
        return r.stdout.strip()
    except Exception:
        return ""


def _count_files(d, suffix):
    """统计目录下（非递归）指定后缀文件数。"""
    p = os.path.join(ROOT, d)
    if not os.path.isdir(p):
        return 0
    return len([f for f in os.listdir(p)
                if f.endswith(suffix) and os.path.isfile(os.path.join(p, f))])


def _count_recursive(d, filename):
    """递归统计目录下指定文件名的数量。"""
    p = os.path.join(ROOT, d)
    n = 0
    for dp, dn, fn in os.walk(p):
        dn[:] = [x for x in dn if x not in EXCLUDE]
        n += sum(1 for f in fn if f == filename)
    return n


def _regex_count(d, pattern, suffix=".go"):
    """递归统计目录下匹配正则的总出现次数（按行匹配，取每行全部命中）。"""
    p = os.path.join(ROOT, d)
    rx = re.compile(pattern)
    n = 0
    for dp, dn, fn in os.walk(p):
        dn[:] = [x for x in dn if x not in EXCLUDE]
        for f in fn:
            if not f.endswith(suffix):
                continue
            try:
                with open(os.path.join(dp, f), encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        n += len(rx.findall(line))
            except Exception:
                continue
    return n


def go_stats():
    go_files = test_files = 0
    non_test_lines = test_lines = 0
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [x for x in dn if x not in EXCLUDE]
        for f in fn:
            if not f.endswith(".go"):
                continue
            go_files += 1
            try:
                with open(os.path.join(dp, f), encoding="utf-8", errors="ignore") as fh:
                    n = sum(1 for _ in fh)
            except Exception:
                n = 0
            if f.endswith("_test.go"):
                test_files += 1
                test_lines += n
            else:
                non_test_lines += n
    return go_files, test_files, non_test_lines, test_lines


def exe_info():
    exe = os.path.join(ROOT, "secautomind-ai.exe")
    if not os.path.isfile(exe):
        return {"present": False}
    h = hashlib.md5()
    with open(exe, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return {
        "present": True,
        "md5": h.hexdigest(),
        "size_mib": round(os.path.getsize(exe) / 1048576, 1),
        "mod_version": _sh("go version -m secautomind-ai.exe | findstr /R \"^\\smod\\s\"") or "",
    }


def main():
    go_files, test_files, non_test, test = go_stats()
    solvers = _regex_count("internal/ctfplatform", r"RegisterSolver\(SolverEntry\{")
    im_adapters = _regex_count("internal/robot", r"^func Start[A-Za-z]*\(")
    data = {
        "head": _sh("git rev-parse --short HEAD") or "unknown",
        "tools_yaml": _count_files("tools", ".yaml"),
        "agents_md": _count_files("agents", ".md"),
        "skills": _count_recursive("skills", "SKILL.md"),
        "roles_yaml": _count_files("roles", ".yaml"),
        "internal_dirs": len([d for d in os.listdir(os.path.join(ROOT, "internal"))
                              if os.path.isdir(os.path.join(ROOT, "internal", d))]),
        "go_packages": int(_sh("go list ./... 2>nul | find /c /v \"\"") or 0) or None,
        "go_files": go_files,
        "test_files": test_files,
        "non_test_lines": non_test,
        "test_lines": test,
        "total_lines": non_test + test,
        "ctf_solvers": solvers,
        "im_adapters": im_adapters,
        "exe": exe_info(),
    }

    if "--json" in sys.argv:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    e = data["exe"]
    print("=" * 62)
    print("SecAutoMind 权威计数口径（单一真值源）  HEAD=%s" % data["head"])
    print("=" * 62)
    print("  工具 YAML            %d" % data["tools_yaml"])
    print("  Agent (agents/*.md)  %d" % data["agents_md"])
    print("  技能包 (SKILL.md)    %d" % data["skills"])
    print("  RBAC 角色            %d" % data["roles_yaml"])
    print("  internal 子目录      %d" % data["internal_dirs"])
    if data["go_packages"]:
        print("  Go 包 (go list)      %d" % data["go_packages"])
    print("  Go 文件              %d" % data["go_files"])
    print("  测试文件             %d" % data["test_files"])
    print("  非测试行             %s" % format(data["non_test_lines"], ","))
    print("  测试行               %s" % format(data["test_lines"], ","))
    print("  总行数               %s" % format(data["total_lines"], ","))
    print("  CTF 求解器（真实注册）%d" % data["ctf_solvers"])
    print("  IM 适配器 (func Start*)%d" % data["im_adapters"])
    if e["present"]:
        print("  交付 exe             md5=%s (%s MiB)" % (e["md5"], e["size_mib"]))
        if e["mod_version"]:
            print("                       %s" % e["mod_version"])
    else:
        print("  交付 exe             (未找到 secautomind-ai.exe)")
    print("=" * 62)
    print("口径纪律：材料数字一律引用本脚本输出；求解器数=RegisterSolver(SolverEntry{ 真实调用数，")
    print("          不含注释行与 func 定义行（历史误把 137 当真值，实际 135）。")


if __name__ == "__main__":
    main()
