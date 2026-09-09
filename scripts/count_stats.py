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
                           encoding="utf-8", errors="ignore", timeout=120)
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


def test_packages_count():
    """统计**含至少一个 *_test.go 的包目录数**（磁盘统计，秒级、确定、不依赖跑测试）。

    为什么不用 `go test ./...` 数 ok 行：那要跑几分钟，且受磁盘/超时影响会漏数（本机已发生过
    C 盘满导致 10 包假 FAIL）。磁盘统计与 go test 的 ok 数一致（实测 28），但可复现得多。
    """
    pkgs = set()
    for base in ("internal", "cmd", "pkg", "test", "tests"):
        root = os.path.join(ROOT, base)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in {".git", "node_modules", "testdata"}]
            if any(f.endswith("_test.go") for f in filenames):
                pkgs.add(os.path.relpath(dirpath, ROOT).replace("\\", "/"))
    return len(pkgs)


def _find_go():
    """定位 go 可执行文件。

    不能直接写 "go" 依赖 PATH —— 本仓库的 Go 装在 .workbuddy/toolchain/ 下，
    PATH 里通常没有。旧实现因此**静默返回 null**，下游（门禁/材料）全部静默跳过该字段，
    这正是本项目明令禁止的「取不到真值就悄悄放过」失效模式（实测 go_packages 恒为 null）。
    """
    import shutil
    local = [os.path.join(ROOT, ".workbuddy", "toolchain", "go", "bin", "go.exe"),
             os.path.join(ROOT, ".workbuddy", "toolchain", "go", "bin", "go")]
    for p in local:
        if os.path.isfile(p):
            return p
    return shutil.which("go")


def go_packages_count():
    """统计 go list ./... 中可构建的包数（排除 ? 前缀的非构建项，输出容错解码）。

    旧实现用 Windows-cmd 语法 `go list ./... 2>nul | find /c /v ""` + `text=True`，
    在 Git Bash 下既失效又会因非 UTF-8 输出崩溃（go_packages 退化为 null）。
    改为显式 encoding/errors 并自行统计行数，跨 shell 一致。

    2026-09-09 再修：即便上面都对了，仍然恒返回 null —— 根因是 shell 里没有 go（PATH 未含
    工具链目录），异常被 `except: return None` 吞掉。现在显式定位 go，
    且**取不到就在 stderr 报警**，不再假装这个字段不存在。
    """
    go = _find_go()
    if not go:
        print("[WARN] 未找到 go 可执行文件，go_packages 无法统计（该字段将为 null，"
              "依赖它的口径检查会失败而非静默通过）", file=sys.stderr)
        return None
    try:
        r = subprocess.run([go, "list", "./..."], cwd=ROOT, shell=False,
                           capture_output=True, encoding="utf-8", errors="ignore",
                           timeout=240)
        if r.returncode != 0:
            print("[WARN] `go list ./...` 失败（rc=%d）：%s"
                  % (r.returncode, (r.stderr or "").strip()[:200]), file=sys.stderr)
            return None
        lines = [l.strip() for l in r.stdout.splitlines()
                 if l.strip() and not l.strip().startswith("?")]
        return len(lines)
    except Exception as e:
        print("[WARN] go_packages 统计异常：%s" % e, file=sys.stderr)
        return None


def builtin_tools_count():
    """统计 Go 内置 MCP 工具数（internal/mcp/builtin/constants.go 的 GetAllBuiltinTools 列表项）。

    与 tools/*.yaml 是两类不同来源，不重叠：
      - tools_yaml    = tools/ 目录下的 YAML 安全工具声明
      - builtin_tools = Go 代码注册的内置 MCP 工具（资产/知识库/webshell/批量任务/C2 等）
      - runtime_tools = 二者之和 = 运行时可用工具总数

    2026-09-08 修正：官网曾写 "140 运行时工具"，既非 90 也非 90+52=142，属三不管数字。
    现改为由本脚本产出 runtime_tools，杜绝手写漂移。
    """
    p = os.path.join(ROOT, "internal", "mcp", "builtin", "constants.go")
    if not os.path.isfile(p):
        return 0
    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
        src = fh.read()
    m = re.search(r"func\s+GetAllBuiltinTools\s*\(\s*\)\s*\[\]\s*string\s*\{(.*?)\n\}",
                  src, re.S)
    if not m:
        return 0
    items = [l.strip() for l in m.group(1).splitlines()
             if re.match(r"^Tool[A-Za-z0-9_]+,\s*$", l.strip())]
    return len(items)


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
    tools_yaml = _count_files("tools", ".yaml")
    builtin_tools = builtin_tools_count()
    data = {
        "head": _sh("git rev-parse --short HEAD") or "unknown",
        "tools_yaml": tools_yaml,
        "builtin_tools": builtin_tools,
        "runtime_tools": tools_yaml + builtin_tools,
        "agents_md": _count_files("agents", ".md"),
        "skills": _count_recursive("skills", "SKILL.md"),
        "roles_yaml": _count_files("roles", ".yaml"),
        "internal_dirs": len([d for d in os.listdir(os.path.join(ROOT, "internal"))
                              if os.path.isdir(os.path.join(ROOT, "internal", d))]),
        "go_packages": go_packages_count(),
        # 有测试的包数 != 总包数。材料里「N 包测试全绿」指的是前者（实测 28），
        # 而 go list ./... 是后者（41）。两者混用是历史漂移的又一来源，必须分开。
        "test_packages": test_packages_count(),
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
    print("  内置 MCP 工具        %d" % data["builtin_tools"])
    print("  运行时工具合计       %d  (= YAML %d + 内置 %d)"
          % (data["runtime_tools"], data["tools_yaml"], data["builtin_tools"]))
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
