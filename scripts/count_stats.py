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


_CTF_PKG = os.path.join("internal", "ctfplatform")
_CH_RET = re.compile(r'return\s+\[\]string\{"[\u4e00-\u9fff]')
_FLAG_BUILD = re.compile(r'"flag\{|"picoCTF\{|"BZHCTF\{|"[A-Za-z0-9_]{2,20}\{"')
_IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def ctf_solver_breakdown():
    """把「已注册 CTF 求解器」拆成 真求解器 / 纯检测器 两类（2026-10-03 口径拆分）。

    为什么必须拆（诚实性，非注水指控）：
      176 个 `RegisterSolver` 注册项里，有一批的 Solver 实现**只做关键词/魔数检测**，
      返回的是硬编码中文提示（如 `"攻击链: TTP战术技术程序"`），**永远不可能等于真 flag**
      （flag 为 ASCII，且基准 55/55 真题 flag 均带 `{}` 外壳）。
      它们在 `TestAllRegisteredSolversActuallyExecute` 下算「已被执行」，
      但「注册了」≠「能解题」——两个口径混在一起会让「176 个求解器全部实跑通过」
      被读成「176 个都能解题」，抽到一个检测器即穿帮。故在真值源里分开计数。

    判据（可复现，只读，与 .workbuddy/ops/audit_solver_inflation.py 同源）：
      1. 建包内函数表 + 调用图；
      2. **叶子诊断函数** = 其全部 `return []string{` 均为硬编码中文标签、且函数体不调 scanFlags；
      3. 某注册求解器的**传递闭包**触及叶子诊断函数，且闭包内无任何「产 flag 能力」
         （无 scanFlags、不构造 `xxx{...}` 字面量）→ 判为**纯检测器**。

    返回 (real_solvers, detectors)；目录缺失返回 (None, None)（调用方 fail-closed 留痕）。
    """
    pkg = os.path.join(ROOT, _CTF_PKG)
    if not os.path.isdir(pkg):
        return None, None

    src_all = {}
    for f in os.listdir(pkg):
        if f.endswith(".go") and not f.endswith("_test.go"):
            try:
                with open(os.path.join(pkg, f), encoding="utf-8", errors="ignore") as fh:
                    src_all[f] = fh.read()
            except OSError:
                continue

    funcs = {}
    for src in src_all.values():
        idx = [m.start() for m in re.finditer(r"(?m)^func\s", src)] + [len(src)]
        for i in range(len(idx) - 1):
            chunk = src[idx[i]:idx[i + 1]]
            m = re.match(r"func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\s*\(", chunk)
            if m:
                funcs.setdefault(m.group(1), chunk)

    def _all_chinese_returns(body):
        rets = re.findall(r"return\s+\[\]string\{[^\n]*", body)
        return bool(rets) and all(_CH_RET.match(r) for r in rets)

    leaves = {fn for fn, b in funcs.items()
              if _all_chinese_returns(b) and "scanFlags(" not in b}

    callees = {fn: {i for i in _IDENT.findall(b) if i in funcs and i != fn}
               for fn, b in funcs.items()}

    def _closure(fn):
        seen, stack = set(), [fn]
        while stack:
            for c in callees.get(stack.pop(), ()):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return seen

    total = detectors = 0
    for src in src_all.values():
        for m in re.finditer(r"RegisterSolver\(SolverEntry\{(.*?)\}\)", src, re.S):
            total += 1
            sv = re.search(r"Solver:\s*([A-Za-z0-9_]+)", m.group(1))
            fn = sv.group(1) if sv else None
            # 解析不到实现函数 -> 保守算「真求解器」，不轻易扣减
            if not fn or fn not in funcs:
                continue
            cl = _closure(fn) | {fn}
            if not (cl & leaves):
                continue
            closure_src = "\n".join(funcs.get(x, "") for x in cl)
            if ("scanFlags(" in closure_src) or _FLAG_BUILD.search(closure_src):
                continue
            detectors += 1
    return total - detectors, detectors


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


def _go_env():
    """构造 go 子进程环境。

    本机坑（2026-09-16 实锤，比之前记录的三个坑更隐蔽）：
      从 WorkBuddy / Git-Bash 启动的 shell 里**没有 `%AppData%`**，于是 go 找不到自己的
      GOENV 配置文件（`%AppData%\\go\\env`，里面就写着 `GOPATH=D:\\DevCache\\gopath`
      `GOPROXY=https://goproxy.cn,direct` `GOTOOLCHAIN=local`），GOPATH 回落到默认的
      `C:\\Users\\<u>\\go`（模块缓存是空的）→ 所有 go 命令都报
      "go: downloading ..." + "module lookup disabled by GOPROXY=off"。
      症状极易被误判成"模块缓存被删/网络不可用"，实际只需补一个环境变量。

    实测：仅补 `APPDATA` 后 `go list ./...` 由 rc=1 变 **rc=0（42 包）**，
    `go build ./cmd/server` 也恢复 rc=0。
    """
    env = dict(os.environ)
    if os.name == "nt" and not env.get("APPDATA"):
        home = env.get("USERPROFILE") or os.path.expanduser("~")
        cand = os.path.join(home, "AppData", "Roaming")
        if os.path.isdir(cand):
            env["APPDATA"] = cand
    return env


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
        r = subprocess.run([go, "list", "./..."], cwd=ROOT, shell=False, env=_go_env(),
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


def _exe_vcs(path):
    r"""从 Go 二进制内嵌 build info 提取 vcs.revision / vcs.time。

    不依赖外部 `go` 命令：旧实现是 `go version -m ... | findstr /R "^\smod\s"`，
    这是 Windows CMD 专用语法，在 bash 下静默取空——交付 exe 的关键版本信息
    （评审最看重的「这个二进制对应哪个 commit」）就在报告里丢了一整个版本。
    """
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return "", ""

    def grab(key):
        idx = blob.find(key.encode())
        if idx < 0:
            return ""
        out = []
        for b in blob[idx + len(key):idx + len(key) + 64]:
            if b in (0x09, 0x0a, 0x0d, 0x00):  # \t \n \r NUL 即终止
                break
            if 32 <= b < 127:
                out.append(chr(b))
        return "".join(out)

    return grab("vcs.revision="), grab("vcs.time=")


def exe_info():
    exe = os.path.join(ROOT, "secautomind-ai.exe")
    if not os.path.isfile(exe):
        return {"present": False}
    h = hashlib.md5()
    with open(exe, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    rev, tm = _exe_vcs(exe)
    return {
        "present": True,
        "md5": h.hexdigest(),
        "size_mib": round(os.path.getsize(exe) / 1048576, 1),
        "vcs_revision": rev,
        "vcs_time": tm,
        "mod_version": ("vcs %s @ %s" % (rev[:12], tm)) if rev else "",
    }


def main():
    go_files, test_files, non_test, test = go_stats()
    solvers = _regex_count("internal/ctfplatform", r"RegisterSolver\(SolverEntry\{")
    real_solvers, solvers_detectors = ctf_solver_breakdown()
    if real_solvers is None:
        print("[WARN] ctf_solver_breakdown 取不到真值（internal/ctfplatform 缺失？）"
              "——ctf_real_solvers/ctf_detectors 将为 null，依赖它的口径检查应失败而非静默通过",
              file=sys.stderr)
    elif real_solvers + solvers_detectors != solvers:
        # 解析口径与正则口径不一致时必须暴露，杜绝两个数各说各话
        print("[WARN] 求解器拆分与注册总数不一致：real=%d + detector=%d != total=%d"
              % (real_solvers, solvers_detectors, solvers), file=sys.stderr)
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
        # 口径拆分（2026-10-03）：solvers = 真求解器 + 纯检测器，三者自洽。
        # 材料若宣称「N 个求解器全实跑」必须区分这两类，见 ctf_solver_breakdown 文档。
        "ctf_real_solvers": real_solvers,
        "ctf_detectors": solvers_detectors,
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
    if data["ctf_real_solvers"] is not None:
        print("    ├─ 真求解器        %d  (可产出 flag 外形)" % data["ctf_real_solvers"])
        print("    └─ 纯检测器        %d  (仅关键词/魔数检测，输出中文提示，永不为真 flag)"
              % data["ctf_detectors"])
    print("  IM 适配器 (func Start*)%d" % data["im_adapters"])
    if e["present"]:
        print("  交付 exe             md5=%s (%s MiB)" % (e["md5"], e["size_mib"]))
        if e.get("vcs_revision"):
            print("                       内嵌 vcs.revision=%s (vcs.time=%s)"
                  % (e["vcs_revision"][:12], e.get("vcs_time", "")))
        elif e["mod_version"]:
            print("                       %s" % e["mod_version"])
    else:
        print("  交付 exe             (未找到 secautomind-ai.exe)")
    print("=" * 62)
    print("口径纪律：材料数字一律引用本脚本输出；求解器数=RegisterSolver(SolverEntry{ 真实调用数，")
    print("          不含注释行与 func 定义行（历史误把 137 当真值，实际 135）。")


if __name__ == "__main__":
    main()
