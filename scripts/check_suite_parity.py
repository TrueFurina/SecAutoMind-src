#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨集双语言 parity 门禁（台账驱动，覆盖【2】～【22】的「Python == Go」宣称）。

## 为什么需要（2026-10-16 实测动机，承接 PR #35）

``data/ctf_benchmark/run_all_benchmarks.py`` 的对外汇总里，【1】～【22】每个基准集都打印
一句硬编码的「Python xxx == Go xxx」宣称，但**长期只有【1】静态集**真的接了逐题机验
（``scripts/check_benchmark_parity.py``）。PR #35 已在脚注留痕「【2】～【8】未接线」——
**而本次实测发现该留痕本身即失真**：实际未接线的是【2】～【22】（21 集），脚注漏报 14 集。

即同一形态第三次出现：**宣称进了对外汇总，却没人接线，连「未接线的范围」都靠手写漂移**
（AGENTS.md 第八条「定义齐全 ≠ 接线」）。

本门禁把范围这件事**从手写改成台账驱动 + 覆盖度自证**：

    data/ctf_benchmark/parity_registry.json   ← 单一真值源（每集 parity 状态 + reason）
      ├─ run_all_benchmarks.py 据此生成脚注（结构上不可能再写错范围）
      └─ 本脚本据此逐集跑 parity（已接线的集真跑三路/两路比对）

## 判据（纯函数 + fail-closed，均非恒真）

| # | 判据 | 条件 | 结论 |
|---|---|---|---|
| 0 | 台账覆盖度自证 | run_all_benchmarks.py 汇总里的【N】集合 ≠ 台账 id 集合 | FAIL（漏登记 = 零覆盖也可能显 PASS） |
| 1 | id 连续无洞 | 台账 id 非 1..N 连续 | FAIL（拓扑漂移） |
| 2 | wired 集必须带判据 | parity=wired 却缺 python_hit_re/go_hit_re（且非静态集） | FAIL（声称接线却无判据 = 哑门禁） |
| 3 | 逐题集合一致 | 某 wired 集 Python 命中集 ≠ Go 命中集（双向） | FAIL（超前=注水方向 / 滞后=宣称不成立） |
| 4 | 空集 fail-closed | 任一侧命中集为空 | FAIL（0 命中 ⇒ 无差异 ⇒ 恒绿，同型空洞绿） |
| 5 | 子进程成功 | judge/go test 非零退出 | FAIL（跑挂了不许蒙混） |

阈值语义 = **一致性 + 台账覆盖度**，不是目标值：判据里没有「必须命中 N 题」这类硬编码，
数字变好不会让门禁漂绿。

## 用法
    python scripts/check_suite_parity.py            # 报数（不判定，exit 0）
    python scripts/check_suite_parity.py --check    # 门禁断言（exit 1 = 红）
    python scripts/check_suite_parity.py --go <path>
    python scripts/check_suite_parity.py --only ecdsa,padding_oracle   # 只跑指定集

环境变量：``SECAUTOMIND_GO`` 可指定 go（CI 用 PATH 上的 go，无需设置）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(REPO_ROOT, "data", "ctf_benchmark", "parity_registry.json")
SUMMARY_PATH = os.path.join(REPO_ROOT, "data", "ctf_benchmark", "run_all_benchmarks.py")
BENCH_DIR = os.path.join(REPO_ROOT, "data", "ctf_benchmark")
PKG = "./internal/ctfplatform/"

# run_all_benchmarks.py 汇总里的集编号行： print("【N】...")
SUMMARY_ID_RE = re.compile(r'print\(\s*["\']【(\d+)】')


# ── 工具链探测（与 check_benchmark_parity.py 同源，勿各写一份）────────

def find_go(explicit=None):
    """定位 go 可执行文件；找不到返回 None（由调用方 fail-closed）。"""
    cands = []
    if explicit:
        cands.append(explicit)
    env_go = os.environ.get("SECAUTOMIND_GO")
    if env_go:
        cands.append(env_go)
    cands += [
        os.path.join(REPO_ROOT, ".workbuddy", "toolchain", "go", "bin", "go.exe"),
        os.path.join(REPO_ROOT, ".workbuddy", "toolchain", "go", "bin", "go"),
    ]
    w = shutil.which("go")
    if w:
        cands.append(w)
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA"),
                     os.environ.get("ProgramFiles(x86)")):
            if base:
                cands.append(os.path.join(base, "Go", "bin", "go.exe"))
                cands.append(os.path.join(base, "Programs", "Go", "bin", "go.exe"))
        cands.append(os.path.join("C:\\", "Go", "bin", "go.exe"))
    else:
        cands += ["/usr/local/go/bin/go", "/usr/lib/go/bin/go", "/snap/bin/go"]
    for c in cands:
        if not c or not os.path.isfile(c):
            continue
        try:
            r = subprocess.run([c, "version"], capture_output=True, text=True, timeout=90)
        except Exception:
            continue
        if r.returncode == 0:
            return c
    return None


def go_env():
    """构造 go 子进程环境（本机缺 %AppData% 会让 go 命令失效，见 AGENTS.md 第五条）。"""
    env = dict(os.environ)
    if os.name == "nt" and not env.get("APPDATA"):
        home = env.get("USERPROFILE") or os.path.expanduser("~")
        cand = os.path.join(home, "AppData", "Roaming")
        if os.path.isdir(cand):
            env["APPDATA"] = cand
    return env


# ── 判据（纯函数，供门禁与变异自测共用）─────────────────────────

def parse_hits(text, pattern):
    """按 pattern（含单捕获组 = 命中 id）从文本抽命中 id 集合（纯函数）。"""
    rx = re.compile(pattern)
    out = set()
    for line in (text or "").splitlines():
        m = rx.search(line)
        if m:
            out.add(m.group(1))
    return out


def coverage_violations(registry_ids, summary_ids):
    """台账覆盖度自证 + id 连续性（纯函数）。返回 violations 列表。"""
    v = []
    if not summary_ids:
        v.append("覆盖度自证失败：无法从 run_all_benchmarks.py 解析出任何【N】集编号"
                 "（判据退化为恒真）—— 疑似汇总格式被改，须同步本门禁的解析式")
    missing = sorted(summary_ids - registry_ids)
    extra = sorted(registry_ids - summary_ids)
    if missing:
        v.append("台账漏登记汇总里存在的集（漏登记=该集即使零覆盖也显 PASS）：%s" % missing)
    if extra:
        v.append("台账登记了汇总里不存在的集（悬空条目）：%s" % extra)
    if registry_ids:
        want = set(range(1, max(registry_ids) + 1))
        holes = sorted(want - registry_ids)
        if holes:
            v.append("台账 id 不连续（拓扑漂移）：缺 %s" % holes)
    return v


def wired_spec_violations(suites):
    """wired 集必须有可执行判据（除静态集由独立脚本负责）。纯函数。"""
    v = []
    for s in suites:
        if s.get("parity") != "wired":
            continue
        if s.get("wired_by") == "scripts/check_benchmark_parity.py":
            continue  # 三路静态集走独立脚本
        if not (s.get("python_hit_re") and s.get("go_hit_re") and s.get("go_tests")):
            v.append("集【%s】%s 标 parity=wired 却缺 python_hit_re/go_hit_re/go_tests"
                     "（哑门禁：声称接线却无判据）" % (s.get("id"), s.get("key")))
    return v


def compare_suite(label, py_hits, go_hits):
    """单个集的逐题集合一致性（纯函数）。返回 violations 列表。"""
    v = []
    if not py_hits:
        v.append("[%s] 空洞绿风险：Python 侧命中集合为空——疑似解析失败/基准被清空，禁止判绿" % label)
    if not go_hits:
        v.append("[%s] 空洞绿风险：Go 侧命中集合为空——疑似解析失败/工具链缺失，禁止判绿" % label)
    ahead = sorted(py_hits - go_hits)
    behind = sorted(go_hits - py_hits)
    if ahead:
        v.append("[%s] Python 镜像宣称 Go 生产侧做不到的命中（注水方向）：%s" % (label, ", ".join(ahead)))
    if behind:
        v.append("[%s] Go 侧命中 Python 镜像没有的题（『双语言互相印证』宣称不成立）：%s"
                 % (label, ", ".join(behind)))
    return v


# ── 取数 ───────────────────────────────────────────────────────

def load_registry():
    with open(REGISTRY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def summary_ids():
    """从 run_all_benchmarks.py 抽【N】集编号（机验覆盖度用，勿让它恒真）。"""
    try:
        with open(SUMMARY_PATH, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return set()
    return {int(x) for x in SUMMARY_ID_RE.findall(text)}


# 所有 judge 只跟本机靶场通信；环境里若有 HTTP_PROXY/HTTPS_PROXY（本机实测有本地代理），
# urllib/requests 会把发往 127.0.0.1 的请求也送进代理 → 超时 → judge 退出码 1，
# 而 curl --noproxy 直连是通的（2026-10-24 实锤：parity 的 [web_hint] 就是这样假红的）。
# 统一在 judge 子进程环境里剥掉代理。
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
               "http_proxy", "https_proxy", "all_proxy")


def judge_env():
    env = {k: v for k, v in os.environ.items() if k not in _PROXY_VARS}
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost,::1,169.254.169.254"
    return env


def run_python_hits(python_exe, judge, pattern, timeout=600):
    path = os.path.join(BENCH_DIR, judge)
    if not os.path.exists(path):
        return None, 1, "judge 缺失: %s" % judge
    try:
        r = subprocess.run([python_exe, path], cwd=REPO_ROOT, env=judge_env(),
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return None, 1, "judge 执行异常: %r" % e
    out = (r.stdout or "") + (r.stderr or "")
    return parse_hits(out, pattern), r.returncode, out


def run_go_hits(go_exe, tests, pattern, timeout=900):
    run_re = "^(" + "|".join(re.escape(t) for t in tests) + ")$"
    cmd = [go_exe, "test", PKG, "-run", run_re, "-count=1", "-v", "-timeout", "600s"]
    try:
        r = subprocess.run(cmd, cwd=REPO_ROOT, env=go_env(),
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return None, 1, "go test 执行异常: %r" % e
    out = (r.stdout or "") + (r.stderr or "")
    return parse_hits(out, pattern), r.returncode, out


# ── 主流程 ─────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="跨集双语言 parity 门禁（台账驱动）")
    ap.add_argument("--check", action="store_true", help="门禁断言模式（exit 1 = 红）")
    ap.add_argument("--go", default=None, help="显式指定 go 可执行文件")
    ap.add_argument("--only", default=None, help="逗号分隔的集 key，仅跑这些集")
    ap.add_argument("--json", action="store_true", help="机读输出")
    args = ap.parse_args()

    try:
        reg = load_registry()
    except Exception as e:  # noqa: BLE001
        print("🔴 BLOCK —— 台账不可读：%r（%s）" % (e, REGISTRY_PATH))
        return 1 if args.check else 0

    suites = reg.get("suites", [])
    registry_ids = {s["id"] for s in suites if isinstance(s.get("id"), int)}
    summ_ids = summary_ids()

    violations = []
    violations += coverage_violations(registry_ids, summ_ids)
    violations += wired_spec_violations(suites)

    wired = [s for s in suites if s.get("parity") == "wired"
             and s.get("wired_by") == "scripts/check_suite_parity.py"]
    if args.only:
        want = {x.strip() for x in args.only.split(",") if x.strip()}
        wired = [s for s in wired if s.get("key") in want]

    go_exe = find_go(args.go) if wired else None
    py_exe = sys.executable
    if wired and go_exe is None:
        violations.append("找不到 go 可执行文件（试过 SECAUTOMIND_GO / 仓库 toolchain / PATH / 常见目录）"
                          "—— 请设 SECAUTOMIND_GO 或 --go")

    results = []
    if go_exe:
        for s in wired:
            key = s.get("key")
            py_hits, py_rc, py_out = run_python_hits(py_exe, s["python_judge"], s["python_hit_re"])
            go_hits, go_rc, go_out = run_go_hits(go_exe, s["go_tests"], s["go_hit_re"])
            suite_v = compare_suite(key, py_hits or set(), go_hits or set())
            if py_rc != 0:
                suite_v.append("[%s] Python judge 退出码 %d" % (key, py_rc))
                print("[WARN] %s judge rc=%d 尾部:\n%s" % (key, py_rc, "\n".join(py_out.splitlines()[-8:])),
                      file=sys.stderr)
            if go_rc != 0:
                suite_v.append("[%s] go test 退出码 %d" % (key, go_rc))
                print("[WARN] %s go rc=%d 尾部:\n%s" % (key, go_rc, "\n".join(go_out.splitlines()[-8:])),
                      file=sys.stderr)
            violations += suite_v
            results.append({
                "key": key, "python": sorted(py_hits or []), "go": sorted(go_hits or []),
                "python_count": len(py_hits or []), "go_count": len(go_hits or []),
                "violations": suite_v,
            })

    if args.json:
        print(json.dumps({
            "registry_ids": sorted(registry_ids), "summary_ids": sorted(summ_ids),
            "wired_checked": [r["key"] for r in results],
            "results": results, "violations": violations, "go": go_exe,
        }, ensure_ascii=False, indent=2))
        return 1 if (args.check and violations) else 0

    print("=== 跨集双语言 parity（台账 %d 集；汇总 %d 集）===" % (len(registry_ids), len(summ_ids)))
    wired_all = [s["key"] for s in suites if s.get("parity") == "wired"]
    unwired_all = [s["key"] for s in suites if s.get("parity") != "wired"]
    print("  已接线 : %s" % (", ".join(wired_all) or "（无）"))
    print("  未接线 : %s" % (", ".join(unwired_all) or "（无）"))
    for r in results:
        print("  [%s] Py=%d Go=%d 集合一致=%s"
              % (r["key"], r["python_count"], r["go_count"], r["python"] == r["go"]))
    print()

    if not args.check:
        print("报数模式：不判定（--check 才是门禁入口）。当前违规 %d 条" % len(violations))
        for x in violations:
            print("  · %s" % x)
        return 0

    if violations:
        print("🔴 FAIL —— %d 条违规：" % len(violations))
        for x in violations:
            print("  · %s" % x)
        return 1
    print("✅ PASS —— 台账覆盖汇总全部 %d 集，%d 个已接线集逐题一致且非空"
          % (len(summ_ids), len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
