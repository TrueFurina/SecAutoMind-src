#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""双语言基准 parity 门禁（Go ↔ Python 逐题命中集合一致性）。

## 为什么需要（2026-10-16 实测动机）

``data/ctf_benchmark/run_all_benchmarks.py`` 的对外汇总里有一串**硬编码宣称**：

    【1】静态确定性基准集 ... Python judge.py 镜像 == Go TestRealBenchmark_ShippedPresolve（生产路径）
    【2】执行集 ...      Python judge_exec.py == Go TestExecSolversAgainstBenchmark + TestLiveExploitation
    【3】Web 集 ...      Python judge_web.py == Go TestWebExploitAgainstRange
    ...

但**没有任何代码校验这些 "=="**。run_all_benchmarks.py 只拿 **Python 侧**的数字去比
``docs/benchmark_baseline.json`` 的**地板**（``g_hit < min_hit`` 才算红），于是：

  · Python 侧**上漂**不报（镜像宣称解出生产路径解不出的题 = 口径注水方向）；
  · Go 两条路径（shipped / registry）的**逐题**差异无人查；
  · 「Python 镜像」与「Go 生产路径」是否真的**逐题**一致，从来只是打印出来的措辞。

即：这是本项目反复吃亏的同一形态——**宣称写进了对外汇总，却没人接线**
（AGENTS.md 第八条「定义齐全 ≠ 接线」）。本门禁把**静态集（55 道真题）**这条线接上。

> 留痕（未接线项，不许默认它们已被验证）：上述汇总里【2】～【8】（执行集 / Web 集 / 附件集 /
> 题目感知集 / JWT / 反序列化 / XXE / 上传 / GraphQL / SSRF / SQLi / SSTI 各层）同样各打印一句
> 「Python == Go」的硬编码宣称，**尚未**接入逐题 parity 校验。本脚本当前只覆盖静态集。
> （这里刻意不写行号 —— 行号会随文件改动漂移，引用过期行号比不引用更坏。）

## 判据（纯函数 + fail-closed，均非恒真）

三路命中 id 集合：

    S = Go TestRealBenchmark_ShippedPresolve    （生产路径，权威口径）
    R = Go TestRealBenchmark_RegistryPresolve   （注册表 sweep 路径）
    P = Python judge.py 镜像（real_coverage_report.json 里 sha256_match=True 的 id）

| # | 判据 | 条件 | 结论 |
|---|---|---|---|
| 0 | 空集 fail-closed | S / R / P 任一为空 | FAIL（0 命中 ⇒ 无差异 ⇒ 恒绿，同型空洞绿） |
| 1 | id 不越界 | 任一集合含 real_benchmark.json 之外的 id | FAIL（解析串味 / 基准被换） |
| 2 | 注册表超集 | S ⊄ R | FAIL（注册表路径漏掉生产能解的题） |
| 3 | 注册表不多余 | R − S ≠ ∅ | FAIL（求解器注册了却没被生产路径调用，需人工裁决） |
| 4 | 镜像不得超前 | P − S ≠ ∅ | FAIL（Python 镜像宣称生产做不到的命中 = 注水方向） |
| 5 | 镜像不得滞后 | S − P ≠ ∅ | FAIL（「双语言互相印证」宣称不成立） |
| 6 | 地板 | len(S) < 基线 static.min_hit | FAIL（能力退化） |

阈值语义 = **一致性 + 地板**，不是目标值：判据里没有「命中数必须等于 20」这类硬编码，
所以**数字变好不会让门禁漂绿**，只有三路真一致且不低于地板才绿。

## 用法
    python scripts/check_benchmark_parity.py            # 报数（不判定，exit 0）
    python scripts/check_benchmark_parity.py --check    # 门禁断言（exit 1 = 红）
    python scripts/check_benchmark_parity.py --go <path>  # 显式指定 go（否则按候选表探测）

环境变量：``SECAUTOMIND_GO`` 可指定 go 可执行文件（CI 用 PATH 上的 go，无需设置）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_PATH = os.path.join(REPO_ROOT, "data", "ctf_benchmark", "real_benchmark.json")
JUDGE_PATH = os.path.join(REPO_ROOT, "data", "ctf_benchmark", "judge.py")
BASELINE_PATH = os.path.join(REPO_ROOT, "docs", "benchmark_baseline.json")
PKG = "./internal/ctfplatform/"

TEST_SHIPPED = "TestRealBenchmark_ShippedPresolve"
TEST_REGISTRY = "TestRealBenchmark_RegistryPresolve"

# Go 侧命中行格式（presolve_benchmark_test.go）：
#     detail = append(detail, "✅ "+id+" engine="+res.Engine)
# MISS 行是 "❌ MISS "+id —— 必须不被本正则命中。
HIT_RE = re.compile(r"✅\s+(\S+)\s+engine=")


# ── 工具链探测 ────────────────────────────────────────────────

def find_go(explicit=None):
    """定位 go 可执行文件；找不到返回 None（由调用方 fail-closed）。

    不能直接写 "go" 依赖 PATH —— 本仓库 Go 常装在 .workbuddy/toolchain/ 或
    自选目录，PATH 里通常没有（实测本机 `which go` 为空）。旧式「取不到就静默跳过」
    是本项目明令禁止的失效模式（见 count_stats._find_go 的教训注释）。
    """
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
    """构造 go 子进程环境（本机缺 %AppData% 会让所有 go 命令失效，见 AGENTS.md 第五条）。"""
    env = dict(os.environ)
    if os.name == "nt" and not env.get("APPDATA"):
        home = env.get("USERPROFILE") or os.path.expanduser("~")
        cand = os.path.join(home, "AppData", "Roaming")
        if os.path.isdir(cand):
            env["APPDATA"] = cand
    return env


# ── 三路取数 ──────────────────────────────────────────────────

def parse_go_hits(stdout: str) -> set:
    """从 go test -v 输出里抽出命中 id 集合（纯函数，供门禁与变异自测共用）。"""
    hits = set()
    for line in (stdout or "").splitlines():
        m = HIT_RE.search(line)
        if m:
            hits.add(m.group(1))
    return hits


def run_go_hits(go_exe, test_name, timeout=900):
    """跑单个 Go 基准测试，返回 (命中集合, rc, 完整输出)。"""
    cmd = [go_exe, "test", PKG, "-run", "^%s$" % test_name,
           "-count=1", "-v", "-timeout", "600s"]
    r = subprocess.run(cmd, cwd=REPO_ROOT, env=go_env(),
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout)
    out = (r.stdout or "") + (r.stderr or "")
    return parse_go_hits(out), r.returncode, out


def run_python_hits(python_exe, timeout=600):
    """跑 judge.py（写临时报告），返回 (命中集合, rc, 完整输出)。"""
    fd, report = tempfile.mkstemp(suffix=".json", prefix="parity_py_")
    os.close(fd)
    env = dict(os.environ)
    env["BENCH"] = BENCH_PATH
    env["REPORT"] = report
    hits, rc, out = set(), 1, ""
    try:
        r = subprocess.run([python_exe, JUDGE_PATH], cwd=REPO_ROOT, env=env,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        rc = r.returncode
        if rc == 0 and os.path.exists(report):
            with open(report, encoding="utf-8") as fh:
                rep = json.load(fh)
            hits = {x["id"] for x in rep.get("results", []) if x.get("sha256_match")}
    finally:
        try:
            os.remove(report)
        except OSError:
            pass
    return hits, rc, out


# ── 判据（纯函数）─────────────────────────────────────────────

def compare_hits(shipped, registry, python_hits, bench_ids, min_hit):
    """三路逐题集合一致性判据。返回 violations 列表（非空即 FAIL）。

    纯函数：不读文件、不起子进程 —— 供主流程与变异自测共用同一判据
    （防「测试过了但判据是另一份」）。
    """
    v = []

    # 0) fail-closed：任一路为空 ⇒ 「无差异 ⇒ 全绿」的同型空洞绿，禁止判绿。
    for name, s in (("Go 生产路径 shipped", shipped),
                    ("Go 注册表路径 registry", registry),
                    ("Python judge.py 镜像", python_hits)):
        if not s:
            v.append("空洞绿风险：%s 命中集合为空——疑似解析失败/工具链缺失/基准被清空，禁止判绿" % name)

    # 1) id 越界：命中 id 必须存在于 real_benchmark.json。
    for name, s in (("shipped", shipped), ("registry", registry), ("python", python_hits)):
        outside = sorted(s - bench_ids)
        if outside:
            v.append("%s 命中 id 不在 real_benchmark.json 内（解析串味/基准被换）：%s"
                     % (name, ", ".join(outside[:8])))

    # 2) 注册表必须覆盖生产路径；多出来的须人工裁决（注册了却没接线）。
    if shipped - registry:
        v.append("注册表路径漏掉生产路径能解的题（R ⊉ S）：%s"
                 % ", ".join(sorted(shipped - registry)))
    if registry - shipped:
        v.append("注册表路径解出生产路径解不出的题（求解器注册了却没被生产路径调用，需人工裁决）：%s"
                 % ", ".join(sorted(registry - shipped)))

    # 3) Python 镜像双向一致（超前 = 注水方向；滞后 = 「互相印证」宣称不成立）。
    if python_hits - shipped:
        v.append("Python 镜像宣称生产路径做不到的命中（注水方向）：%s"
                 % ", ".join(sorted(python_hits - shipped)))
    if shipped - python_hits:
        v.append("Python 镜像滞后于生产路径（「双语言互相印证」宣称不成立）：%s"
                 % ", ".join(sorted(shipped - python_hits)))

    # 4) 地板：能力退化。
    if min_hit is not None and len(shipped) < min_hit:
        v.append("生产路径命中 %d < 基线地板 %d（能力退化）" % (len(shipped), min_hit))

    return v


# ── 主流程 ────────────────────────────────────────────────────

def load_bench():
    """读基准题 id 全集与总数；缺失/不可解析返回 (None, None) 由调用方判红。"""
    try:
        with open(BENCH_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
        probs = doc["problems"]
        if not isinstance(probs, dict) or not probs:
            return None, None
        return set(probs.keys()), len(probs)
    except Exception as e:
        print("[WARN] 读取 %s 失败：%s" % (BENCH_PATH, e), file=sys.stderr)
        return None, None


def load_floor():
    """读 docs/benchmark_baseline.json 的 static.min_hit；缺失返回 None（fail-closed 由调用方处理）。"""
    try:
        with open(BASELINE_PATH, encoding="utf-8") as fh:
            d = json.load(fh)
        return int(d["suites"]["static"]["min_hit"])
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="双语言基准 parity 门禁（静态集 55 题）")
    ap.add_argument("--check", action="store_true", help="门禁断言模式（exit 1 = 红）")
    ap.add_argument("--go", default=None, help="显式指定 go 可执行文件")
    ap.add_argument("--json", action="store_true", help="机读输出")
    args = ap.parse_args()

    bench_ids, bench_total = load_bench()
    floor = load_floor()

    go_exe = find_go(args.go)
    py_exe = sys.executable

    blocked = []
    if bench_ids is None:
        blocked.append("real_benchmark.json 缺失/为空/不可解析（%s）" % BENCH_PATH)
    if floor is None:
        blocked.append("基线地板不可读（%s）" % BASELINE_PATH)
    if go_exe is None:
        blocked.append("找不到 go 可执行文件（试过 SECAUTOMIND_GO / 仓库 .workbuddy/toolchain / PATH / 常见安装目录）"
                       "—— 请设 SECAUTOMIND_GO 或 --go")

    if blocked:
        print("🔴 BLOCK —— 前置条件不满足，fail-closed（不静默放过）：")
        for b in blocked:
            print("  · %s" % b)
        return 1 if args.check else 0

    shipped, rc1, out1 = run_go_hits(go_exe, TEST_SHIPPED)
    registry, rc2, out2 = run_go_hits(go_exe, TEST_REGISTRY)
    python_hits, rc3, out3 = run_python_hits(py_exe)

    for label, rc, out in (("Go shipped", rc1, out1), ("Go registry", rc2, out2), ("Python judge.py", rc3, out3)):
        if rc != 0:
            print("[WARN] %s 退出码 %d（输出尾部）：" % (label, rc), file=sys.stderr)
            print("\n".join((out or "").splitlines()[-12:]), file=sys.stderr)

    violations = compare_hits(shipped, registry, python_hits, bench_ids, floor)
    # 子进程非零退出也算违规（否则「跑挂了但集合非空」可能蒙混）。
    for label, rc in (("Go shipped", rc1), ("Go registry", rc2), ("Python judge.py", rc3)):
        if rc != 0:
            violations.append("%s 子进程退出码 %d（测试/judge 本身失败）" % (label, rc))

    if args.json:
        print(json.dumps({
            "bench_total": bench_total,
            "floor": floor,
            "shipped": sorted(shipped),
            "registry": sorted(registry),
            "python": sorted(python_hits),
            "shipped_count": len(shipped),
            "registry_count": len(registry),
            "python_count": len(python_hits),
            "violations": violations,
            "go": go_exe,
        }, ensure_ascii=False, indent=2))
        return 1 if (args.check and violations) else 0

    print("=== 双语言基准 parity（静态集 real_benchmark.json %d 题）===" % bench_total)
    print("  Go  shipped  (生产路径) : %2d  %s" % (len(shipped), sorted(shipped)[:6]))
    print("  Go  registry (注册表)   : %2d" % len(registry))
    print("  Py  judge.py (镜像)     : %2d" % len(python_hits))
    print("  基线地板 static.min_hit : %s" % floor)
    print("  三路集合一致            : %s" % (shipped == registry == python_hits))
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
    print("✅ PASS —— Go shipped / Go registry / Python 镜像 三路逐题一致，且不低于地板 %d" % floor)
    return 0


if __name__ == "__main__":
    sys.exit(main())
