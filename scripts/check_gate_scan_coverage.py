#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
门禁：CI 扫描型门禁的「空扫描集必须判红」（2026-11-10）。

背景（真实缺陷）：
    遍历型门禁的通用形态是「收集文件 -> 逐文件检查 -> 汇总 errors -> 空则 rc 0」。
    一旦 os.walk / glob.glob 的扫描范围被缩小、路径常量写错、目录被移走，
    就会变成「扫 0 个文件 = 0 条违规 = 全绿」——门禁永远绿，且看不出它瞎了。
    实测（2026-11-10）：check_flag_eval_regex.py 与 check_docs_lint.py 在把
    os.walk 置空后仍 rc=0 / PASS；两者都已补上扫描集下限断言。

为什么是行为级判据而不是「源码里有没有 MIN_ 常量」：
    正则/字符串匹配会被注释、docstring、改名骗过（本项目已有多次实证：
    temperature_fixed 判据、_registry_threaded_proven 判据）。本判据在独立
    子进程里真的把 os.walk / glob.glob / os.listdir / Path.rglob|glob|iterdir
    替换为空，再调用门禁的 main()，看返回码——测的是行为，不是文字。

判据 R1~R8：
    R1 候选集（ci.yml 中的遍历型门禁）必须存在且数量达下限。
    R2 每个探测目标在正常态必须 rc=0（本判据不掩盖门禁本身的红项）。
    R3 非挂账目标在空集态必须 rc!=0（fail-closed；rc=0 即假绿）。
    R4 不适用者必须具名豁免：键必须在候选集内、理由具体、数量有上限。
    R5 候选集中「未探测且未豁免」的必须判红（防新增遍历型门禁漏登记）。
    R6 三层防缩水：ci.yml 可提取门禁数、目标数、空集判红数各有下限。
    R7 探测子进程异常/超时不得静默当绿（probe 报错即判红）。
    R8 已确认但未修的假绿必须登记为可见挂账（理由具体、只减不增）；
       一旦某条挂账真的修好（空集判红），登记过期立即判红，逼人删键。

作用域：
    - 只覆盖 ci.yml 中以 `python [scripts/]X.py` 直接调用、且源码含目录遍历
      调用的门禁；间接 import、动态 subprocess 拼接不声称覆盖。
    - AST 判定排除 ast.walk（语法树遍历不是目录遍历），因此本判据自身不构成
      遍历型候选，不参与子进程探测；自身由 --selftest 的变异自测覆盖。
    - patch 在模块加载之后生效，只模拟「运行期扫描集为空」；模块级就缓存好
      文件列表的门禁不在本判据能力范围内（这类需单独登记豁免）。

用法：
    python scripts/check_gate_scan_coverage.py --selftest   # 变异自测
    python scripts/check_gate_scan_coverage.py --stats      # 仓库现状 + 统计
    python scripts/check_gate_scan_coverage.py              # CI 门禁入口
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CI_YML = ROOT / ".github/workflows" / "ci.yml"
SCRIPTS = ROOT / "scripts"

# ── 防缩水下限（实测 2026-11-10：候选 21 / 目标见 --stats）──
MIN_CI_GATES = 25          # ci.yml 中可提取的门禁类脚本数（实测 34）
MIN_CANDIDATES = 15        # 遍历型候选数（实测 21）
MIN_TARGETS = 8            # 实际探测目标数（实测 16，其中 7 条为挂账）
MIN_RED = 8                # 空集判红数（实测 9）
MAX_EXEMPTIONS = 12        # 豁免上限，防止「全部豁免 = 判据空转」
MAX_KNOWN_FALSE_GREEN = 7  # 已确认但未修的假绿挂账上限（实测 7，只减不增）

# 具名豁免：不适用本判据的遍历型门禁，必须写清具体理由。
NOT_PROBED: dict[str, str] = {
    "audit_external_pool_readiness.py":
        "CI 入口为 --selftest 自测，本体需外部池运行日志，空集语义不适用",
    "check_binary_version.py":
        "正常态依赖本机 Go 二进制产物，CI Linux 与本机形态不同，不纳入本机探测",
    "check_material_numbers.py":
        "官网 26 处用户裁定不动的既有挂账，正常态本身 RC=1，不得由本判据吞掉",
    "check_quant_effect.py":
        "CI 用 --full 跑量化效果重算，耗时长且依赖实验产物，不做空集子进程探测",
    "check_line_endings.py":
        "本机 CRLF 工作树两个 .sh 是已知假红（git blob 纯 LF）；纯 LF 提交态实测 RC=0，"
        "空集态本身也已判红，由提交态门禁集合覆盖",
}

# 已确认「空集仍报绿」但本轮未修的门禁 —— 挂账不是通过。
# 冻结基线：数量只减不增；任何一条修复后 empty_rc 会变红，届时本表必须删除该键
# （R8 会判「挂账过期」），否则判据变红，杜绝挂账退化成永久遮羞布。
KNOWN_FALSE_GREEN: dict[str, str] = {
    "audit_benchmark_validity.py":
        "空集下真求解器 0 题 / 命中率 0.0% 仍 PASS（3 项断言全过）；需加题数下限",
    "check_agent_docs.py":
        "空集下 C3/C5 等数量型判据 vacuous truth 全过；需加 docs 顶层文档数下限",
    "check_doc_port_consistency.py":
        "空集下自报『扫描 docs（0 个文件）』仍 PASS；需加扫描文件数下限",
    "check_final_artifacts_freeze.py":
        "空集下没有冻结产物可比，仍 PASS；需加产物数下限",
    "check_flag_extract_contract.py":
        "空集下『仓库内各拷贝逐份相符』退化为 0 份空真；需加拷贝数下限",
    "check_mcp_servers.py":
        "空集下仍按固定清单报 3 个 server 并 PASS，目录侧遍历未进结论；需修或定性不适用",
    "check_web_asset_parity.py":
        "空集下源/目标各 0 文件仍判『一致无漂移』；需加两侧文件数下限",
}

# 空集 patch 在「模块已加载后」生效：加载阶段不受影响，只模拟运行期扫描集塌陷。
PROBE = r'''
import sys, os, glob, json, io, contextlib, importlib.util, pathlib, inspect
path, argv, mode = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
sys.path.insert(0, os.path.dirname(path))  # 模拟 `python scripts/x.py` 的 sys.path[0]
spec = importlib.util.spec_from_file_location("gate_under_probe", path)
mod = importlib.util.module_from_spec(spec)
rc, err, tail, load_err = None, None, "", None
try:
    spec.loader.exec_module(mod)
except Exception as e:
    load_err = type(e).__name__ + ": " + str(e)[:120]
if load_err is None and mode == "empty":
    pathlib.Path.rglob = lambda s, *a, **k: iter(())
    pathlib.Path.glob = lambda s, *a, **k: iter(())
    pathlib.Path.iterdir = lambda s, *a, **k: iter(())
    os.walk = lambda *a, **k: iter(())
    os.listdir = lambda *a, **k: []
    glob.glob = lambda *a, **k: []
    glob.iglob = lambda *a, **k: iter(())
sys.argv = [path] + list(argv)
buf = io.StringIO()
if load_err is None:
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                needs_argv = len(inspect.signature(mod.main).parameters) > 0
                r = mod.main(list(argv)) if needs_argv else mod.main()
                rc = r if isinstance(r, int) else 0
            except SystemExit as e:
                rc = e.code
    except Exception as e:
        err = type(e).__name__ + ": " + str(e)[:120]
tail = buf.getvalue()[-300:]
sys.stdout.write(json.dumps({"rc": rc, "err": err, "load_err": load_err, "tail": tail}))
'''

GATE_PREFIXES = ("check_", "verify_", "audit_")
SELFTEST_TOKENS = ("selftest", "self-test", "self_test")
TRAVERSE_ATTRS = ("walk", "rglob", "glob", "iterdir", "listdir")


def _is_traversing(src: str) -> bool:
    """AST 判定源码是否含目录遍历调用（注释/字符串不算）。"""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in TRAVERSE_ATTRS:
            # ast.walk 是语法树遍历，不是目录遍历（自指假阳性实测 2026-11-10）
            if ast.unparse(f.value).split(".")[-1] == "ast":
                continue
            return True
        if isinstance(f, ast.Name) and f.id in TRAVERSE_ATTRS:
            return True
    return False


def collect_ci_gates(text: str) -> dict[str, list[str]]:
    """从 ci.yml 的 run 行提取 `python [scripts/]X.py [flags]`，按脚本聚合 argv。"""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.search(r"python\s+(?:scripts/)?([A-Za-z0-9_\-]+\.py)([^\n]*)", line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        if not name.startswith(GATE_PREFIXES) or name.endswith("_test.py"):
            continue
        flags = re.findall(r"(--[A-Za-z0-9_\-]+)", rest)
        out.setdefault(name, []).append(flags)
    return out


def pick_argv(options: list[list[str]]) -> list[str]:
    """优先选不含自测 flag 的最简 argv（CI 常先跑自测再跑本体）。"""
    plain = [a for a in options if not any(t in " ".join(a).lower() for t in SELFTEST_TOKENS)]
    pool = plain or options
    return sorted(pool, key=len)[0]


def collect_candidates(ci_text: str) -> tuple[list[str], dict[str, list[str]], int]:
    """返回 (遍历型候选名, 各候选的 CI argv, ci.yml 可提取门禁数)。"""
    gates = collect_ci_gates(ci_text)
    candidates: list[str] = []
    argvs: dict[str, list[str]] = {}
    for name in sorted(gates):
        p = SCRIPTS / name
        if not p.is_file():
            continue
        src = p.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
        if not _is_traversing(src):
            continue
        candidates.append(name)
        argvs[name] = pick_argv(gates[name])
    return candidates, argvs, len(gates)


def run_probe(name: str, argv: list[str], mode: str) -> dict:
    path = str((SCRIPTS / name).resolve())
    try:
        r = subprocess.run(
            [sys.executable, "-c", PROBE, path, json.dumps(argv), mode],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=90, cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return {"rc": None, "err": "TIMEOUT", "load_err": None, "tail": ""}
    if r.returncode != 0:
        return {"rc": None, "err": "PROBE_RC%d" % r.returncode,
                "load_err": None, "tail": (r.stderr or "")[-200:]}
    try:
        data = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"rc": None, "err": "BAD_PROBE_OUTPUT", "load_err": None,
                "tail": (r.stdout or "")[-200:]}
    if not isinstance(data, dict) or "rc" not in data:
        return {"rc": None, "err": "BAD_PROBE_SCHEMA", "load_err": None, "tail": ""}
    return data


def check(results: dict[str, dict], candidates: list[str],
          targets: list[str], exemptions: dict[str, str],
          n_ci_gates: int, known: dict[str, str]) -> list[str]:
    """纯函数判据，便于变异自测注入合成数据。"""
    errors: list[str] = []
    cand = set(candidates)

    # R1 候选集
    if len(candidates) < MIN_CANDIDATES:
        errors.append("R1 遍历型候选仅 %d < %d（ci.yml 提取口径或 AST 判定失效）"
                      % (len(candidates), MIN_CANDIDATES))
    if n_ci_gates < MIN_CI_GATES:
        errors.append("R1 ci.yml 可提取门禁仅 %d < %d（CI 被大改）"
                      % (n_ci_gates, MIN_CI_GATES))

    # R4 豁免健康度
    for key, reason in exemptions.items():
        if key not in cand:
            errors.append("R4 豁免键不在候选集内（悬空）: %s" % key)
        if len(reason.strip()) < 12:
            errors.append("R4 豁免理由不具体: %s" % key)
    if len(exemptions) > MAX_EXEMPTIONS:
        errors.append("R4 豁免 %d > 上限 %d（判据接近空转）"
                      % (len(exemptions), MAX_EXEMPTIONS))

    # R8 挂账健康度：键真实、理由具体、只减不增
    for key, reason in known.items():
        if key not in cand:
            errors.append("R8 挂账键不在候选集内（悬空）: %s" % key)
        if len(reason.strip()) < 12:
            errors.append("R8 挂账理由不具体: %s" % key)
    if len(known) > MAX_KNOWN_FALSE_GREEN:
        errors.append("R8 挂账 %d > 冻结基线 %d（只减不增，不许新增假绿）"
                      % (len(known), MAX_KNOWN_FALSE_GREEN))

    # R5 未探测且未豁免
    missing = sorted(cand - set(targets) - set(exemptions))
    for name in missing:
        errors.append("R5 遍历型门禁既未探测也未豁免: %s" % name)

    # R6 防缩水
    if len(targets) < MIN_TARGETS:
        errors.append("R6 探测目标仅 %d < %d" % (len(targets), MIN_TARGETS))
    n_red = sum(1 for t in targets
                if results.get(t, {}).get("empty", {}).get("rc") not in (0, None))
    if n_red < MIN_RED:
        errors.append("R6 空集判红仅 %d < %d（大量门禁其实是假绿）" % (n_red, MIN_RED))

    # R2 / R3 / R7 逐目标
    for name in targets:
        rec = results.get(name)
        if rec is None:
            errors.append("R7 %s 缺探测结果" % name)
            continue
        normal, empty = rec.get("normal", {}), rec.get("empty", {})
        for label, d in (("normal", normal), ("empty", empty)):
            if d.get("err") or d.get("load_err"):
                errors.append("R7 %s %s 探测异常: %s"
                              % (name, label, d.get("err") or d.get("load_err")))
        if normal.get("rc") != 0:
            errors.append("R2 %s 正常态 rc=%s（门禁本身红，不得由本判据吞掉）"
                          % (name, normal.get("rc")))
        if name in known:
            if empty.get("rc") not in (0, None):
                errors.append("R8 %s 空集已判红 => 挂账过期，必须从 KNOWN_FALSE_GREEN 移除"
                              % name)
        elif empty.get("rc") in (0, None):
            errors.append("R3 %s 空扫描集仍 rc=%s => 假绿（必须 fail-closed）"
                          % (name, empty.get("rc")))
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--stats", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    ci_text = CI_YML.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
    candidates, argvs, n_ci_gates = collect_candidates(ci_text)
    exemptions = {k: v for k, v in NOT_PROBED.items() if k in candidates}
    known = {k: v for k, v in KNOWN_FALSE_GREEN.items() if k in candidates}
    targets = [n for n in candidates if n not in exemptions]

    results: dict[str, dict] = {}
    for name in targets:
        results[name] = {
            "normal": run_probe(name, argvs[name], "normal"),
            "empty": run_probe(name, argvs[name], "empty"),
        }

    errors = check(results, candidates, targets, exemptions, n_ci_gates, known)
    n_red = sum(1 for t in targets if results[t]["empty"]["rc"] not in (0, None))
    if a.stats:
        print("stats: ci_gates=%d candidates=%d targets=%d exemptions=%d "
              "known_false_green=%d empty_red=%d"
              % (n_ci_gates, len(candidates), len(targets), len(exemptions),
                 len(known), n_red))
        for name in targets:
            n, e = results[name]["normal"], results[name]["empty"]
            tag = ("挂账(已确认假绿)" if name in known
                   else "空集判红" if e.get("rc") not in (0, None) else "未判红")
            print("  %-42s normal=rc%-4s empty=rc%-4s %-18s %s"
                  % (name, n.get("rc"), e.get("rc"), tag,
                     (e.get("err") or e.get("load_err") or "")[:40]))
        print("exemptions:", ", ".join(sorted(exemptions)))
        print("挂账（发布节点前必须清零）:", ", ".join(sorted(known)))
    for e in errors:
        print("RED:", e)
    print("结论：%s（%d 个目标，空集判红 %d，已登记假绿挂账 %d 项）"
          % ("PASS" if not errors else "FAIL", len(targets), n_red, len(known)))
    return 1 if errors else 0


def selftest() -> int:
    """变异自测：证明每条判据真的能变红，且正常态/冻结挂账不误报。"""
    candidates = ["g%02d.py" % i for i in range(20)]
    targets = ["g%02d.py" % i for i in range(12)]
    exemptions = {"g12.py": "需要外部实验产物，正常态依赖本机二进制，不做空集探测",
                  "g13.py": "CI 入口仅为自测，本体需联网日志，空集语义不适用",
                  "g14.py": "当前稳定判红的既有挂账，不得由本判据吞掉，具名豁免",
                  "g15.py": "依赖 Go 二进制产物，Linux CI 与本机形态不同，具名豁免",
                  "g16.py": "正常态需 40 秒以上重算，纳入会让 CI 超时，具名豁免",
                  "g17.py": "模块加载期即缓存文件列表，运行期 patch 打不中，具名豁免",
                  "g18.py": "只做盘点不做判定，非闸门，具名豁免",
                  "g19.py": "需真实运行日志参数，空集无法构造合法调用，具名豁免"}

    def rec(normal=0, empty=1):
        return {"normal": {"rc": normal, "err": None, "load_err": None, "tail": ""},
                "empty": {"rc": empty, "err": None, "load_err": None, "tail": ""}}

    results = {n: rec() for n in targets}
    n_ci = [34]

    def with_known(r, c, t, ex, k, n):
        """把 7 个候选改成「已确认假绿但登记挂账」的形态。"""
        for name in c[12:19]:
            t.append(name)
            r[name] = rec(empty=0)
            k[name] = "已确认空集假绿的具体理由文字足够长"
            ex.pop(name, None)

    def compose(*fns):
        def run(*args):
            for fn in fns:
                fn(*args)
        return run

    def case(name, mutate, expect_red=True):
        n_ci[0] = 34  # 每个用例重置，避免 M2 的塌陷污染后续用例
        r = {x: {kk: dict(vv) for kk, vv in d.items()} for x, d in results.items()}
        c, t, ex, k = list(candidates), list(targets), dict(exemptions), {}
        mutate(r, c, t, ex, k, n_ci[0])
        errs = check(r, c, t, ex, n_ci[0], k)
        ok = bool(errs) if expect_red else not errs
        print("  [%s] %-52s -> %s" % ("PASS" if ok else "FAIL", name,
                                      "RED" if errs else "GREEN"))
        return ok

    noop = lambda r, c, t, ex, k, n: None
    oks = []
    oks.append(case("B0 正常态不误报", noop, False))
    oks.append(case("B1 7 条冻结挂账不误报", with_known, False))
    oks.append(case("M1 候选集塌陷", lambda r, c, t, ex, k, n: c.clear()))
    oks.append(case("M2 ci.yml 门禁数塌陷",
                    lambda r, c, t, ex, k, n: n_ci.__setitem__(0, 3)))
    oks.append(case("M3 目标集清空", lambda r, c, t, ex, k, n: t.clear()))
    oks.append(case("M4 非挂账门禁空集仍 rc=0（假绿）",
                    lambda r, c, t, ex, k, n: r[t[0]]["empty"].update(rc=0)))
    oks.append(case("M5 某门禁正常态红不得吞掉",
                    lambda r, c, t, ex, k, n: r[t[1]]["normal"].update(rc=1)))
    oks.append(case("M6 探测异常不得当绿",
                    lambda r, c, t, ex, k, n: r[t[2]]["empty"].update(rc=None, err="TIMEOUT")))
    oks.append(case("M7 模块加载失败不得当绿",
                    lambda r, c, t, ex, k, n: r[t[3]]["normal"].update(load_err="ImportError")))
    oks.append(case("M8 新增遍历型门禁未登记",
                    lambda r, c, t, ex, k, n: c.append("g20_new.py")))
    oks.append(case("M9 豁免键悬空",
                    lambda r, c, t, ex, k, n: ex.update(
                        {"ghost.py": "不存在的门禁也要有具体理由"})))
    oks.append(case("M10 豁免理由空洞",
                    lambda r, c, t, ex, k, n: ex.update({"g12.py": "略"})))
    oks.append(case("M11 豁免数量超上限",
                    lambda r, c, t, ex, k, n: ex.update(
                        {"extra%d.py" % i: "批量塞入的假豁免理由文字够长" for i in range(20)})))
    oks.append(case("M12 空集判红数塌陷",
                    lambda r, c, t, ex, k, n: [r[x]["empty"].update(rc=0) for x in t[:8]]))
    oks.append(case("M13 缺探测结果", lambda r, c, t, ex, k, n: r.pop(t[4])))
    oks.append(case("M14 挂账过期（已修复却未移除登记）",
                    compose(with_known,
                            lambda r, c, t, ex, k, n: r[c[12]]["empty"].update(rc=1))))
    oks.append(case("M15 挂账键悬空",
                    lambda r, c, t, ex, k, n: k.update(
                        {"ghost.py": "不存在的门禁也要有具体理由"})))
    oks.append(case("M16 挂账理由空洞",
                    compose(with_known,
                            lambda r, c, t, ex, k, n: k.update({"g12.py": "略"}))))
    oks.append(case("M17 挂账数超冻结基线（只减不增）",
                    compose(with_known,
                            lambda r, c, t, ex, k, n: k.update(
                                {"extra%d.py" % i: "批量新增假绿挂账理由文字够长"
                                 for i in range(10)}))))
    ok = all(oks)
    print("SELFTEST: %s（%d/%d）" % ("PASS" if ok else "FAIL", sum(oks), len(oks)))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
