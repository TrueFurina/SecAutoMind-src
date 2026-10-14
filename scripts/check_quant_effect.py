#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对外量化陈述机验：把 docs/quant_effect.md 的声明逐条复跑比对。

验收第 8 条要求「对外量化陈述 100% 可指回」。若只在文档里写"数字可复现"，
那仍是口头结论；本脚本真的把每条声明的命令跑一遍，用声明里给的正则从输出
里取值，与声明的期望值比对。

设计取舍：
- **不依赖 pyyaml**：CI 环境不保证装了它，且本文件的 YAML 值含中文/括号，
  自解析反而更可控。
- **quick / slow 分档**：slow 项（执行层/Web/附件，Python 侧跑真实利用链）
  耗时较长，CI 默认只跑 quick（秒级，含最关键的两条真题覆盖率与自研集）；
  `--full` 才跑全部，供本地与赛前复验。分档是为了让门禁跑得动——
  一个没人愿意等、于是被跳过的门禁等于不存在。
- **失败即退出非 0**：不提供"仅警告"模式。数字漂移必须显式处理。
- **验证不得有副作用**：机验命令跑完后，任何对受版本管理产物（基准汇总、基线冻结）
  的改动都会被自动还原（默认告警，`--strict-isolation` 下升级为失败）。
  基准汇总另做事前重定向，源头就不写受管理路径。

用法:
    python scripts/check_quant_effect.py            # quick（CI 默认）
    python scripts/check_quant_effect.py --full     # 含 slow
    python scripts/check_quant_effect.py --list     # 只列声明不跑
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "quant_effect.md")

# 每条 claim 跑命令的超时（秒）
TIMEOUT_SLOW = 600
TIMEOUT_QUICK = 300

# ── 验证不得有副作用：受保护产物的监视范围 ────────────────────────────────
# 背景（2026-10-14 实锤）：`benchmark_suite_green` 声明会跑
# data/ctf_benchmark/run_all_benchmarks.py，而该脚本此前**无条件就地写**
# data/ctf_benchmark/all_benchmarks_summary.json —— 那是受版本管理、且被
# build_championship_evidence.py / verify_evidence.py / 基线门禁消费的证据产物。
# 于是「跑验证」= 「改产物」：降级环境下写进降级值并级联判红基线门禁。
# 两层修复：① 事前重定向（见 REDIRECT_ENV，源头不写受管理路径）
#           ② 事后守卫（本处：快照 → 跑 → 比对 → 还原 + 告警）
WATCH_GLOBS = (
    "data/ctf_benchmark/*.json",
    "docs/benchmark_baseline.json",
)
REDIRECT_ENV = "CTF_AGENT_BENCH_SUMMARY_OUT"


def watched_paths():
    """监视清单：受版本管理、可能被机验命令就地改写的产物。

    用 glob 而不是硬编码文件名——新增基准集产物自动纳入保护，不必改本脚本。
    只取**快照时已存在**的文件：data/* 在 .gitignore 内（新增文件本就不入仓），
    若把"新增"也算异常，CI 每次跑基准都会刷出一堆无意义告警。
    """
    found = set()
    for pattern in WATCH_GLOBS:
        for path in glob.glob(os.path.join(ROOT, pattern)):
            if os.path.isfile(path):
                found.add(os.path.relpath(path, ROOT).replace("\\", "/"))
    return sorted(found)


def snapshot(paths):
    snap = {}
    for rel in paths:
        try:
            with open(os.path.join(ROOT, rel), "rb") as fh:
                snap[rel] = fh.read()
        except OSError:
            pass
    return snap


def restore_if_changed(snap):
    """把被机验命令改动的受保护产物还原，返回被改动的路径清单。

    只处理快照里**已存在**的文件（改动 / 删除 → 字节级还原）。
    验证动作本就不该持久化任何状态，故还原是无条件正确的；
    若确需刷新产物，应显式跑 run_all_benchmarks.py，而不是借道本门禁。
    """
    changed = []
    for rel, blob in sorted(snap.items()):
        abs_path = os.path.join(ROOT, rel)
        try:
            with open(abs_path, "rb") as fh:
                cur = fh.read()
        except OSError:
            cur = None
        if cur != blob:
            changed.append(rel)
            with open(abs_path, "wb") as fh:
                fh.write(blob)
    return changed


def parse_claims(text: str):
    """从 md 的 ```yaml 块里解析 claims（自解析，不依赖 pyyaml）。"""
    blocks = re.findall(r"```yaml\s*\n(.*?)```", text, re.S)
    if not blocks:
        return []
    claims = []
    cur = None
    for line in blocks[0].splitlines():
        m_new = re.match(r"^\s*-\s+id:\s*(\S+)\s*$", line)
        if m_new:
            cur = {"id": m_new.group(1)}
            claims.append(cur)
            continue
        if cur is None:
            continue
        m_kv = re.match(r"^\s+([^\s:]+):\s*(.*?)\s*$", line)
        if m_kv:
            k, v = m_kv.group(1), m_kv.group(2)
            # 去掉配对引号（pattern 字段用单引号包裹以保留反斜杠）
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            cur[k] = v
    return claims


def nums_of(s: str):
    """从 '20/55 = 36.4%' 这类字符串里抽出数字序列 [20.0, 55.0, 36.4]。"""
    return [float(x) for x in re.findall(r"\d+(?:\.\d+)?", s or "")]


def run_claim(c: dict, timeout: int):
    """执行声明里的命令，用声明里的正则取值，返回 (ok, 实测值文本, 说明)。"""
    cmd = c.get("command", "").strip()
    pat = c.get("pattern", "").strip()
    if not cmd or not pat:
        return None, "", "缺 command 或 pattern，无法机验（应改列到人工核验表）"

    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=ROOT, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return False, "", "命令超时（%ss）" % timeout
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    dt = time.time() - t0

    m = re.search(pat, out)
    if not m:
        tail = " | ".join(out.strip().splitlines()[-3:])
        msg = "pattern 未命中输出（命令 rc=%s，%.1fs）。输出尾部：%s" % (
            p.returncode, dt, tail[:200])
        return False, "", msg

    got = [float(x) for x in m.groups()]
    exp = nums_of(c.get("期望", ""))
    n = min(len(got), len(exp))
    if n == 0:
        return False, "", "期望值或实测值无法解析出数字"

    actual_txt = "/".join(str(int(g) if g.is_integer() else g) for g in got)
    if got[:n] != exp[:n]:
        # 值不符时必须给出"哪一题/哪一步"的证据：跨平台的漂移（如本机 Windows
        # 17/17、CI Linux 15/17）光看"期望/实测"两个数根本无法定位。
        # 优先抽 MISS/FAIL 行（直接点名），抽不到再退化为输出尾部。
        bad = [l.strip() for l in out.splitlines()
               if re.search(r"MISS|FAIL|✗|❌|Timeout|Traceback", l)]
        diag = " ; ".join(bad[:10]) if bad else \
            " | ".join(out.strip().splitlines()[-6:])
        return False, actual_txt, "漂移：期望 %s，实测 %s || %s" % (
            exp[:n], got[:n], diag[:500])
    return True, actual_txt, "%.1fs" % dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="连 slow 项一起跑")
    ap.add_argument("--list", action="store_true", help="只列声明不执行")
    ap.add_argument("--strict-isolation", action="store_true",
                    help="把「机验命令改写了受保护产物」由告警升级为失败（CI 收紧用）")
    args = ap.parse_args()

    if not os.path.exists(DOC):
        print("FAIL: 找不到 %s" % DOC)
        return 1
    text = open(DOC, encoding="utf-8").read()
    claims = parse_claims(text)
    if not claims:
        print("FAIL: quant_effect.md 中未解析到 claims（yaml 块缺失或格式变了）")
        return 1

    selected = [c for c in claims
                if args.full or (c.get("耗时类", "quick") != "slow")]
    skipped = [c for c in claims if c not in selected]

    print("=== 对外量化陈述机验（%s）===" % ("full" if args.full else "quick"))
    print("声明总数 %d，本次机验 %d，跳过 slow %d\n"
          % (len(claims), len(selected), len(skipped)))

    if args.list:
        for c in claims:
            print("  [%s] %-22s %s" % (c.get("耗时类", "quick"), c["id"],
                                        c.get("期望", "")))
        return 0

    # 🔴 空洞绿防线（2026-10-14 门禁审计实锤，三种形态逐一封死）：
    #  1. quick 模式选中 0 条（例如有人把所有声明标成 slow）→ 门禁零机验却报 PASS；
    #  2. 声明缺 command/pattern → 旧版记 SKIP 且**不计入** fails，还能谎报"N 条全部可复现"；
    #  3. PASS 文案用 len(selected) 计数，把 SKIP 的也算了进去。
    # 三者同构于 `_audit_llm_pool.py` 当年的"输入缺失/解析为 0 → 自动全真"。
    # 纪律：凡"扫声明后汇总"的门禁，**机验条数为 0 本身必须算红**（fail-closed）。
    if not selected:
        print()
        print("结论：FAIL —— 本次机验选中 0 条声明（共解析到 %d 条）。"
              % len(claims))
        print("处置：CI 默认跑 quick；若声明全被标成 slow，本门禁在 CI 上等于空转，"
              "与失效门禁同构。请至少保留 1 条 quick 声明，或让 CI 显式跑 --full。")
        return 1

    fails = []
    verified = 0

    # 事前：把基准汇总重定向到临时目录（源头不写受版本管理路径）。
    # 事后：比对快照，任何改动一律还原 + 告警。
    guard_paths = watched_paths()
    guard_snap = snapshot(guard_paths)
    tmpdir = tempfile.mkdtemp(prefix="qe_isolated_")
    prev_redirect = os.environ.get(REDIRECT_ENV)
    os.environ[REDIRECT_ENV] = os.path.join(tmpdir, "all_benchmarks_summary.json")

    try:
        for c in selected:
            ok, actual, note = run_claim(c, TIMEOUT_SLOW if args.full else TIMEOUT_QUICK)
            if ok is None:
                # 不可机验的对外量化陈述 = 违反验收第 8 条「100% 可指回」，必须计红。
                mark = "UNVERIFIABLE"
                fails.append(c["id"])
            else:
                mark = "PASS" if ok else "FAIL"
                if ok:
                    verified += 1
                else:
                    fails.append(c["id"])
            print("  [%s] %-22s 期望 %-18s 实测 %-12s %s"
                  % (mark, c["id"], c.get("期望", ""), actual or "-", note))
    finally:
        if prev_redirect is None:
            os.environ.pop(REDIRECT_ENV, None)
        else:
            os.environ[REDIRECT_ENV] = prev_redirect
        shutil.rmtree(tmpdir, ignore_errors=True)
        now_write = restore_if_changed(guard_snap)

    if now_write:
        print()
        print("[WARN] 机验命令改写了 %d 个受保护产物，已自动还原（验证不得有副作用）："
              % len(now_write))
        for rel in now_write:
            print("       - %s" % rel)
        print("       若确需刷新这些产物，请显式跑 data/ctf_benchmark/run_all_benchmarks.py，"
              "不要借道本门禁。")
        if args.strict_isolation:
            fails.append("isolation")

    for c in skipped:
        print("  [SKIP] %-22s %s（slow，需 --full）" % (c["id"], c.get("期望", "")))

    print()
    if fails:
        claim_fails = [f for f in fails if f != "isolation"]
        if claim_fails:
            print("结论：FAIL —— %d 条陈述不可机验或与实测不符：%s"
                  % (len(claim_fails), ", ".join(claim_fails)))
            print("处置：数字漂移应**改材料**；若确属测量口径变更，须在 "
                  "`口径修复清单.md` 登记后再改本表期望值。")
            print("      缺 command/pattern 的陈述应改列到「人工核验表」，"
                  "留在机验表里即为未兑现的对外陈述。")
        if "isolation" in fails:
            print("结论：FAIL —— 机验命令改写了受保护产物（--strict-isolation 已开启）。")
            print("处置：让该命令支持输出重定向（如 run_all_benchmarks.py --summary-out），"
                  "或在门禁侧追加 REDIRECT_ENV，不得让验证污染被验证的产物。")
        return 1
    print("结论：PASS —— 本次机验的 %d 条量化陈述全部可复现（另有 %d 条 slow 跳过）。"
          % (verified, len(skipped)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
