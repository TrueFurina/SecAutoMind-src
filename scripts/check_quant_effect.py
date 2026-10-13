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

用法:
    python scripts/check_quant_effect.py            # quick（CI 默认）
    python scripts/check_quant_effect.py --full     # 含 slow
    python scripts/check_quant_effect.py --list     # 只列声明不跑
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "quant_effect.md")

# 每条 claim 跑命令的超时（秒）
TIMEOUT_SLOW = 600
TIMEOUT_QUICK = 300


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

    fails = []
    for c in selected:
        ok, actual, note = run_claim(c, TIMEOUT_SLOW if args.full else TIMEOUT_QUICK)
        mark = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
        print("  [%s] %-22s 期望 %-18s 实测 %-12s %s"
              % (mark, c["id"], c.get("期望", ""), actual or "-", note))
        if not ok and ok is not None:
            fails.append(c["id"])

    for c in skipped:
        print("  [SKIP] %-22s %s（slow，需 --full）" % (c["id"], c.get("期望", "")))

    print()
    if fails:
        print("结论：FAIL —— %d 条陈述与实测不符：%s" % (len(fails), ", ".join(fails)))
        print("处置：数字漂移应**改材料**；若确属测量口径变更，须在 "
              "`口径修复清单.md` 登记后再改本表期望值。")
        return 1
    print("结论：PASS —— 本次机验的 %d 条量化陈述全部可复现。" % len(selected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
