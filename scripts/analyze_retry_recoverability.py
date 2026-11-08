#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""把多轮私有题池结果拆成「pass@1 / pass@k / 空答可恢复率」三个可引用的数。

为什么要单独一个脚本（锐评口径）：
  `summarize_private_pool_runs.py` 出的是**单轮池化率**（解出数 / 总格数），
  它对外的语义是 pass@1。但同一批结果里还藏着两个完全不同的数：

    1. pass@k（任一 rounds 解出即算该题可解）—— 上限，回答「模型会不会」；
    2. 空答恢复率（第 k 轮空答时，第 k+1 轮能不能解出）—— 回答
       「把空答当错误重试一次，能捡回多少」。

  不把这三个数分开写，88.3% 会被两头误读：
    拿它当能力上限 ⇒ 低估（有题只是这一轮没答出来）；
    拿它当工程基线 ⇒ 高估可优化空间（空答**不能**简单靠重试全捡回来）。

判据全部来自结果文件本身，不做主观归因：
  SOLVED     solved=True
  EMPTY      got 为空且 raw_head 无重复退化
  REPEAT     got 为空且 raw_head 里同一 24 字符片段 >= 3 次（下界估计，只看得到前 300 字符）
  WRONG      got 非空但 solved=False

用法：
  python scripts/analyze_retry_recoverability.py --pool <池> \
      --result <r1.json> [--result <r2.json> ...] [--md out.md]
退出码：0 正常 / 2 用法或文件错误（题 id 与池不一致即 fail-closed）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SOLVED, EMPTY, REPEAT, WRONG = "SOLVED", "EMPTY", "REPEAT", "WRONG"
EMPTYISH = (EMPTY, REPEAT)


def load_pool(path):
    d = json.load(open(path, encoding="utf-8"))
    return {k: {"category": v.get("category", "?"),
                "difficulty": v.get("difficulty", "?")}
            for k, v in (d.get("problems") or {}).items()}


def load_result(path):
    d = json.load(open(path, encoding="utf-8"))
    rows = d.get("details") or d.get("results") or []
    return {r["id"]: r for r in rows if "id" in r}


def repeated_garbage(text, gram=24, limit=3):
    if not text or len(text) < gram * limit:
        return False
    seen = Counter(text[i:i + gram] for i in range(len(text) - gram + 1))
    return bool(seen) and seen.most_common(1)[0][1] >= limit


def classify(row):
    if row.get("solved"):
        return SOLVED
    if not (row.get("got") or "").strip():
        return REPEAT if repeated_garbage(row.get("raw_head") or "") else EMPTY
    return WRONG


def pct(a, b):
    return "%.1f%%" % (100.0 * a / b) if b else "n/a"


def clopper_pearson(k, n, z=1.96):
    """二项比例的 95% 区间（小样本必须给区间：7 次里 2 次成功，点估计 28.6% 会骗人）。"""
    if n == 0:
        return (0.0, 1.0)
    if k == 0:
        return (0.0, 1 - 0.5 ** (1.0 / n))
    if k == n:
        return (0.5 ** (1.0 / n), 1.0)
    import math
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - r) / d), min(1.0, (c + r) / d))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", required=True)
    ap.add_argument("--result", action="append", required=True)
    ap.add_argument("--label", action="append", default=None)
    ap.add_argument("--md", default=None)
    a = ap.parse_args()

    if not os.path.isfile(a.pool):
        print("池不存在: %s" % a.pool, file=sys.stderr)
        return 2
    pool = load_pool(a.pool)
    if not pool:
        print("池为空，拒绝出表（fail-closed）", file=sys.stderr)
        return 2
    labels = a.label or [os.path.basename(p).split(".")[0].replace(".result", "")
                         for p in a.result]
    runs = []
    for p in a.result:
        if not os.path.isfile(p):
            print("结果不存在: %s" % p, file=sys.stderr)
            return 2
        runs.append(load_result(p))
    for label, r in zip(labels, runs):
        if set(r) != set(pool):
            print("[FAIL] %s 题 id 与池不一致（缺 %d / 多 %d）"
                  % (label, len(set(pool) - set(r)), len(set(r) - set(pool))),
                  file=sys.stderr)
            return 2
    if len(runs) < 2:
        print("[FAIL] 至少两轮才能算 pass@k 与空答恢复率", file=sys.stderr)
        return 2

    n, R = len(pool), len(runs)
    cls = {lab: {pid: classify(runs[k][pid]) for pid in pool}
           for k, lab in enumerate(labels)}
    out, w = [], None
    w = out.append
    w("# 私有题池：pass@1 / pass@k / 空答可恢复率（%d 题 × %d 轮）" % (n, R))
    w("")
    w("> 全部由 `scripts/analyze_retry_recoverability.py` 从结果文件机算；"
      "不给区间的小样本比例一律视为不可引用。")
    w("")

    # ---- 一、三个口径 ----
    cells = n * R
    solved_cells = sum(1 for k in range(R) for pid in pool if cls[labels[k]][pid] == SOLVED)
    solved_any = [pid for pid in pool if any(cls[labels[k]][pid] == SOLVED for k in range(R))]
    w("## 一、三个口径（同一个池，不同的数）")
    w("")
    w("| 口径 | 值 | 分母 | 含义 |")
    w("|---|---|---|---|")
    w("| pass@1（池化） | %s | %d 格 | 每一格都独立算一次机会 —— 对外报的那个数 |"
      % (pct(solved_cells, cells), cells))
    w("| pass@%d（同轮全解） | %d/%d = %s | %d 题 | 三轮全对才算稳，最严 |"
      % (R, sum(1 for pid in pool if all(cls[labels[k]][pid] == SOLVED for k in range(R))),
         n, pct(sum(1 for pid in pool
                    if all(cls[labels[k]][pid] == SOLVED for k in range(R))), n), n))
    w("| pass@%d（任一解出） | %d/%d = %s | %d 题 | 模型「会不会」的上限，不是成绩 |"
      % (R, len(solved_any), n, pct(len(solved_any), n), n))
    w("")

    # ---- 二、每轮 ----
    w("## 二、每轮分解")
    w("")
    w("| 轮 | 解出 | 率 | 空答 | 其中重复退化 | 答错 |")
    w("|---|---|---|---|---|---|")
    for lab in labels:
        c = Counter(cls[lab].values())
        w("| %s | %d/%d | %s | %d | %d | %d |"
          % (lab, c[SOLVED], n, pct(c[SOLVED], n),
             c[EMPTY] + c[REPEAT], c[REPEAT], c[WRONG]))
    w("")

    # ---- 三、空答可恢复率（本脚本的核心问题）----
    pairs = []          # (pid, k, next_class)
    for pid in sorted(pool):
        for k in range(R - 1):
            if cls[labels[k]][pid] in EMPTYISH:
                pairs.append((pid, labels[k], cls[labels[k + 1]][pid]))
    rec = sum(1 for _, _, nx in pairs if nx == SOLVED)
    lo, hi = clopper_pearson(rec, len(pairs))
    w("## 三、空答当错误重试一次，能捡回多少")
    w("")
    w("口径：第 k 轮判 EMPTY/REPEAT 的格子，看**同一题第 k+1 轮**的结果。"
      "这正是「不改任何东西、只重跑一次」的实测代理。")
    w("")
    if pairs:
        w("- 空答格且存在下一轮：**%d 个**" % len(pairs))
        w("- 下一轮解出：**%d 个 ⇒ 恢复率 %s（95%% CI %s ~ %s）**"
          % (rec, pct(rec, len(pairs)), pct(lo, 1), pct(hi, 1)))
        w("- 下一轮仍是空答：%d 个；下一轮答错：%d 个"
          % (sum(1 for _, _, nx in pairs if nx in EMPTYISH),
             sum(1 for _, _, nx in pairs if nx == WRONG)))
        w("")
        w("| 题 | 空答轮 | 下一轮 |")
        w("|---|---|---|")
        mark = {SOLVED: "O", EMPTY: "-", REPEAT: "R", WRONG: "X"}
        for pid, lab, nx in pairs:
            w("| `%s` | %s | %s |" % (pid, lab, mark[nx]))
        w("")
    else:
        w("- 没有「空答且有下一轮」的格子，本节无结论（不是 0%，是没样本）。")
        w("")

    # ---- 四、空答是不是「想不出来」：用可机验的三个旁证 ----
    w("## 四、空答格的旁证（能不能归因成解码病理）")
    w("")
    empty_rows = [(pid, lab, runs[labels.index(lab)][pid])
                  for pid in pool for lab in labels
                  if cls[lab][pid] in EMPTYISH]
    solved_rows = [(pid, lab, runs[labels.index(lab)][pid])
                   for pid in pool for lab in labels
                   if cls[lab][pid] == SOLVED]
    if empty_rows:
        tc = Counter(int(r.get("tool_calls") or 0) for _, _, r in empty_rows)
        lat_e = [float(r.get("latency") or 0) for _, _, r in empty_rows]
        lat_s = [float(r.get("latency") or 0) for _, _, r in solved_rows]
        w("| 旁证 | 空答格 | 解出格 | 说明 |")
        w("|---|---|---|---|")
        w("| 格数 | %d | %d | — |" % (len(empty_rows), len(solved_rows)))
        w("| tool_calls=0 的格数 | %d | %d | 0 调用 ⇒ 没动手就交卷 |"
          % (sum(v for k, v in tc.items() if k == 0),
             sum(1 for _, _, r in solved_rows if int(r.get("tool_calls") or 0) == 0)))
        w("| 平均延迟 | %.1fs | %.1fs | 空答若显著更短 ⇒ 提前放弃，而非算不动 |"
          % (sum(lat_e) / len(lat_e) if lat_e else 0,
             sum(lat_s) / len(lat_s) if lat_s else 0))
        w("| error 非空 | %d | %d | 非空 ⇒ 是接口/超时，不是能力 |"
          % (sum(1 for _, _, r in empty_rows if (r.get("error") or "").strip()),
             sum(1 for _, _, r in solved_rows if (r.get("error") or "").strip())))
        w("")

    # ---- 五、逐题稳定性 ----
    w("## 五、逐题稳定性")
    w("")
    w("| 题 | 类别 | 难度 | %s | 判定 |" % " | ".join(labels))
    w("|" + "---|" * (4 + R))
    mark = {SOLVED: "O", EMPTY: "-", REPEAT: "R", WRONG: "X"}
    never, flaky = [], []
    for pid in sorted(pool):
        seq = [cls[lab][pid] for lab in labels]
        if all(c == SOLVED for c in seq):
            verdict = "稳定命中"
        elif SOLVED not in seq:
            verdict = "从未命中"
            never.append(pid)
        else:
            verdict = "波动（本轮损失 %d 格）" % sum(1 for c in seq if c != SOLVED)
            flaky.append(pid)
        w("| `%s` | %s | %s | %s | %s |"
          % (pid, pool[pid]["category"], pool[pid]["difficulty"],
             " | ".join(mark[c] for c in seq), verdict))
    w("")
    w("图例：O=解出　-=空答　R=空答且文本重复退化　X=答错")
    w("")
    w("- 稳定命中 %d 题、从未命中 %d 题、波动 %d 题。"
      % (n - len(never) - len(flaky), len(never), len(flaky)))
    if never:
        w("- 从未命中：%s —— 只有这些题的失败可以谈「能力边界」。"
          % ", ".join("`%s`" % p for p in never))
    if flaky:
        w("- 波动：%s —— 单轮没解出不等于不会，引用 pass@1 时必须同时给这一行。"
          % ", ".join("`%s`" % p for p in flaky))
    w("")

    text = "\n".join(out) + "\n"
    if a.md:
        with open(a.md, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("写出 %s（%d 行）" % (os.path.relpath(a.md, ROOT), text.count("\n")))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
