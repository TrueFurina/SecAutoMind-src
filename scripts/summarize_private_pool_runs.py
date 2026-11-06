#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""把多轮私有题池跑批结果汇总成可引用表格（只读，不改任何 verdict）。

为什么要单独一个脚本：跑批率一出来，最容易被误读的就是「未解 = 不会」。
本脚本把未解拆成三类，并把「空答」里能机验的重复退化标出来——
因为实测（2026-11-07 40 题三轮）7 个未解里有 5 个是**模型原地重复同一句话
直到输出预算耗尽**，那是解码病理，不是能力边界。不拆开写，这个数字对外
就是错的口径。

三类未解（判据全部来自结果文件本身，不做主观归因）：
  EMPTY        got 为空字符串 —— 模型没有交出任何 flag 形态的答案
  REPEAT       在 EMPTY 之上，raw_head 里出现同一 24 字符片段 >= 3 次
               （机验：只能看到 raw_head 前 300 字符，属**下界**估计）
  WRONG        交了答案但与 flag_sha256 不符

用法：
  python scripts/summarize_private_pool_runs.py --pool <池> \
      --result <r1.json> [--result <r2.json> ...] [--md out.md]
退出码：0 正常 / 2 用法或文件错误。池与结果题 id 集合不一致即判错（fail-closed）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_pool(path):
    d = json.load(open(path, encoding="utf-8"))
    probs = d.get("problems", {})
    return {k: {"category": v.get("category", "?"),
                "difficulty": v.get("difficulty", "?")} for k, v in probs.items()}


def load_result(path):
    d = json.load(open(path, encoding="utf-8"))
    rows = d.get("details") or d.get("results") or []
    return {r["id"]: r for r in rows if "id" in r}


def repeated_garbage(text, gram=24, limit=3):
    """raw_head 里同一 gram 片段重复 >= limit 次即判重复退化（下界估计）。"""
    if not text or len(text) < gram * limit:
        return False
    seen = Counter(text[i:i + gram] for i in range(len(text) - gram + 1))
    return bool(seen) and seen.most_common(1)[0][1] >= limit


def classify(row):
    got = (row.get("got") or "").strip()
    if row.get("solved"):
        return "SOLVED"
    if not got:
        return "REPEAT" if repeated_garbage(row.get("raw_head") or "") else "EMPTY"
    return "WRONG"


def pct(a, b):
    return "%.1f%%" % (100.0 * a / b) if b else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", required=True)
    ap.add_argument("--result", action="append", required=True)
    ap.add_argument("--label", action="append", default=None,
                    help="每轮的标签（可选，默认用文件名）")
    ap.add_argument("--md", default=None)
    a = ap.parse_args()

    if not os.path.isfile(a.pool):
        print("池不存在: %s" % a.pool, file=sys.stderr)
        return 2
    pool = load_pool(a.pool)
    if not pool:
        print("池为空，拒绝出表（fail-closed）", file=sys.stderr)
        return 2
    labels = a.label or [os.path.basename(p).split(".")[0] for p in a.result]
    runs = []
    for p in a.result:
        if not os.path.isfile(p):
            print("结果不存在: %s" % p, file=sys.stderr)
            return 2
        runs.append(load_result(p))
    for label, r in zip(labels, runs):
        missing = set(pool) - set(r)
        extra = set(r) - set(pool)
        if missing or extra:
            print("[FAIL] %s 题 id 与池不一致：缺 %d 题、多 %d 题"
                  % (label, len(missing), len(extra)), file=sys.stderr)
            return 2

    out = []
    w = out.append
    n = len(pool)
    w("# 私有题池跑批汇总（%d 题 × %d 轮）" % (n, len(runs)))
    w("")
    w("> 由 `scripts/summarize_private_pool_runs.py` 从结果文件机算；"
      "未解已按 EMPTY / REPEAT / WRONG 拆开。REPEAT 为**下界**（只看得到 raw_head 300 字符）。")
    w("")
    w("## 一、每轮总览")
    w("")
    w("| 轮次 | 解出 | 率 | EMPTY | 其中 REPEAT | WRONG | 延迟合计 |")
    w("|---|---|---|---|---|---|---|")
    for label, r in zip(labels, runs):
        cls = Counter(classify(r[i]) for i in pool)
        lat = sum((r[i].get("latency") or 0) for i in pool)
        w("| %s | %d/%d | %s | %d | %d | %d | %.0fs |"
          % (label, cls["SOLVED"], n, pct(cls["SOLVED"], n),
             cls["EMPTY"] + cls["REPEAT"], cls["REPEAT"], cls["WRONG"], lat))
    tot = sum(sum(1 for i in pool if runs[k][i].get("solved")) for k in range(len(runs)))
    w("| **合计** | **%d/%d** | **%s** | | | | |"
      % (tot, n * len(runs), pct(tot, n * len(runs))))
    w("")

    for field, title in (("category", "二、按类别"), ("difficulty", "三、按难度")):
        groups = OrderedDict()
        for pid in sorted(pool):
            groups.setdefault(pool[pid][field], []).append(pid)
        w("## %s" % title)
        w("")
        w("| %s | 题数 | %s | 合计率 |" %
          (field, " | ".join(labels)))
        w("|" + "---|" * (3 + len(runs)))
        for g, ids in groups.items():
            cells = []
            s_all = 0
            for k in range(len(runs)):
                s = sum(1 for i in ids if runs[k][i].get("solved"))
                s_all += s
                cells.append("%d/%d" % (s, len(ids)))
            w("| %s | %d | %s | %s |"
              % (g, len(ids), " | ".join(cells), pct(s_all, len(ids) * len(runs))))
        w("")

    w("## 四、逐题矩阵")
    w("")
    w("| 题 | 类别 | 难度 | %s | 稳定 |" % " | ".join(labels))
    w("|" + "---|" * (4 + len(runs)))
    mark = {"SOLVED": "O", "WRONG": "X", "EMPTY": "-", "REPEAT": "R"}
    for pid in sorted(pool):
        cells, cls = [], []
        for k in range(len(runs)):
            c = classify(runs[k][pid])
            cls.append(c)
            cells.append(mark[c])
        uniq = set(cls)
        stab = "稳定命中" if uniq == {"SOLVED"} else (
            "从未命中" if "SOLVED" not in uniq else "波动")
        w("| `%s` | %s | %s | %s | %s |"
          % (pid, pool[pid]["category"], pool[pid]["difficulty"],
             " | ".join(cells), stab))
    w("")
    w("图例：O=解出　X=答错　-=空答　R=空答且文本重复退化")
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
