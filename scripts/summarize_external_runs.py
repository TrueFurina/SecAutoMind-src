#!/usr/bin/env python3
"""外部赛题池多轮 / 多模型结果汇总（只读）。

跟 summarize_private_pool_runs.py 的区别：
  - 支持**同一池上多个模型**（--run label:model:path）
  - 分母按准入审计算（剔除污染与硬不可用），不是简单 len(rows)
  - 单独统计「被预算截断的轮次」——它决定这次读数是工程上限还是能力边界
  - 未解三分类：EMPTY / TRUNCATED / WRONG / NO_TOOL

用法：
  python scripts/summarize_external_runs.py \
      --pool data/questions_external_bench/external_bench.json \
      --audit .workbuddy/tmp/external_pool_readiness.json \
      --run step_s1:step-3.5-flash:runs/step_s1.result.json \
      --run step_s2:step-3.5-flash:runs/step_s2.result.json \
      --out docs/evidence/external_bench_20261107/SUMMARY.md
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_rows(path):
    d = json.load(open(path, encoding="utf-8"))
    return d.get("summary", {}), [r for r in d.get("details", []) if isinstance(r, dict)]


def classify(r):
    """未解原因分类。顺序重要：先判工程因素，再判模型行为。

    API_ERROR 必须排最前：额度耗尽 / 限流 / 403 不等于「不会」，
    2026-11-07 qwen3.8-max 40 题里 29 题是 403，旧口径把它算成 EMPTY，
    读出来就是一个假的 0 分解出率。
    """
    if r.get("solved"):
        return "SOLVED"
    if (r.get("api_error_rounds") or 0) > 0 or (r.get("timeout_rounds") or 0) > 0:
        return "API_ERROR"
    # 回退：2026-11-07 之前产生的结果没有 api_error_rounds 字段，
    # 只能看 raw_head 里的标记（当时内层异常只往文本里塞了这一行）。
    head = str(r.get("raw_head") or "")
    if "(llm_error:" in head or "(llm_hard_deadline:" in head:
        return "API_ERROR"
    rounds = r.get("llm_rounds") or []
    trunc = sum(1 for x in rounds if x.get("finish_reason") == "length")
    got = str(r.get("got") or "").strip()
    if trunc and (r.get("truncated_rounds") or trunc):
        return "TRUNCATED"
    if r.get("error"):
        return "ERROR"
    if not rounds:
        return "NO_RESPONSE"
    if not r.get("tool_calls"):
        return "NO_TOOL"
    if not got:
        return "EMPTY"
    return "WRONG"


def pct(a, b):
    return 0.0 if not b else a / b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="data/questions_external_bench/external_bench.json")
    ap.add_argument("--audit", default=".workbuddy/tmp/external_pool_readiness.json")
    ap.add_argument("--run", action="append", default=[], metavar="LABEL:MODEL:PATH")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    pool = json.load(open(os.path.join(ROOT, args.pool), encoding="utf-8"))
    probs = pool.get("problems", pool)
    meta = {k: v for k, v in (probs.items() if isinstance(probs, dict) else
                              [(p["id"], p) for p in probs])}

    admissible = None
    tiers = {}
    if os.path.exists(os.path.join(ROOT, args.audit)):
        audit = json.load(open(os.path.join(ROOT, args.audit), encoding="utf-8"))
        admissible = set()
        bad = set(audit["tiers"]["C_contaminated"]) | set(audit["tiers"]["D_hard_unavailable"])
        admissible = {pid for pid in meta if pid not in bad}
        tiers = audit["tiers"]

    runs = []
    for spec in args.run:
        label, model, path = spec.split(":", 2)
        p = path if os.path.isabs(path) else os.path.join(ROOT, path)
        if not os.path.exists(p):
            print("跳过（不存在）: %s" % path, file=sys.stderr)
            continue
        summ, rows = load_rows(p)
        ids = {r["id"] for r in rows}
        unknown = ids - set(meta)
        if unknown:
            print("题 id 不属于本池（判红）: %s -> %s" % (label, sorted(unknown)[:5]), file=sys.stderr)
            return 2
        # 🔴 模型自证：--run 里声明的模型必须出现在结果文件自己记录的 models_used 里。
        # 否则就是「表里写 A、文件里跑的是 B」的误标（2026-11-07 dashscope 下 --model
        # 覆盖时日志头打默认值，正是这个坑）。宁可判红，不可出一张标错模型的对照表。
        used = summ.get("models_used")
        if used and model not in used:
            print("模型误标（判红）: %s 声明 %r，结果文件 models_used=%s"
                  % (label, model, used), file=sys.stderr)
            return 2
        runs.append({"label": label, "model": model, "path": path, "summary": summ, "rows": rows})

    if not runs:
        print("没有可用结果文件", file=sys.stderr)
        return 2

    lines = []
    w = lines.append
    w("# 外部赛题池跑批汇总（机器生成）")
    w("")
    w("池：`%s`  题数 %d  可计分分母 %s" %
      (args.pool, len(meta), len(admissible) if admissible is not None else "N/A"))
    w("")

    # ── 总表 ─────────────────────────────────────────────
    w("## 一、总体")
    w("")
    hdr = ("| 轮次 | 模型 | 解出 | rate(全池) | rate(可计分) | API失败 | 截断题 | 空答/无工具 | 平均耗时 |")
    w(hdr)
    w("|" + "---|" * 9)
    tot = {}
    # 全表统一的分类入口：先判「已解出」，再判「这题本来就不该计分」。
    # NOT_ADMISSIBLE 是给污染/硬不可用题用的 —— 它们**不是**模型放弃，
    # 混进 EMPTY 会让「模型空答」这种结论直接失真（F-13 同类：分母资格）。
    def cls(x):
        if x.get("solved"):
            return "SOLVED"
        if admissible is not None and x["id"] not in admissible:
            return "NOT_ADMISSIBLE"
        return classify(x)

    for r in runs:
        rows = r["rows"]
        solved = sum(1 for x in rows if x.get("solved"))
        cls_list = [cls(x) for x in rows]
        trunc = sum(1 for c in cls_list if c == "TRUNCATED")
        empty = sum(1 for c in cls_list if c in ("EMPTY", "NO_TOOL", "NO_RESPONSE"))
        lat = [x.get("latency") or 0 for x in rows]
        # 可计分分母：剔除（污染 + 硬不可用）与（API 失败题）。后者是本轮新增口径，
        # 理由同 classify()：接口挂了不能算模型答错。
        adm_rows = [x for x in rows
                    if (admissible is None or x["id"] in admissible)
                    and classify(x) != "API_ERROR"]
        adm_solved = sum(1 for x in adm_rows if x.get("solved"))
        api_err = sum(1 for c in cls_list if c == "API_ERROR")
        w("| %s | %s | %d/%d | %.3f | %s | %d | %d | %d | %.0fs |" % (
            r["label"], r["model"], solved, len(rows), pct(solved, len(rows)),
            ("%.3f" % pct(adm_solved, len(adm_rows))) if adm_rows else "-",
            api_err, trunc, empty, sum(lat) / len(lat) if lat else 0))
        tot.setdefault(r["model"], [0, 0, 0])
        tot[r["model"]][0] += solved
        tot[r["model"]][1] += len(rows)
        tot[r["model"]][2] += adm_solved

    if len(runs) > 1:
        w("")
        w("### 按模型合计")
        w("")
        w("| 模型 | 解出 | 总题次 | rate |")
        w("|---|---|---|---|")
        for m, (s, n, _a) in tot.items():
            w("| %s | %d | %d | %.3f |" % (m, s, n, pct(s, n)))

    # ── 分档 / 分类 ──────────────────────────────────────
    if tiers:
        w("")
        w("## 二、按结构分档")
        w("")
        A = set(tiers.get("A_static_complete") or [])
        B = set(tiers.get("B_needs_oracle") or [])
        w("| 轮次 | A 静态数据完备 | B 需自建 oracle | 软受限 |")
        w("|---|---|---|---|")
        E = set(tiers.get("E_soft_constrained") or [])
        for r in runs:
            rows = r["rows"]
            a = [x for x in rows if x["id"] in A]
            b = [x for x in rows if x["id"] in B]
            e = [x for x in rows if x["id"] in E]
            fmt = lambda g: "%d/%d (%.0f%%)" % (
                sum(1 for x in g if x.get("solved")), len(g),
                100 * pct(sum(1 for x in g if x.get("solved")), len(g))) if g else "-"
            w("| %s | %s | %s | %s |" % (r["label"], fmt(a), fmt(b), fmt(e)))

    w("")
    w("## 三、按类别")
    w("")
    cats = sorted({str(x.get("category") or "unknown") for r in runs for x in r["rows"]})
    w("| 轮次 | " + " | ".join(cats) + " |")
    w("|" + "---|" * (1 + len(cats)))
    for r in runs:
        cells = []
        for c in cats:
            g = [x for x in r["rows"] if str(x.get("category") or "unknown") == c]
            cells.append("%d/%d" % (sum(1 for x in g if x.get("solved")), len(g)) if g else "-")
        w("| %s | %s |" % (r["label"], " | ".join(cells)))

    # ── 未解明细 ────────────────────────────────────────
    w("")
    w("## 四、未解分类（逐题）")
    w("")
    for r in runs:
        cnt = {}
        for x in r["rows"]:
            c = cls(x)
            if c != "SOLVED":
                cnt[c] = cnt.get(c, 0) + 1
        w("**%s**：%s" % (r["label"],
                          " / ".join("%s %d" % (k, v) for k, v in sorted(cnt.items())) or "全解出"))
        w("")
        detail = [(x["id"], cls(x), x.get("tool_calls") or 0,
                   round(x.get("latency") or 0), x.get("truncated_rounds") or 0)
                  for x in r["rows"] if not x.get("solved")]
        if detail:
            w("| 题 | 分类 | tool_calls | 耗时 | 截断轮次 |")
            w("|---|---|---|---|---|")
            for pid, c, tc, lat, tr in sorted(detail, key=lambda t: t[1]):
                w("| %s | %s | %d | %ds | %d |" % (pid, c, tc, lat, tr))
            w("")

    text = "\n".join(lines) + "\n"
    if args.out:
        p = os.path.join(ROOT, args.out)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write(text)
        print("写出 %s" % args.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
