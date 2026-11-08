#!/usr/bin/env python3
"""把 overnight 批次的所有结果 json 汇总成一页 STATUS.md。

早上起来只需要看这一个文件：
  1. 进度（完成几个任务、还剩多少时间）
  2. 每个任务的读数（解出 / 可计分分母 / 接口失败 / 截断 / 零工具调用 / 中位耗时）
  3. 到底解出了哪些题、哪个模型解的
  4. 哪些题**所有模型都没解出**（可能是题本身需交互，或能力边界）
  5. 台账尾部（有没有被跳过的任务）

统计口径与 summarize_external_runs.py 保持一致：
  - 接口失败 / 超时不算答错，剔出可计分分母
  - 污染题与硬不可用题剔出分母
"""
import argparse
import glob
import json
import os
import statistics
import time


def load_audit(path):
    try:
        d = json.load(open(path, encoding="utf-8"))
        t = d.get("tiers") or {}
        bad = set(t.get("C_contaminated") or []) | set(t.get("D_hard_unavailable") or [])
        return bad
    except Exception:
        return set()


def classify(r, bad):
    if r.get("id") in bad:
        return "NOT_ADMISSIBLE"
    if (r.get("api_error_rounds") or 0) > 0 or (r.get("timeout_rounds") or 0) > 0:
        return "API_ERROR"
    if r.get("solved"):
        return "SOLVED"
    if (r.get("truncated_rounds") or 0) > 0:
        return "TRUNCATED"
    if (r.get("tool_calls") or 0) == 0:
        return "NO_TOOL"
    if not (r.get("got") or "").strip():
        return "EMPTY"
    return "WRONG"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--audit", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ledger", default="")
    a = ap.parse_args()

    bad = load_audit(a.audit) if a.audit else set()
    files = sorted(glob.glob(os.path.join(a.results, "*.result.json")))

    rows, solved_by, corrupt = [], {}, []
    for p in files:
        name = os.path.basename(p).replace(".result.json", "")
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            corrupt.append(name)
            continue
        s = d.get("summary") or {}
        det = d.get("details") or []
        if not det:
            corrupt.append(name)
            continue
        cls = [classify(r, bad) for r in det]
        adm = [r for r, c in zip(det, cls) if c not in ("NOT_ADMISSIBLE", "API_ERROR")]
        adm_solved = sum(1 for r in adm if r.get("solved"))
        lat = [r.get("latency") or 0 for r in det]
        rows.append({
            "name": name,
            "model": ",".join(s.get("models_used") or [s.get("model") or "?"]),
            "budget": s.get("max_tokens"),
            "total": len(det),
            "solved": s.get("solved", sum(1 for r in det if r.get("solved"))),
            "adm_total": len(adm),
            "adm_solved": adm_solved,
            "api": sum(1 for c in cls if c == "API_ERROR"),
            "na": sum(1 for c in cls if c == "NOT_ADMISSIBLE"),
            "trunc": sum(1 for c in cls if c == "TRUNCATED"),
            "zero": sum(1 for r in det if (r.get("tool_calls") or 0) == 0),
            "lat": round(statistics.median(lat)) if lat else 0,
            "sha": (s.get("code_sha256") or "-")[:8],
        })
        for r in det:
            if r.get("solved"):
                solved_by.setdefault(r["id"], []).append(name)

    all_ids = set()
    for p in files:
        try:
            d = json.load(open(p, encoding="utf-8"))
            for r in d.get("details") or []:
                all_ids.add(r.get("id"))
        except Exception:
            pass
    never = sorted(all_ids - set(solved_by) - bad)

    L = []
    L.append("# Overnight 批次状态")
    L.append("")
    L.append("更新时间：%s（服务器本地时间）" % time.strftime("%Y-%m-%d %H:%M:%S"))
    L.append("")
    L.append("完成结果文件 %d 个；解出过的题 **%d** 道；所有模型都没解出的题 **%d** 道。"
             % (len(rows), len(solved_by), len(never)))
    L.append("")
    L.append("口径：接口失败/超时**不算答错**，已剔出可计分分母；污染题与硬不可用题同样剔出。")
    L.append("")
    L.append("## 各任务读数")
    L.append("")
    L.append("| 任务 | 模型 | 预算 | 解出 | 可计分 | rate | 接口失败 | 非计分 | 截断 | 零工具 | 中位耗时 | 代码 |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda x: x["name"]):
        rate = ("%.3f" % (r["adm_solved"] / r["adm_total"])) if r["adm_total"] else "-"
        L.append("| %s | %s | %s | %d/%d | %d/%d | %s | %d | %d | %d | %d | %ss | %s |"
                 % (r["name"], r["model"], r["budget"], r["solved"], r["total"],
                    r["adm_solved"], r["adm_total"], rate, r["api"], r["na"],
                    r["trunc"], r["zero"], r["lat"], r["sha"]))
    L.append("")

    L.append("## 解出清单")
    L.append("")
    if solved_by:
        for pid in sorted(solved_by):
            L.append("- `%s` ← %s" % (pid, ", ".join(sorted(set(solved_by[pid])))))
    else:
        L.append("（暂无）")
    L.append("")

    L.append("## 所有模型都没解出的题")
    L.append("")
    L.append("共 %d 道。这些题要么需要交互式环境，要么超出当前能力；" % len(never))
    L.append("不能单凭这份清单判断「不可解」，但可以据此判断下一步该换维度。")
    L.append("")
    if never:
        L.append("```")
        for pid in never:
            L.append(pid)
        L.append("```")
    L.append("")

    if corrupt:
        L.append("## 结果文件损坏（被 timeout 杀掉或写一半）")
        L.append("")
        for c in corrupt:
            L.append("- %s" % c)
        L.append("")

    if a.ledger and os.path.exists(a.ledger):
        L.append("## 台账尾部")
        L.append("")
        L.append("```")
        with open(a.ledger, encoding="utf-8", errors="replace") as f:
            lines = f.read().strip().splitlines()
        for ln in lines[-25:]:
            L.append(ln)
        L.append("```")
        L.append("")

    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L[:8]))


if __name__ == "__main__":
    main()
