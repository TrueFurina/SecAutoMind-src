#!/usr/bin/env python3
"""A/B 对照：基线 vs P0 修复后，逐题比对解题来源(layer)。

只信 sha256_match + layer 两字段，不做任何明文判分。
用法:
  python3 scripts/compare_runs_ab.py BASELINE.json P0RUN.json
"""
import json, sys

def load(path):
    d = json.load(open(path, encoding="utf-8"))
    res = d["results"]
    by_id = {}
    for r in res:
        by_id[r["id"]] = r
    return d, by_id

def summarize(tag, d):
    res = d["results"]
    hits = [r for r in res if r.get("sha256_match")]
    l2 = [r["id"] for r in hits if r.get("layer") == "l2"]
    l3 = [r["id"] for r in hits if r.get("layer") == "l3"]
    total = d.get("total", len(res))
    skipped = d.get("skipped", 0)
    execd = total - skipped
    print(f"[{tag}] total={total} skipped={skipped} executed={execd} "
          f"hit={len(hits)} engine_rate={100*len(hits)/total:.1f}%")
    print(f"    L2 hits (skill, 零token): {l2}")
    print(f"    L3 hits (pure LLM wins): {l3}")
    return hits, l2, l3

if __name__ == "__main__":
    base_p, p0_p = sys.argv[1], sys.argv[2]
    bd, b_by = load(base_p)
    pd, p_by = load(p0_p)

    bh, bl2, bl3 = summarize("BASELINE", bd)
    ph, pl2, pl3 = summarize("P0", pd)

    # 逐题变动：P0 新命中(BASELINE 未命中) 的题
    base_hit_ids = {r["id"] for r in bh}
    new_hits = [r for r in ph if r["id"] not in base_hit_ids]
    # 基线是命中、P0 掉回未命中的题(回归)
    p0_hit_ids = {r["id"] for r in ph}
    regressed = [r["id"] for r in bh if r["id"] not in p0_hit_ids]

    print("\n=== 变动 ===")
    print(f"P0 新命中(BASELINE 未命中): {[ (r['id'], r.get('layer')) for r in new_hits ]}")
    print(f"P0 回归(BASELINE 命中但 P0 未命中): {regressed}")
    pure_llm_wins = [r["id"] for r in new_hits if r.get("layer") == "l3"]
    print(f"\n>>> 纯 LLM 真赢(layer=l3 且 BASELINE 未命中): {pure_llm_wins}")

    if pure_llm_wins:
        print("结论: P0 修复使纯 LLM 解出数 > 0，方向有效，可继续放大。")
    elif new_hits:
        print("结论: P0 出现新命中但全部来自 L2 skill(零token)，属 L2 非确定性波动，"
              "不能算 P0 功劳 / 不能算 LLM 解出率。")
    else:
        print("结论: P0 对真实解题数零贡献(engine 率未变)。"
              "死锁解除只是行为层，R3(模型知识/codegen 天花板)才是真墙。")
