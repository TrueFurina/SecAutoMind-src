#!/usr/bin/env python3
"""多模型分摊版 held-out 基准（2026-09-17）。

为什么存在
----------
千问AI平台（dashscope）每个模型仅 **1M tokens 免费额度、用尽即停**，而 full-78 实测约 4.8M。
故把题池按模型额度切成 N 批，**每批换一个免费模型**跑，最后合并报告——在零超额成本下拿到全量样本。

配套：
  scripts/benchmark_heldout.py        （选题/脱敏/冷黑板）
  config.DASHSCOPE_FREE_MODELS        （免费模型登记表）
关键：config 的 `_PROVIDER_MODEL_ALLOWLIST['qwen']` 允许 CTF_AGENT_LIGHT/HEAVY_MODEL 覆盖为
     登记在册的 dashscope 模型（否则被端点-模型一致性净化回退默认）。

运行：
  python scripts/benchmark_heldout_multimodel.py                # 默认 10 模型 × 8 题/批
  python scripts/benchmark_heldout_multimodel.py --dry-run      # 只打印分批与 token 估算
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import scripts.benchmark_heldout as bh  # noqa: E402

RESULTS = bh.RESULTS

# 首选强推理/通用免费模型（均 0 消耗档）
DEFAULT_MODELS = [
    "deepseek-v3.1", "deepseek-v3.2-exp", "kimi-k2.6", "kimi-k2-thinking", "kimi-k2.5",
    "qwen3.7-max-preview", "qwen3.7-plus", "glm-5.2", "glm-5.1", "qwen3.6-plus",
    "qwen3.7-max-2026-06-08", "deepseek-r1", "qwen3.6-max-preview", "glm-5",
]


def _chunks(seq, n):
    return [seq[i:i + n] for i in range(0, len(seq), n)]


def _drop_no_input_after_neutralize(cands: list) -> tuple:
    """剔除「脱敏后无真实输入」的题，返回 (可跑题, 被剔除数)。

    为什么需要（2026-10-25 破晓实测）：
      heldout 34 道题里，**33 道的附件在磁盘上不存在**，只有 ``real_reverse_js`` 一道
      的附件真在（``coso.js``）。判定口径与 ``eval.corpus.has_input`` 保持一致：

        - 未登记附件 → 纯文本题，信息在 description 里 → 可跑
        - 登记了附件 → **至少一个文件真实存在**才算有输入

      之前只看「附件是否全是脱敏哨兵」是不够的：28 道题的附件只有 ``flag.txt``
      （脱敏成哨兵），另有 5 道登记了真实附件名（如 ``BeCare4.md``）但**文件本身就不在磁盘上**。
      两类都跑不了，但症状不同，只看哨兵会漏掉后一类。

      不剔除的后果：脚本打印「题池 34 道」，``eval.benchmark`` 里 ``apply_corpus_gate``
      全判 ``no_input`` 跳过，报告写 ``total=0 solved=0``——
      **看起来像「跑了但没解出」，其实是「根本没跑」**。这是最贵的假动作。

    这里提前剔除并显式报数，让分母诚实（口径铁律①：必声明分母）。
    """
    runnable, dropped = [], 0
    for c in cands:
        try:
            q = json.loads((ROOT / c["path"]).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        atts = bh._neutralize(q).get("attachments") or []
        if not atts:
            runnable.append(c)          # 纯文本题
            continue
        if any((ROOT / str(a)).exists() for a in atts):
            runnable.append(c)          # 至少一个附件真实存在
        else:
            dropped += 1                # 登记了附件但一个都不在 → no_input
    return runnable, dropped


def main() -> int:
    ap = argparse.ArgumentParser(description="多模型分摊 held-out 基准")
    ap.add_argument("--models", default=",".join(DEFAULT_MODELS))
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--wallclock", type=float, default=300.0)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--per-batch-budget", type=int, default=900000,
                    help="每批全局 token 上限（须 < 单模型 1M 免费额度）")
    ap.add_argument("--provider", default="qwen")
    ap.add_argument("--limit", type=int, default=0,
                    help="只跑候选池前 N 道（0=全量）。"
                         "用于「先 ≤5 样本估费、再决定是否全量」的纪律动作——"
                         "不设此参数时脚本会跑满 34 道，一次烧掉数小时与数百万 token。")
    ap.add_argument("--external-dir", default="",
                    help="并入外部采源池（传 data/questions_external）。"
                         "不传=只跑 questions_real 能力分母池。")
    # 2026-10-26 A/B 开关（显式可见版）。
    # ⚠️ 更正（本会话实跑核实）：子进程 env 是 `dict(os.environ)` 起底，
    # **外层环境变量本来就会自动继承**——`CTF_AGENT_PRELOAD_ATTACHMENTS=1
    # python benchmark_heldout_multimodel.py` 直接生效，无需本开关。
    # 保留本开关的理由是「可发现性」而非「必要性」：跑批命令行里显式写出实验臂，
    # 比依赖调用方记得 export 更不易漏读；且它写入子进程 env，保证与
    # benchmark 报告里记录的口径一致。默认不置位 = 完全不改环境 = 基线不变。
    ap.add_argument("--preload-attachments", action="store_true", default=None,
                    help="开启框架预读附件注入（A/B 实验臂）。写入子进程 "
                         "CTF_AGENT_PRELOAD_ATTACHMENTS=1；默认关，保证基线 KPI 不变。"
                         "（注：外层同名环境变量本就会被继承，本开关只是显式化。）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    ext_dir = Path(args.external_dir).resolve() if args.external_dir else None
    if ext_dir and not ext_dir.exists():
        print(f"[mm] --external-dir 不存在：{ext_dir}")
        return 2
    if ext_dir:
        print(f"[mm] 并入外部采源池：{ext_dir}")
    cands, _ = bh.select_candidates(require_sha256=True,
                                    include_neutralized=True,
                                    external_dir=ext_dir)
    cands, _dropped = _drop_no_input_after_neutralize(cands)
    if _dropped:
        print(f"[mm] 剔除 {_dropped} 道「脱敏后无输入」的题（附件缺失，或仅 flag.txt）"
              f" -> 真正可跑 {len(cands)} 道")
    if args.limit > 0:
        cands = cands[:args.limit]
        print(f"[mm] --limit {args.limit}：只跑前 {len(cands)} 道（估费模式，不是全量基线）")
    batches = _chunks(cands, args.batch_size)
    est_tokens = len(cands) * 62000  # 实测 ~62K/题（400s 档）
    print(f"[mm] 题池 {len(cands)} 道 -> {len(batches)} 批（批大小 {args.batch_size}）")
    print(f"[mm] 模型池 {len(models)} 个：{models[:len(batches)]}")
    print(f"[mm] 预估 token ≈ {est_tokens:,}（{est_tokens/1e6:.1f}M）；"
          f"免费额度 {len(models)}M（{len(models)} 模型 × 1M）-> 足够")
    for i, b in enumerate(batches):
        print(f"    batch {i+1:2d}: model={models[i % len(models)]:32s} n={len(b)}")
    if args.dry_run:
        return 0

    mm_dir = RESULTS / f"mm_{datetime.now():%Y%m%d_%H%M%S}"
    mm_dir.mkdir(parents=True, exist_ok=True)
    print(f"[mm] 输出目录 {mm_dir}")

    backup = bh._backup_and_clear_blackboard()
    merged: list[dict] = []
    try:
        for i, batch in enumerate(batches):
            model = models[i % len(models)]
            run_dir = mm_dir / f"run_{i:02d}"
            out_dir = mm_dir / f"out_{i:02d}"
            run_dir.mkdir(parents=True, exist_ok=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            for c in batch:
                try:
                    q = json.loads((ROOT / c["path"]).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                q = bh._neutralize(q)
                (run_dir / f"{c['id']}.json").write_text(
                    json.dumps(q, ensure_ascii=False, indent=1), encoding="utf-8")

            env = dict(os.environ)
            env.update({
                "CTF_AGENT_USE_REAL_LLM": "1",
                "CTF_AGENT_LIGHT_MODEL": model,
                "CTF_AGENT_MID_MODEL": model,
                "CTF_AGENT_HEAVY_MODEL": model,
                "CTF_AGENT_GLOBAL_BUDGET": str(args.per_batch_budget),
            })
            # 2026-10-26 A/B 臂：--preload-attachments 置位时显式写入子进程 env。
            # 说明：env 由 dict(os.environ) 起底，外层同名变量本就会继承；
            # 这里显式写一次，是为了让「命令行带了实验臂」与「子进程实际生效」不会因
            # 调用方 export 遗漏而产生「以为开了其实没开」的静默失真。
            if args.preload_attachments:
                env["CTF_AGENT_PRELOAD_ATTACHMENTS"] = "1"
            cmd = [sys.executable, "-m", "eval.benchmark",
                   "--questions-dir", str(run_dir),
                   "--presolve-skip",
                   "--provider", args.provider,
                   "--wallclock", str(args.wallclock),
                   "--results-dir", str(out_dir),
                   "--concurrency", str(args.concurrency)]
            print(f"[mm] === batch {i+1}/{len(batches)} model={model} n={len(batch)} ===", flush=True)
            subprocess.call(cmd, cwd=str(ROOT), env=env)
            rep = out_dir / "benchmark_report.json"
            if rep.exists():
                d = json.loads(rep.read_text(encoding="utf-8"))
                for r in d.get("results", []):
                    r["_model"] = model
                    r["_batch"] = i
                    merged.append(r)
                tk = (d.get("summary", {}).get("tokens", {}) or {}).get("global_total")
                print(f"[mm] batch {i+1} done tokens={tk}", flush=True)
    finally:
        bh._restore_blackboard(backup)

    total = len(merged)
    solved = sum(1 for r in merged if r.get("solved"))
    by_cat: dict = {}
    by_src: dict = {}
    for r in merged:
        c = r.get("category") or "?"
        cs = by_cat.setdefault(c, {"total": 0, "solved": 0})
        cs["total"] += 1; cs["solved"] += 1 if r.get("solved") else 0
        s = r.get("solved_by") or "unknown"
        ss = by_src.setdefault(s, {"total": 0, "solved": 0})
        ss["total"] += 1; ss["solved"] += 1 if r.get("solved") else 0

    combined = {
        "mode": "real_main_agent_multimodel",
        "generated_by": "scripts/benchmark_heldout_multimodel.py",
        "models": models[:len(batches)],
        "total": total, "solved": solved,
        "solve_rate": (solved / total if total else 0.0),
        "by_category": by_cat, "by_solved_by": by_src,
        "results": merged,
    }
    out = mm_dir / "combined_report.json"
    out.write_text(json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[mm] DONE total={total} solved={solved} rate={combined['solve_rate']:.1%} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
