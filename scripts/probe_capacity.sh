#!/bin/bash
# 容量探测：用**真实请求规模**（真附件 + 真轮次）逐模型打两题，看谁还能用。
# 为什么不能信 64-token 的探针：2026-11-07 早上探针 8/10 通过，但真跑 39/40 是 403
# —— 小请求吃的是免费额度的残余，真实 agentic 请求（单题 prompt 4 万 token 级）直接超额。
set -u
export PYTHONUNBUFFERED=1
ROOT=/home/user/sam_runs/capprobe
mkdir -p "$ROOT"
RUN=/home/user/sam_runs/run.sh
ORCH=scripts/ctf_stepfun_orchestrator.py
BENCH=data/questions_external_bench/external_bench.json
ART=data/questions_external_bench/_attachments
IDS=ext_gctf2022_enigma,ext_gctf2023_mhk2

run_one() {  # provider model tag
    local prov=$1 model=$2 tag=$3
    sudo -u ctfsbx env PYTHONUNBUFFERED=1 timeout 600 "$RUN" "$ORCH" \
        --provider "$prov" --model "$model" --benchmark "$BENCH" \
        --artifact-dir "$ART" --only-ids "$IDS" --concurrency 2 \
        --timeout 240 --max-iter 3 --max-tokens 16384 --wall-budget 600 \
        --agentic --slice capprobe --out "$ROOT/$tag.json" > "$ROOT/$tag.log" 2>&1
}

run_one dashscope qwen3.8-27b q27 &
run_one dashscope deepseek-v4-flash-0731 ds31 &
run_one dashscope kimi-k3 kimi &
run_one dashscope qwen3.8-flash qf &
run_one dashscope MiniMax-M2.5 mm &
run_one dashscope qwen3.8-2.4t-a95b t24 &
run_one dashscope qwen3.5-35b-a3b q35 &
run_one dashscope qwen3.7-plus q37p &
run_one stepfun step-3.5-flash step &
wait

python3 - <<'PY'
import glob, json, os
print("%-8s %-9s %-9s %-7s %s" % ("tag", "solved", "apierr", "tokens", "first_error"))
for p in sorted(glob.glob('/home/user/sam_runs/capprobe/*.json')):
    try:
        d = json.load(open(p))
    except Exception:
        print("%-8s 结果文件损坏" % os.path.basename(p)[:-5]); continue
    det = d.get("details") or []
    ae = sum(1 for r in det if (r.get("api_error_rounds") or 0) > 0 or (r.get("timeout_rounds") or 0) > 0)
    ct = sum((r.get("completion_tokens_total") or 0) for r in det)
    pt = sum((r.get("prompt_tokens_total") or 0) for r in det)
    err = next((str(r.get("api_error_first"))[:70] for r in det if r.get("api_error_first")), "")
    print("%-8s %-9s %-9s %-7s %s" % (os.path.basename(p)[:-5],
          "%d/%d" % (d["summary"]["solved"], d["summary"]["total"]),
          "%d/%d" % (ae, len(det)), "%dk/%dk" % (pt // 1000, ct // 1000), err))
PY
