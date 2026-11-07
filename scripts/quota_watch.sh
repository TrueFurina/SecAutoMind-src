#!/bin/bash
# 额度看门狗：DashScope 一旦解除「仅使用免费额度」，自动启动整夜批次。
#
# 背景（2026-11-07 08:00 实测）：账户已充值，但有 6 个模型仍返回
#   HTTP 403 Free quota exhausted ... disable the "use free tier only" mode
# 这是控制台开关，代码绕不过去。用户睡觉期间若在控制台关闭该开关，
# 本脚本会在下一个探测周期（≤10 分钟）自动把正式批次拉起来。
#
# 探测策略：**用真实请求探测**（1 题、真附件、max_tokens 4096），
# 不用 max_tokens=4 的小探针 —— 实测小探针会在额度耗尽时仍然返回 200（假信号）。
# 403 的探测不消耗额度，只有真正可用时才花钱。
#
# 用 root 启动；每个解题进程以 ctfsbx(995) 运行，与 iptables uid 规则对齐。

set -u
export PYTHONUNBUFFERED=1
ROOT=/home/user/sam_runs/overnight
RUN=/home/user/sam_runs/run.sh
ORCH=scripts/ctf_stepfun_orchestrator.py
BENCH=data/questions_external_bench/external_bench.json
ART=data/questions_external_bench/_attachments
WLOG=$ROOT/quota_watch.log
PROBE_ID=ext_gctf2022_appnote-txt
END_TS=$(( $(date +%s) + ${WATCH_SECONDS:-27000} ))

MODELS="qwen3.8-max-0902 deepseek-v4.1-flash qwen3.8-flash MiniMax-M2.5 qwen3.8-2.4t-a95b qwen3.7-plus"

say() { echo "[$(date +%H:%M:%S)] $*" >> "$WLOG"; }

probe_one() {   # model -> 0 = 真能用
    local m=$1 out=/tmp/qp_$$.json
    rm -f "$out"
    sudo -u ctfsbx env PYTHONUNBUFFERED=1 timeout 240 "$RUN" "$ORCH" \
        --provider dashscope --model "$m" --benchmark "$BENCH" \
        --artifact-dir "$ART" --only-ids "$PROBE_ID" --concurrency 1 \
        --timeout 120 --max-iter 1 --max-tokens 4096 --wall-budget 300 \
        --agentic --slice quota-probe --out "$out" > /dev/null 2>&1
    python3 - "$out" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("BROKEN"); raise SystemExit(1)
r = (d.get("details") or [{}])[0]
if (r.get("api_error_rounds") or 0) > 0 or (r.get("timeout_rounds") or 0) > 0:
    print("BLOCKED"); raise SystemExit(1)
print("OK"); raise SystemExit(0)
PY
    local rc=$?
    rm -f "$out"
    return $rc
}

batch_running() {
    pgrep -f "overnight_run[.]sh" > /dev/null
}

say "watchdog start, end=$(date -d @$END_TS -Is)"
while [ "$(date +%s)" -lt "$END_TS" ]; do
    if batch_running; then
        sleep 600; continue
    fi
    for m in $MODELS; do
        if probe_one "$m"; then
            say "RECOVERED model=$m -> 启动正式批次"
            remaining=$(( END_TS - $(date +%s) ))
            env OVERNIGHT_SECONDS="$remaining" setsid bash -c \
                "bash $ROOT/overnight_run.sh >> $ROOT/master.log 2>&1" < /dev/null &
            sleep 30
            break
        else
            say "still blocked: $m"
        fi
    done
    sleep 600
done
say "watchdog end"
