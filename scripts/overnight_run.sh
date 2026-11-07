#!/bin/bash
# 8 小时无人值守跨模型批次（2026-11-07 夜）
#
# 设计原则
#  1) 按「模型」分通道（lane），**通道内串行、通道间并行**：同一模型不会自己和自己抢配额，
#     不同模型互不阻塞。任何一条通道跑崩，其余照跑。
#  2) 每个任务都有三层时限：单次请求 --timeout、单题 --wall-budget、进程级 timeout(1)。
#     最坏情况是「任务被砍」，不是「整夜挂死」。
#  3) 全局 END_TS 硬截止：剩余时间不够就不启动新任务，写 SKIPPED_NO_TIME 进台账。
#  4) 主通道跑完后进入 **补充轮**：只要还没到截止时间就一直加跑重复轮，
#     保证机器跑满（重复轮本身就是方差数据，不是空转）。
#  5) 每完成一个任务重算 STATUS.md；整轮全 403 时写 ALERT（这是历史上真正浪费过一整轮的场景）。
#  6) 所有解题进程以 ctfsbx(995) 运行，与 iptables 的 uid 规则对齐；
#     用 root 跑等于完全绕过隔离。
#
# 说明：2026-11-07 07:55 实测，qwen3.8-max-0902 与 deepseek-v4.1-flash 仍 403
#   （"Free quota exhausted ... disable the 'use free tier only' mode"），属控制台侧开关，
#   不是代码问题，故不放进通道。其余 8 个模型可用。

set -u
export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8

ROOT=/home/user/sam_runs/overnight
RES=$ROOT/results
LOGS=$ROOT/logs
LEDGER=$ROOT/ledger.tsv
RUN=/home/user/sam_runs/run.sh
ORCH=scripts/ctf_stepfun_orchestrator.py          # run.sh 会 cd /home/user/sam
BENCH=data/questions_external_bench/external_bench.json
ART=data/questions_external_bench/_attachments
POOL_AUDIT=$ROOT/pool_readiness.json
STATUS_PY=$ROOT/overnight_status.py
PICK_PY=$ROOT/overnight_pick_ids.py

mkdir -p "$RES" "$LOGS"

# 8 小时总窗，留 20 分钟给收尾汇总
BUDGET=${OVERNIGHT_SECONDS:-28800}
END_TS=$(( $(date +%s) + BUDGET - 1200 ))

log() { echo "[$(date +%H:%M:%S)] $*" >> "$ROOT/master.log"; }
left() { echo $(( END_TS - $(date +%s) )); }

# ── 隔离看门狗 ────────────────────────────────────────────────
# 规则本应常驻，但历史上被手工/意外清过。这里每 5 分钟核一次：
# 一旦 REJECT 规则不见，立即补回并**留痕**（不能悄悄补，否则证据里看不出中间断过）。
isolation_watchdog() {
    local alert=$ROOT/isolation_alerts.log
    while :; do
        if ! iptables -C OUTPUT -m owner --uid-owner 995 -j REJECT \
                --reject-with icmp-port-unreachable 2>/dev/null; then
            echo "[$(date +%H:%M:%S)] MISSING uid=995 REJECT rule -> re-adding" >> "$alert"
            iptables -A OUTPUT -m owner --uid-owner 995 -j REJECT \
                --reject-with icmp-port-unreachable 2>>"$alert"
        fi
        sleep 300
    done
}

# ── 单任务 ────────────────────────────────────────────────────
# run_task NAME MODEL BUDGET REQTIMEOUT ITER CONC MODE WALL
#   MODE = agentic | pure
run_task() {
    local name=$1 model=$2 budget=$3 tmo=$4 iter=$5 conc=$6 mode=$7 wall=$8
    local rem; rem=$(left)
    if [ "$rem" -lt 900 ]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$name" "SKIPPED_NO_TIME" "$rem" "-" "-" >> "$LEDGER"
        log "SKIP  $name (剩余 ${rem}s 不足)"
        return 0
    fi
    local cap=$rem
    [ "$cap" -gt 7200 ] && cap=7200        # 单任务最多 2 小时

    local args=(--provider dashscope --model "$model" --benchmark "$BENCH"
                --artifact-dir "$ART" --concurrency "$conc" --timeout "$tmo"
                --max-iter "$iter" --max-tokens "$budget" --wall-budget "$wall"
                --slice "overnight-${budget}" --out "$RES/$name.result.json")
    [ "$mode" = "agentic" ] && args+=(--agentic)
    # 冒烟/定点重跑用：把整轮缩到固定几题，其余逻辑（限时、台账、状态页）一字不改
    [ -n "${OVERNIGHT_ONLY_IDS:-}" ] && args+=(--only-ids "$OVERNIGHT_ONLY_IDS")

    local t0; t0=$(date +%s)
    log "START $name model=$model budget=$budget tmo=$tmo iter=$iter conc=$conc mode=$mode"
    sudo -u ctfsbx env PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8 \
        timeout -k 30 "$cap" "$RUN" "$ORCH" "${args[@]}" \
        > "$LOGS/$name.log" 2>&1
    local rc=$?
    local dur=$(( $(date +%s) - t0 ))

    local solved="-" apierr="-" total="-"
    if [ -f "$RES/$name.result.json" ]; then
        read -r solved total apierr < <(python3 -c "
import json
try:
    d=json.load(open('$RES/$name.result.json'))
    s=d['summary']; det=d['details']
    ae=sum(1 for r in det if (r.get('api_error_rounds') or 0)>0 or (r.get('timeout_rounds') or 0)>0)
    print('%d/%d %d %d' % (s['solved'], s['total'], s['total'], ae))
except Exception:
    print('? - -')" 2>/dev/null)
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$name" "rc=$rc" "${dur}s" "solved=$solved" "apierr=${apierr}/${total}" >> "$LEDGER"
    log "DONE  $name rc=$rc ${dur}s solved=$solved apierr=${apierr}/${total}"

    # 整轮接口全挂 = 这一轮没有任何能力读数，必须喊出来（历史教训：静默全 0 被当成"模型不会"）
    if [ "$apierr" != "-" ] && [ "$apierr" = "$total" ] && [ "$total" != "-" ]; then
        echo "[$(date +%H:%M:%S)] ALERT $name 全部 $total 题接口失败/超时 -> 本轮无能力读数" >> "$ROOT/alerts.log"
        log "ALERT $name 全题接口失败"
    fi

    python3 "$STATUS_PY" --results "$RES" --audit "$POOL_AUDIT" --out "$ROOT/STATUS.md" --ledger "$LEDGER" \
        > /dev/null 2>&1 || true
}

pick_ids() {
    local what=$1; shift
    python3 "$PICK_PY" --what "$what" "$@" 2>/dev/null
}

# ── 通道主体 ──────────────────────────────────────────────────
# lane_common TAG MODEL ROUNDS DO64 DO_PURE
lane_common() {
    local tag=$1 model=$2 rounds=$3 do64=$4 dopure=$5
    local i
    for i in $(seq 1 "$rounds"); do
        run_task "${tag}_full16k_r${i}" "$model" 16384 600 12 3 agentic 1800
    done
    if [ "$do64" = "1" ]; then
        run_task "${tag}_full64k_r1" "$model" 65536 900 12 2 agentic 2400
    fi
    if [ "$dopure" = "1" ]; then
        run_task "${tag}_pure16k" "$model" 16384 300 1 4 pure 600
    fi

    # 解出题复现：同一模型同一题再跑 3 次，看解出是不是偶然
    local ids; ids=$(pick_ids solved "$RES/${tag}_full16k_r1.result.json" "$RES/${tag}_full16k_r2.result.json")
    if [ -n "$ids" ]; then
        for i in 1 2 3; do
            local rem; rem=$(left)
            [ "$rem" -lt 900 ] && break
            local cap=$rem; [ "$cap" -gt 3600 ] && cap=3600
            local t0; t0=$(date +%s)
            log "START ${tag}_repeat${i} ids=$ids"
            sudo -u ctfsbx env PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8 \
                timeout -k 30 "$cap" "$RUN" "$ORCH" \
                --provider dashscope --model "$model" --benchmark "$BENCH" \
                --artifact-dir "$ART" --only-ids "$ids" --concurrency 2 \
                --timeout 600 --max-iter 12 --max-tokens 16384 --wall-budget 1800 \
                --slice "overnight-repeat-${i}" --agentic \
                --out "$RES/${tag}_repeat${i}.result.json" \
                > "$LOGS/${tag}_repeat${i}.log" 2>&1
            local rc=$?
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "${tag}_repeat${i}" "rc=$rc" \
                "$(( $(date +%s) - t0 ))s" "ids=$ids" "-" >> "$LEDGER"
            log "DONE  ${tag}_repeat${i} rc=$rc"
        done
    else
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "${tag}_repeat" "NO_SOLVED_IDS" "-" "-" "-" >> "$LEDGER"
        log "SKIP  ${tag}_repeat（两轮都没解出，无可复现对象）"
    fi
}

# ── 通道分配（2026-11-07 07:55 实测可用的 8 个模型）────────────
lane_q27()   { lane_common q27   qwen3.8-27b             2 1 1; }
lane_ds31()  { lane_common ds31  deepseek-v4-flash-0731   2 1 1; }
lane_kimi()  { lane_common kimi  kimi-k3                  2 1 1; }
lane_qf()    { lane_common qf    qwen3.8-flash            2 0 1; }
lane_mm()    { lane_common mm    MiniMax-M2.5             2 0 1; }
lane_t24()   { lane_common t24   qwen3.8-2.4t-a95b        2 0 1; }
lane_q35()   { lane_common q35   qwen3.5-35b-a3b          2 0 0; }
lane_q37p()  { lane_common q37p  qwen3.7-plus             2 0 0; }

# 冒烟模式：只用一条通道跑 agentic + pure 各一次，验证限时/台账/状态页/降权全链路。
if [ "${OVERNIGHT_SMOKE:-0}" = "1" ]; then
    lane_q27()   { lane_common smoke qwen3.8-27b 1 0 1; }
    lane_ds31()  { :; }
    lane_kimi()  { :; }
    lane_qf()    { :; }
    lane_mm()    { :; }
    lane_t24()   { :; }
    lane_q35()   { :; }
    lane_q37p()  { :; }
fi

# ── 启动 ──────────────────────────────────────────────────────
{
  echo "=== overnight batch start $(date -Is) ==="
  echo "budget=${BUDGET}s  end=$(date -d @$END_TS -Is)"
} >> "$ROOT/master.log"

iptables -S OUTPUT > "$ROOT/iptables_at_start.txt" 2>&1

isolation_watchdog &
WATCHDOG=$!

lane_q27   & sleep 15
lane_ds31  & sleep 15
lane_kimi  & sleep 15
lane_qf    & sleep 15
lane_mm    & sleep 15
lane_t24   & sleep 15
lane_q35   & sleep 15
lane_q37p  &
wait

# ── 补充轮：主通道跑完后，只要还有时间就一直加跑重复轮（填满整夜）────
if [ "${OVERNIGHT_SMOKE:-0}" != "1" ]; then
    for round in 3 4 5 6; do
        for spec in "q27:qwen3.8-27b" "ds31:deepseek-v4-flash-0731" "kimi:kimi-k3" \
                    "qf:qwen3.8-flash" "mm:MiniMax-M2.5" "t24:qwen3.8-2.4t-a95b" \
                    "q35:qwen3.5-35b-a3b" "q37p:qwen3.7-plus"; do
            [ "$(left)" -lt 1200 ] && break 2
            tag=${spec%%:*}; model=${spec#*:}
            run_task "${tag}_extra_r${round}" "$model" 16384 600 12 3 agentic 1800
        done
    done
fi

kill $WATCHDOG 2>/dev/null

iptables -S OUTPUT > "$ROOT/iptables_at_end.txt" 2>&1
python3 "$STATUS_PY" --results "$RES" --audit "$POOL_AUDIT" --out "$ROOT/STATUS.md" --ledger "$LEDGER" > /dev/null 2>&1 || true
log "=== overnight batch end $(date -Is) ==="
