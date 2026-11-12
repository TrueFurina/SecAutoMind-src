#!/usr/bin/env bash
# Batch 2: 受控 P0 跑批 on OpenRouter（deepseek/deepseek-chat = V3，本账户唯一可用模型；r1 已 no provider）
# 注：withp0 / nop0 实为同一份当前源码编译的二进制复制（P0 死锁修复 diff 已从源码丢失，见 memory 续5），
#     故 A/B 退化为同二进制自比；保留交错结构仅为兼容历史命名。
#
# 相对 batch1 的关键改进（针对 2026-11-12 实测的 402 在途限额崩溃）：
#   1) 启动前先查 OpenRouter /credits，total_credits<=0 直接拒跑，避免白烧一次 23 题的等待。
#   2) 把 23 题按 CHUNK 切块，逐批串行（批内最多 CHUNK 个在途），把在途并发压到可控范围，
#      不再一次灌 23 个在途触发 "would exceed your available credits given your current in-flight requests"。
#   3) 单批若因 402/限额全 SKIP，按指数退避重试（最多 MAX_RETRY 次）—— 等在途请求 settle 后额度释放即可续跑。
#   4) 以"块"为粒度在 withp0 / nop0 间交错，保证 A/B 时间邻近、可比。
#
# 用法：先确保 /home/user/.openrouter_key 有【已充值】的 key，再 nohup bash batch2_openrouter.sh > master.log 2>&1 &
set -u
cd /home/user/SecAutoMind
export PATH=$PATH:/home/user/go1.25.0/bin
export CTF_AIRGAP=1
export RUNNER_LLM_AIRGAP=1
export RUNNER_LLM_FALLBACK=true          # 网关守卫需 true 才放行模型调用（与下方 NO_FALLBACK 不冲突：两道独立闸门）
export RUNNER_LLM_NO_FALLBACK=1          # 评测红线：只走主通道，禁止降级到匿名/备用小模型（否则匿名小模型冒用强模型名 → 假绿）
export RUNNER_LLM_MODEL="deepseek/deepseek-chat"   # 本账户 OpenRouter 实测仅 V3-chat 可用（r1 报 no provider；DeepSeek 旧端点 2026-07-24 退役）。preflight 已用 1-token 实测探测 slug 是否真可调；若账户后续开通 r1 再换回（推理更强，crypto 更优）
export RUNNER_LLM_BASE_URL="https://openrouter.ai/api/v1"
export RUNNER_LLM_API_KEY=$(cat /home/user/.openrouter_key)
export PYTHONIOENCODING=utf-8
# 402/429 同通道退避重试（runnerl3 新能力）：开启后瞬时在途/限流不再立即切通道打崩整轮，
# 而是在同一通道退避重试，与上面的批级退避形成双层防护（批内重试 + 批级退避）。
export RUNNER_LLM_RATELIMIT_RETRY=1
export RUNNER_LLM_RATELIMIT_MAX_RETRIES=8
export RUNNER_LLM_RATELIMIT_BACKOFF_SEC=3

# ---------- 成本护栏（直接回应“烧钱”担忧）----------
# 单题最大轮次 / 工具调用上限：二进制默认是 12 轮，空转题会一直烧到上限。
# 显式卡小可把单题最坏 token 消耗钉死；整批 23 题 × 在途 CHUNK 的总开销因此有硬上限，
# 不会因个别题死循环而失控。预算更紧可调到 6 / 30。
export RUNNER_LLM_MAX_ROUNDS=8
export RUNNER_LLM_MAX_TOOL_CALLS=40

# ---------- 可调参数 ----------
CHUNK=4            # 每批题数（= 最大在途并发上限）。额度小就调小（如 2/3）。
MAX_RETRY=6        # 单批因 402 耗尽额度时的退避重试次数
RETRY_BASE=20      # 退避基数（秒）：第 k 次重试等待 RETRY_BASE * 2^(k-1)
IDS_FILE=/home/user/SecAutoMind/.p0_ids.txt
# 规范化 IDs 文件：支持逗号/空格/换行混合分隔，统一成「每行一个 ID」，
# 否则 split -l CHUNK 会把逗号串当成单行，切块全乱甚至空跑。
NORM_IDS=/tmp/b2_ids_norm.txt
python3 - "$IDS_FILE" "$NORM_IDS" <<'PY'
import sys, re
src = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
ids = [i.strip() for i in re.split(r"[,\s]+", src) if i.strip()]
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(ids) + "\n")
print("规范化得到 %d 个 ID" % len(ids))
PY
IDS_FILE=$NORM_IDS
ATT="data/questions_external_bench/_attachments"
Q="data/questions_external_bench/external_bench.json"

# ---------- 启动前余额护栏 ----------
check_credits() {
  local key; key=$(cat /home/user/.openrouter_key 2>/dev/null || true)
  if [ -z "$key" ]; then echo "!!! 找不到 /home/user/.openrouter_key"; return 1; fi
  local resp; resp=$(curl -s -m 20 -H "Authorization: Bearer $key" \
      https://openrouter.ai/api/v1/credits 2>/dev/null)
  local total; total=$(printf '%s' "$resp" | python3 -c \
      "import sys,json;d=json.load(sys.stdin);print(float(d.get('data',{}).get('total_credits',0)))" 2>/dev/null)
  echo "OpenRouter total_credits=${total:-?}"
  # 数值 > 0 才放行
  python3 - "$total" <<'PY'
import sys
try:
    v=float(sys.argv[1])
except Exception:
    sys.exit(1)
sys.exit(0 if v>0 else 1)
PY
}

if ! check_credits; then
  echo "!!! OpenRouter 余额 <= 0 或不可达：先去 https://openrouter.ai 给该账户充值，再跑本脚本。"
  exit 2
fi

# ---------- 切块 ----------
rm -f /tmp/b2_ids_*.txt
split -l "$CHUNK" "$IDS_FILE" /tmp/b2_ids_
chunks=(/tmp/b2_ids_*)
echo "切块完成：${#chunks[@]} 批，每批约 $CHUNK 题"

# ---------- 单批运行 + 402 退避重试 ----------
run_chunk() {
  local cfg=$1 num=$2 chunkfile=$3
  local out="batch2_${cfg}_${num}.json"
  local log="batch2_${cfg}_${num}.log"
  local attempt=0
  while :; do
    attempt=$((attempt+1))
    echo ">>> [$cfg] chunk#$num attempt#$attempt start $(date -u +%H:%M:%SZ) -> $out"
    ./llmbench_${cfg} -real "$Q" -ids "$chunkfile" -att-root "$ATT" -out "$out" -with-skills -with-l2 > "$log" 2>&1
    local rc=$?
    echo "<<< [$cfg] chunk#$num attempt#$attempt end rc=$rc"
    local tot skip
    tot=$(python3 -c "import json;print(len(json.load(open('$out')).get('results',[])))" 2>/dev/null || echo 0)
    skip=$(python3 -c "import json;print(sum(1 for r in json.load(open('$out')).get('results',[]) if r.get('skipped')))" 2>/dev/null || echo 0)
    echo "    tot=$tot skipped=$skip"
    if [ "$tot" != "0" ] && [ "$skip" = "$tot" ]; then
      if grep -qi "exceed your available credits\|402\|rate limit" "$log"; then
        if [ "$attempt" -lt "$MAX_RETRY" ]; then
          local wait=$(( RETRY_BASE * (2 ** (attempt-1)) ))
          echo "!!! 402/限额：本批全 SKIP，退避 ${wait}s 后重试（attempt $attempt/$MAX_RETRY）"
          sleep "$wait"
          continue
        else
          echo "!!! 已达最大重试次数，放弃本批 [$cfg] chunk#$num"
          return 1
        fi
      else
        echo "!!! 全 SKIP 但非 402（疑为真 LLM 不可用），放弃本批 [$cfg] chunk#$num"
        return 1
      fi
    fi
    return 0
  done
}

# ---------- 主流程：以块粒度在 withp0 / nop0 间交错 ----------
echo "BATCH2 START $(date -u +%H:%M:%SZ)"
ci=0
for cf in "${chunks[@]}"; do
  ci=$((ci+1))
  run_chunk withp0 "$ci" "$cf" || echo "WARN: withp0 chunk $ci 失败（见 batch2_withp0_${ci}.log）"
  run_chunk nop0  "$ci" "$cf" || echo "WARN: nop0 chunk $ci 失败（见 batch2_nop0_${ci}.log）"
done
echo "ALL DONE $(date -u +%H:%M:%SZ)"
