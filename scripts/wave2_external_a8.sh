#!/bin/bash
# 外部池第二轮：固定 8 题切片（A 档 = 静态数据完备）× 多模型跨厂对照
#
# 为什么从 40 题改成 8 题（2026-11-07 实测，不是猜的）：
#   DashScope 免费额度是**每模型 1M tokens**。实测单题 token 消耗（12 轮 agentic，
#   prompt 随轮次累积）在 43k–240k 之间，qwen3.8-max 跑了 11 题就把 1M 烧光，
#   之后 29 题全是 `HTTP 403 Free quota exhausted`。也就是说：
#   跑 40 题 ≈ 只有前 ~10 题是有效读数，后 30 题买的是 403。
#   改成固定 8 题后，每个模型都在额度内跑完，跨模型才可比。
#
# 切片定义：准入审计里的 A 档（附件里给了 output/cipher/pubkey，理论上不交互也能解）
#   共 8 题，全部纳入 —— 这是**最可能可解**的子集，因此解出数只能读成上限的乐观估计，
#   不能读成「难度均衡样本」。
#
# 🔴 必须以 ctfsbx(uid 995) 执行：iptables 规则按 UID 匹配，root 跑等于完全绕过隔离。
set -u
OUT=/home/user/sam_runs
POOL=data/questions_external_bench/external_bench.json
ATT=data/questions_external_bench/_attachments
CTX=/home/user/sam_runs/run.sh
IDS="ext_gctf2021_h1,ext_gctf2021_tiramisu,ext_gctf2022_appnote-txt,ext_gctf2022_enigma,ext_gctf2023_least-common-genominator,ext_gctf2023_mhk2,ext_gctf2024_mceliece,ext_gctf2025_numerology"

run_one() {
  local label="$1" model="$2"
  echo "=== [$(date +%H:%M:%S)] start $label ($model) ids=8 uid=ctfsbx ==="
  sudo -u ctfsbx "$CTX" scripts/ctf_stepfun_orchestrator.py \
      --provider dashscope --model "$model" \
      --benchmark "$POOL" --artifact-dir "$ATT" \
      --only-ids "$IDS" \
      --concurrency 2 --timeout 180 --max-iter 12 --wall-budget 900 --max-tokens 16384 \
      --slice "ext-google-ctf-a8" --out "$OUT/$label.result.json" \
      > "$OUT/$label.log" 2>&1
  local rc=$?
  local solved
  solved=$(python3 -c "
import json
try:
    d=json.load(open('$OUT/$label.result.json'))
    print('%d/%d' % (d['summary']['solved'], d['summary']['total']))
except Exception:
    print('?')
" 2>/dev/null)
  echo "=== [$(date +%H:%M:%S)] done $label rc=$rc solved=$solved ==="
}

lane1() {
  run_one ds41_a8          deepseek-v4.1-flash
  run_one qwen38flash_a8   qwen3.8-flash
  run_one minimax_a8       MiniMax-M2.5
}
lane2() {
  run_one kimik3_a8        kimi-k3
  run_one qwen38_24t_a8    qwen3.8-2.4t-a95b
  run_one qwen38_27b_a8    qwen3.8-27b
}

lane1 &
lane2 &
wait

echo "=== WAVE2 ALL DONE $(date) ==="
