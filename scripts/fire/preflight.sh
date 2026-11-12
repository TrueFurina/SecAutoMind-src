#!/usr/bin/env bash
# preflight.sh — 受控跑批前的「零成本」预检（在服务器 /home/user/SecAutoMind 下运行）
#
# 目的：在真正花 OpenRouter 额度跑 batch2_openrouter.sh 之前，先把所有「会白烧」的
#       配置错误拦在门外。任一项不过直接 exit 非 0，并给出可执行的修复提示。
#
# 覆盖 batch2 本身不覆盖（或只在中途才暴露）的坑：
#   1) 二进制是否真的复制成了 llmbench_withp0 / llmbench_nop0（忘了 scp/cp 会中途崩）
#   2) 二进制能否启动（-h 不 panic）
#   3) 关键环境变量是否设置，且模型 slug 不是已证无效的 deepseek-reasoner
#   4) OpenRouter /credits 真实 > 0（与 batch2 的护栏同源，但先单独确认）
#   5) 网络可达 openrouter.ai
#   6) 源 ids 文件存在且非空
#   7) （可选，默认开）对 1 个 id 做真·冒烟：确认真打通、用对模型、非全 SKIP
#
# 用法：
#   bash preflight.sh            # 含 1-id 冒烟（极少量额度，仅验证链路）
#   bash preflight.sh --no-smoke # 跳过冒烟，纯静态预检（零额度消耗）
set -u
cd /home/user/SecAutoMind 2>/dev/null || { echo "!!! 当前目录不是 /home/user/SecAutoMind，请先 cd 过去"; exit 3; }
KEY_PATH=/home/user/.openrouter_key

PASS=0
FAIL=0
warn() { echo "  [!] $*"; FAIL=$((FAIL+1)); }
ok()   { echo "  [✓] $*"; PASS=$((PASS+1)); }

echo "=== preflight: 静态预检 ==="

# ---------- 1) 二进制存在且可执行 ----------
for bin in llmbench_withp0 llmbench_nop0; do
  if [ -x "./$bin" ]; then ok "$bin 存在且可执行"; else warn "$bin 不存在或不可执行（先 scp llmbench_linux 并 cp 成 $bin）"; fi
done

# ---------- 2) 二进制能启动 ----------
if [ -x "./llmbench_withp0" ]; then
  if ./llmbench_withp0 -h >/dev/null 2>&1; then ok "llmbench_withp0 -h 正常启动（无 panic）"; else warn "llmbench_withp0 -h 启动异常"; fi
else
  warn "跳过 -h 检查：llmbench_withp0 不可用"
fi

# ---------- 3) 环境变量与 slug ----------
if [ -n "${RUNNER_LLM_MODEL:-}" ]; then
  if [ "$RUNNER_LLM_MODEL" = "deepseek-reasoner" ]; then
    warn "RUNNER_LLM_MODEL=deepseek-reasoner 在 OpenRouter 上是无效 slug，会 model-not-found 崩；应改为 deepseek/deepseek-chat"
  else
    ok "RUNNER_LLM_MODEL=$RUNNER_LLM_MODEL（含 '/'，格式正确）"
  fi
  # 真实可用性质检：用 1-token 探测确认「本账户」真能调该 slug。
  # 仅查 /api/v1/models 列表不够——那是全站模型，不反映本账户是否 no-provider/区域封锁。
  # 1-token 实测是唯一的权威判据：否则充值后 model-not-found / 402 直接白烧。
  if [ -s "$KEY_PATH" ]; then
    mresp=$(curl -s -m 25 -X POST https://openrouter.ai/api/v1/chat/completions \
      -H "Authorization: Bearer $(cat "$KEY_PATH")" \
      -H "Content-Type: application/json" \
      -d "{\"model\":\"$RUNNER_LLM_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"max_tokens\":1}" 2>/dev/null)
    if printf '%s' "$mresp" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    sys.exit(1 if (d.get('error')) else 0)
except Exception:
    sys.exit(2)" 2>/dev/null; then
      ok "slug $RUNNER_LLM_MODEL 账户 1-token 实测可调（充值后不会白烧）"
    else
      warn "slug $RUNNER_LLM_MODEL 1-token 探测失败（error/超时）—— 充值后必白烧！换成本账户真实可用 slug（本账户实测仅 deepseek/deepseek-chat 可用）"
    fi
  fi
else
  warn "RUNNER_LLM_MODEL 未设置"
fi

[ "${RUNNER_LLM_NO_FALLBACK:-}" = "1" ] && ok "RUNNER_LLM_NO_FALLBACK=1（评测红线已设）" || warn "RUNNER_LLM_NO_FALLBACK 未设成 1（匿名小模型可能冒充强模型 → 假绿）"
[ "${RUNNER_LLM_FALLBACK:-}" = "true" ] && ok "RUNNER_LLM_FALLBACK=true（网关守卫放行所需）" || warn "RUNNER_LLM_FALLBACK 未设成 true（网关可能不放行模型调用）"
[ "${CTF_AIRGAP:-}" = "1" ] && ok "CTF_AIRGAP=1（判分只认零外网执行）" || warn "CTF_AIRGAP 未设成 1"

# ---------- 4) key + 余额 ----------
if [ -s "$KEY_PATH" ]; then ok "$KEY_PATH 存在且非空"; else warn "$KEY_PATH 不存在或为空"; fi

total=""
if [ -s "$KEY_PATH" ]; then
  resp=$(curl -s -m 20 -H "Authorization: Bearer $(cat "$KEY_PATH")" https://openrouter.ai/api/v1/credits 2>/dev/null)
  total=$(printf '%s' "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(float(d.get('data',{}).get('total_credits',0)))" 2>/dev/null)
  echo "  OpenRouter total_credits=${total:-?}"
  if python3 - "$total" <<'PY' 2>/dev/null
import sys
v=float(sys.argv[1])
sys.exit(0 if v>0 else 1)
PY
  then ok "余额 > 0，可跑批"; else warn "余额 <= 0 或不可达：先去 openrouter.ai 充值，再跑"; fi
else
  warn "无法查余额（key 缺失）"
fi

# ---------- 5) 网络可达 ----------
if curl -s -m 10 -o /dev/null -w "%{http_code}" https://openrouter.ai/api/v1/credits >/dev/null 2>&1; then
  ok "网络可达 openrouter.ai"
else
  warn "网络不可达 openrouter.ai（DNS/代理/防火墙问题）"
fi

# ---------- 6) 源 ids 文件 ----------
IDS_SRC=/home/user/SecAutoMind/.p0_ids.txt
if [ -s "$IDS_SRC" ]; then
  n=$(python3 -c "import re;print(len([i for i in re.split(r'[,\s]+',open('$IDS_SRC',encoding='utf-8',errors='ignore').read()) if i.strip()]))" 2>/dev/null || echo 0)
  ok "源 ids 文件存在，含 $n 个 id"
  [ "${n:-0}" -gt 0 ] 2>/dev/null || warn "源 ids 文件解析到 0 个 id"
else
  warn "源 ids 文件 $IDS_SRC 不存在或为空"
fi

# ---------- 7) 可选：1-id 真·冒烟 ----------
SMOKE=1
[ "${1:-}" = "--no-smoke" ] && SMOKE=0
if [ "$SMOKE" = "1" ] && [ -x "./llmbench_withp0" ] && [ -s "$IDS_SRC" ]; then
  echo "=== preflight: 1-id 冒烟（极少量额度，验证真实链路） ==="
  one=$(python3 -c "import re;print([i for i in re.split(r'[,\s]+',open('$IDS_SRC',encoding='utf-8',errors='ignore').read()) if i.strip()][0])" 2>/dev/null)
  if [ -n "$one" ]; then
    sm_out=/tmp/preflight_smoke.json
    ./llmbench_withp0 -real data/questions_external_bench/external_bench.json \
      -ids <(echo "$one") -att-root data/questions_external_bench/_attachments \
      -out "$sm_out" -with-skills -with-l2 >/tmp/preflight_smoke.log 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then warn "冒烟进程退出码 $rc（见 /tmp/preflight_smoke.log）";
    else
      tot=$(python3 -c "import json;print(len(json.load(open('$sm_out')).get('results',[])))" 2>/dev/null || echo 0)
      skip=$(python3 -c "import json;print(sum(1 for r in json.load(open('$sm_out')).get('results',[]) if r.get('skipped')))" 2>/dev/null || echo 0)
      if [ "$tot" = "0" ]; then warn "冒烟无结果（tot=0）";
      elif [ "$skip" = "$tot" ]; then warn "冒烟全 SKIP（查 /tmp/preflight_smoke.log：额度? 模型名? 402?）";
      else ok "冒烟有真实结果（tot=$tot skip=$skip）—— 链路打通，可放 batch2"; fi
    fi
  else
    warn "取不到首个 id，跳过冒烟"
  fi
else
  echo "（跳过冒烟：--no-smoke 或 二进制/ids 不可用）"
fi

echo "=== preflight 汇总：通过 $PASS / 失败 $FAIL ==="
[ "$FAIL" -eq 0 ] && { echo "✅ 全部通过，可以跑 batch2_openrouter.sh"; exit 0; } || { echo "❌ 有 $FAIL 项未过，先修再跑"; exit 1; }
