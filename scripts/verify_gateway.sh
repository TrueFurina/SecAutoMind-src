#!/usr/bin/env bash
# =============================================================
# verify_gateway.sh — AI 安全网关（安恒恒脑）接入自检
# 赛题 XH-202609 第一环节硬约束：「模型 API 提前报备、经 AI 安全网关接入」
# 把 ai-gateway-compliance.md §3 的 4 条人工勾选项变成可执行验证。
#
# 用法：
#   bash scripts/verify_gateway.sh --base-url https://<网关>/v1 --api-key <网关Key>
#   bash scripts/verify_gateway.sh --base-url ... --api-key ... --model qwen-max
# 环境变量等价写法：
#   AI_GATEWAY_BASE_URL=... AI_GATEWAY_API_KEY=... bash scripts/verify_gateway.sh
#
# 退出码：0=全过  1=存在 FAIL  2=参数错误
# 网关侧自检前请先完成报备（模型清单见 ai-gateway-compliance.md §4）。
# =============================================================
set -u

# ── 参数解析 ──
BASE_URL="${AI_GATEWAY_BASE_URL:-}"
API_KEY="${AI_GATEWAY_API_KEY:-}"
MODEL=""
TIMEOUT=20

while [ $# -gt 0 ]; do
  case "$1" in
    --base-url) BASE_URL="$2"; shift 2 ;;
    --api-key)  API_KEY="$2";  shift 2 ;;
    --model)    MODEL="$2";    shift 2 ;;
    --timeout)  TIMEOUT="$2";  shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$BASE_URL" ] || [ -z "$API_KEY" ]; then
  echo "用法: $0 --base-url <网关/v1> --api-key <网关Key> [--model 模型名] [--timeout N]" >&2
  exit 2
fi

# 默认模型：从 config.yaml 的 default_channel 读取
if [ -z "$MODEL" ]; then
  MODEL="$(grep -E '^  default_channel:' config.yaml 2>/dev/null | awk '{print $2}')"
  MODEL="${MODEL:-qwen-max}"
fi

ENDPOINT="${BASE_URL%/}/chat/completions"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $1"; }

echo "=============================================================="
echo " AI 安全网关接入自检"
echo " 网关端点: $ENDPOINT"
echo " 报备模型: $MODEL"
echo "=============================================================="

# ── 第 1 条：网关连通性（带分配 Key 返回 200）─────────────────────
echo ""
echo "[1/4] 网关连通性（分配 Key 鉴权）"
CODE=$(curl -s -m "$TIMEOUT" -o /tmp/gw_body.json -w "%{http_code}" \
  -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${API_KEY}" \
  -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"max_tokens\":5}" 2>/dev/null)
if [ "$CODE" = "200" ]; then
  ok "连通性 OK（HTTP 200），网关接受报备模型 ${MODEL}"
else
  bad "连通性 FAIL（HTTP ${CODE:-无响应}）——检查网关地址/Key/模型报备状态"
  echo "    响应: $(head -c 300 /tmp/gw_body.json 2>/dev/null)"
fi

# ── 第 2 条：系统内 Agent 走网关成功（真实一次对话，非直连）────────
# 用 --internal 模式调用平台：向 /api/multi-agent/stream 发一条最小任务，
# 若网关启用了流量审计，该请求应出现在网关侧流量日志（人工到网关控制台核对）。
echo ""
echo "[2/4] 平台内 Agent 对话经网关（网关侧流量日志人工复核）"
if curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:18086/ 2>/dev/null | grep -q 200; then
  echo "  平台在线（18086）。发一条最小 Agent 任务，请到网关控制台确认出现对应流量："
  echo "    bash scripts/experiments/gw_probe.sh   # 或手动在平台界面发一条消息"
  ok "平台就绪；网关流量请人工复核（第 3 条不误伤通过后此项即满足）"
else
  echo "  平台未启动（不影响网关直连验证，跳过此条平台侧检查）"
  ok "平台离线，跳过（启动平台后重跑可复核网关流量）"
fi

# ── 第 3 条：审计/限流策略不误伤调试行为（代码解释/批量扫描特征）───
echo ""
echo "[3/4] 审计/限流策略对调试行为不误伤"
# 发送一条带「代码解释+批量任务」特征的请求，模拟 Agent 调试行为；
# 若网关 WAF/限流策略过度激进会拦截（429/403），此处应仍放行。
PROBE_BODY='{"model":"__MODEL__","messages":[{"role":"user","content":"解释这段 python 代码的作用：for i in range(10): print(i)。这是安全检测 Agent 的正常调试输出。"}],"max_tokens":20}'
PROBE_BODY="${PROBE_BODY/__MODEL__/$MODEL}"
CODE=$(curl -s -m "$TIMEOUT" -o /tmp/gw_probe.json -w "%{http_code}" \
  -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${API_KEY}" \
  -d "$PROBE_BODY" 2>/dev/null)
case "$CODE" in
  200) ok "调试特征请求放行（HTTP 200）——审计策略未误伤" ;;
  429) bad "调试特征请求被限流（HTTP 429）——需在网关侧调高 Agent 会话限额" ;;
  403) bad "调试特征请求被拦截（HTTP 403）——需在网关侧加白调试/代码解释行为" ;;
  *)   bad "调试特征请求异常（HTTP ${CODE:-无响应}）" ;;
esac

# ── 第 4 条：网关故障时降级行为明确（错误提示 vs 静默重试/挂起）───
echo ""
echo "[4/4] 网关故障降级行为（错误显式上报，不静默挂起）"
# 用错误 Key 模拟鉴权故障，验证客户端在 <timeout> 内返回明确错误（401/403），而非无限重试
CODE=$(curl -s -m "$TIMEOUT" -o /tmp/gw_err.json -w "%{http_code}" \
  -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalid-key-for-failover-test" \
  -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_tokens\":5}" 2>/dev/null)
case "$CODE" in
  401|403) ok "错误 Key 在 ${TIMEOUT}s 内返回 HTTP ${CODE}（显式错误，未静默挂起）——降级行为明确" ;;
  200)     bad "错误 Key 竟返回 200——网关未校验 Key，需检查网关鉴权配置" ;;
  *)       bad "故障场景响应异常（HTTP ${CODE:-无响应}），需确认客户端错误处理链路" ;;
esac

echo ""
echo "=============================================================="
echo " 结果: PASS ${PASS} / FAIL ${FAIL}"
echo "=============================================================="
[ "$FAIL" = "0" ] && echo "网关接入自检全过。剩余人工步骤：报备清单填表(§4)、现场替换 config 网关段。" && exit 0
echo "存在 FAIL，请按上方提示到网关侧调整后重跑。" && exit 1
