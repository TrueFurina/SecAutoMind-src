#!/usr/bin/env bash
# =============================================================
# gw_probe.sh — 平台内 Agent 最小对话探针（薄壳）
# verify_gateway.sh [2/4] 依赖：向平台下发一条最小任务，
# 证明「平台内 Agent 对话」链路可用；网关启用后本条流量应
# 出现在网关侧流量日志（人工复核点，见 ai-gateway-compliance.md §3 第 2 条）。
#
# 用法：
#   bash scripts/experiments/gw_probe.sh
#   bash scripts/experiments/gw_probe.sh --message "自定义任务"
# =============================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"

# 优先用环境变量指定的解释器，否则用仓库实验统一解释器，最后退回 PATH
if [ -n "${SAM_PYTHON:-}" ]; then
  PY="$SAM_PYTHON"
elif [ -x "C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe" ]; then
  PY="C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
else
  PY="python"
fi

exec "$PY" "$HERE/gw_probe.py" "$@"
