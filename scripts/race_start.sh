#!/usr/bin/env bash
# race_start.sh —— SecAutoMind Runner 一键启动（Linux/服务器）
#
# 做的事：
#   1. 设参赛推荐 env var（CTF² 平台 + 自动提交 + 起靶机）
#   2. 自动探测 runner 二进制（先找 ./runner_ctf，再找 go run ./cmd/runner）
#   3. 日志落盘到 ./logs/runner_YYYYMMDD_HHMMSS.log
#   4. 后台启动 + tail -f 实时看；Ctrl+C 优雅 kill
#
# 用法：
#   CTF2_AGENT_TOKEN=xxx bash scripts/race_start.sh             # 自动找二进制
#   CTF2_AGENT_TOKEN=xxx RUNNER_BIN=./runner_ctf bash scripts/race_start.sh
#   CTF2_AGENT_TOKEN=xxx bash scripts/race_start.sh --dry-run  # 不提交 flag
#   bash scripts/race_start.sh --check                         # 只做 preflight，不启动
#
# 依赖：bash ≥ 4 + Go ≥ 1.24 + angr/pwntools（runner Layer 2）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── 参数解析 ────────────────────────────────────────────────
DRY_RUN=false
CHECK_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --check)   CHECK_ONLY=true ;;
    -h|--help)
      sed -n '3,25p' "$0"; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

# ── env 自动设（只在未设时覆盖）───────────────────────────────
: "${CTF_POLL_INTERVAL:=30}"
: "${CTF_SOLVE_TIMEOUT:=180}"
: "${CTF_MAX_CONCURRENCY:=4}"
: "${CTF_MAX_RETRY_SUBMIT:=2}"
: "${CTF_AUTO_BUILD_ENV:=true}"
: "${CTF_AUTO_FETCH_DETAIL:=true}"
: "${CTF_AUTO_FETCH_ATTACHMENT:=true}"
: "${CTF_AUTO_RELEASE_ENV:=true}"
: "${CTF_AUTOSOLVE_SUBMIT:=true}"
: "${CTF_FIRST_BLOOD_WINDOW:=900}"
: "${CTF_FIRST_BLOOD_INTERVAL:=10}"
export CTF_POLL_INTERVAL CTF_SOLVE_TIMEOUT CTF_MAX_CONCURRENCY \
       CTF_MAX_RETRY_SUBMIT CTF_AUTO_BUILD_ENV CTF_AUTO_FETCH_DETAIL \
       CTF_AUTO_FETCH_ATTACHMENT CTF_AUTO_RELEASE_ENV CTF_AUTOSOLVE_SUBMIT \
       CTF_FIRST_BLOOD_WINDOW CTF_FIRST_BLOOD_INTERVAL

if $DRY_RUN; then
  CTF_AUTOSOLVE_SUBMIT=false
  export CTF_AUTOSOLVE_SUBMIT
fi

# LLM fallback 默认不启用（token 成本考量）；要开显式设 RUNNER_LLM_FALLBACK=true
export RUNNER_LLM_FALLBACK="${RUNNER_LLM_FALLBACK:-false}"

# ── runner 二进制探测 ────────────────────────────────────────
RUNNER_BIN="${RUNNER_BIN:-}"
if [ -z "$RUNNER_BIN" ]; then
  for cand in \
    "$REPO_ROOT/runner_ctf" \
    "$HOME/ctf_run/runner_v2" \
    "$HOME/ctf_run/runner" \
    "$REPO_ROOT/cmd/runner/runner_ctf"; do
    if [ -x "$cand" ]; then
      RUNNER_BIN="$cand"; break
    fi
  done
fi

if [ -z "$RUNNER_BIN" ] && command -v go &>/dev/null; then
  RUNNER_BIN="go run $REPO_ROOT/cmd/runner"
fi

if [ -z "$RUNNER_BIN" ]; then
  echo "❌ 找不到 runner 二进制，也没有 go 命令" >&2; exit 1
fi

# ── preflight（只做不启动）───────────────────────────────────
if $CHECK_ONLY; then
  echo "=== Preflight ==="
  echo "RUNNER_BIN     : $RUNNER_BIN"
  echo "CTF2_AGENT_TOKEN: ${CTF2_AGENT_TOKEN:+已设}"
  echo "skills_dir     : ${CTF_SKILLS_DIR:-未设（runner 自动探测）}"
  python3 -c "import angr, pwnlib" 2>/dev/null && echo "angr/pwnlib     : ✅" || echo "angr/pwnlib     : ⚠️ 未装（Layer 2 会跳过）"
  [ -n "$CTF2_AGENT_TOKEN" ] && echo "Token          : ✅" || echo "Token          : ❌ CTF2_AGENT_TOKEN 未设"
  exit 0
fi

# ── 必须项检查 ───────────────────────────────────────────────
if [ -z "${CTF2_AGENT_TOKEN:-}" ]; then
  echo "❌ CTF2_AGENT_TOKEN 未设 —— runner 无法拉题" >&2
  echo "   用法: CTF2_AGENT_TOKEN=xxx bash scripts/race_start.sh" >&2
  exit 1
fi

# ── 日志目录 ────────────────────────────────────────────────
LOG_DIR="${LOG_DIR:-$REPO_ROOT/logs}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/runner_$(date +%Y%m%d_%H%M%S).log"

echo "=============================================="
echo "SecAutoMind Runner 启动"
echo "=============================================="
echo "二进制    : $RUNNER_BIN"
echo "Dry-run   : $DRY_RUN"
echo "Max Conc  : $CTF_MAX_CONCURRENCY"
echo "Auto Subm : $CTF_AUTOSOLVE_SUBMIT"
echo "LLM Layer : $RUNNER_LLM_FALLBACK"
echo "日志      : $LOG_FILE"
echo "=============================================="

# ── 启动 + 信号处理 ─────────────────────────────────────────
cleanup() {
  echo ""
  echo "收到 Ctrl+C，正在停止 runner..."
  kill -TERM "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  echo "已停止"
  exit 0
}
trap cleanup SIGINT SIGTERM

cd "$REPO_ROOT"
if [[ "$RUNNER_BIN" == go\ run* ]]; then
  $RUNNER_BIN *>> "$LOG_FILE" &
else
  "$RUNNER_BIN" *>> "$LOG_FILE" &
fi
PID=$!

echo "✅ Runner 已启动，PID=$PID"
echo "tail -f $LOG_FILE 实时看日志；Ctrl+C 停止"

# 前台 tail + Ctrl+C 时 kill runner
tail -f "$LOG_FILE" &
TAIL_PID=$!
trap "kill $TAIL_PID 2>/dev/null; cleanup" EXIT INT TERM
wait "$TAIL_PID"
