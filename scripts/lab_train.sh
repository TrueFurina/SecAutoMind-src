#!/usr/bin/env bash
# lab_train.sh — 真实靶场训练回路：拉起靶机 → 跑旁路证据探测 → 记录本轮结果
#
# 用法：
#   bash scripts/lab_train.sh              # 跑一轮
#   bash scripts/lab_train.sh -n 5         # 连跑 5 轮（每轮间隔 5s，用于观察稳定性）
#   bash scripts/lab_train.sh --no-start   # 不自动拉起靶机，直接跑
#
# 退出码：0 = 至少检出 1 条证据；1 = 0 条（探测链没打通）；2 = 环境未就绪
#
# 结果同时追加到 .workbuddy/lab/train_log.md（该目录被 .gitignore 忽略，不污染仓库）
set -u

ROUNDS=1
AUTO_START=1
while [ $# -gt 0 ]; do
  case "$1" in
    -n) ROUNDS="${2:-1}"; shift 2 ;;
    --no-start) AUTO_START=0; shift ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$REPO/.workbuddy/lab"
LOG="$LOG_DIR/train_log.md"
mkdir -p "$LOG_DIR"
BASE="${CTF4_LAB_URL:-http://127.0.0.1:8080/}"

export APPDATA="${APPDATA:-$USERPROFILE/AppData/Roaming}"
case ":$PATH:" in *"/d/DevCache/go/bin:"*) ;; *) export PATH="/d/miniconda3_new:/d/DevCache/go/bin:$PATH" ;; esac
export TMP="${TMP:-D:/tmp_gotest}"; export TEMP="${TEMP:-D:/tmp_gotest}"; export TMPDIR="${TMPDIR:-D:/tmp_gotest}"
mkdir -p "$TMP"
export CTF4_LAB_URL="$BASE"

# ---------- 1. 环境就绪 ----------
if [ "$AUTO_START" = "1" ]; then
  bash "$REPO/scripts/ctf4_lab.sh" start >/dev/null 2>&1 || true
fi

ready=0
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$BASE" 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then ready=1; break; fi
  sleep 3
done
if [ "$ready" != "1" ]; then
  echo "[FAIL] 靶机未就绪（$BASE 无 200）。先跑 bash scripts/ctf4_lab.sh start" >&2
  exit 2
fi
echo "[env] 靶机就绪: $BASE"

# ---------- 2. 逐轮训练 ----------
[ -f "$LOG" ] || printf '# 真实靶场训练日志\n\n| 时间 | 轮次 | 证据数 | 命中信号 | 载荷 | 结果 |\n|---|---|---|---|---|---|\n' > "$LOG"

overall=0
for r in $(seq 1 "$ROUNDS"); do
  OUT="$TMP/lab_train_round${r}.out"
  go test -p 1 -count=1 -timeout 300s -run TestLiveSensitiveFileRead -v \
      ./internal/ctfplatform/ > "$OUT" 2>&1
  rc=$?
  ev=$(grep -c 'kind=lfi_sensitive_file' "$OUT" 2>/dev/null || echo 0)
  sigs=$(grep -oE 'signal=[a-z_]+' "$OUT" 2>/dev/null | sed 's/signal=//' | sort -u | paste -sd, -)
  [ -z "$sigs" ] && sigs="-"
  elapsed=$(grep -oE 'elapsed=[0-9.]+[a-zµ]+' "$OUT" 2>/dev/null | head -1 | sed 's/elapsed=//')
  [ -z "$elapsed" ] && elapsed="-"
  if [ "$rc" = "0" ]; then res="PASS"; else res="FAIL(rc=$rc)"; overall=1; fi

  echo "[round $r] $res  证据=$ev  信号=$sigs  耗时=$elapsed"
  grep -E '  #[0-9]+ kind=' "$OUT" 2>/dev/null | sed 's/^ *//' | head -6

  printf '| %s | %s | %s | %s | %s | %s |\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$r" "$ev" "${sigs:--}" "${elapsed:--}" "$res" >> "$LOG"

  if [ "$r" -lt "$ROUNDS" ]; then sleep 5; fi
done

echo ""
echo "[log] 已追加到 $LOG"
exit "$overall"
