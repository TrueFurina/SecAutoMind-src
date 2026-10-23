#!/usr/bin/env bash
# lab_killchain.sh — 一键跑完整杀伤链（URL → root），逐步打印结果
#
# 用法：
#   bash scripts/lab_killchain.sh                       # 用内置/字典破解
#   bash scripts/lab_killchain.sh --user U --pass P     # 用已知凭据跳过破解（快）
#   CTF4_WORDLIST=D:/tmp_gotest/words.txt bash scripts/lab_killchain.sh
#
# 环境变量：
#   CTF4_LAB_URL   默认 http://127.0.0.1:8080/
#   CTF4_SSH_ADDR  默认 127.0.0.1:2222
#   CTF4_WORDLIST  可选，字典文件（不给则只用内置小字典，命中率低）
#
# 退出码：0 = 到达 root；1 = 未到 root；2 = 环境未就绪
set -u

USER_OPT=""; PASS_OPT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_OPT="${2:-}"; shift 2 ;;
    --pass) PASS_OPT="${2:-}"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${CTF4_LAB_URL:-http://127.0.0.1:8080/}"
SSH_ADDR="${CTF4_SSH_ADDR:-127.0.0.1:2222}"

export APPDATA="${APPDATA:-$USERPROFILE/AppData/Roaming}"
case ":$PATH:" in *"/d/DevCache/go/bin:"*) ;; *) export PATH="/d/miniconda3_new:/d/DevCache/go/bin:$PATH" ;; esac
export TMP="${TMP:-D:/tmp_gotest}"; export TEMP="${TEMP:-D:/tmp_gotest}"; export TMPDIR="${TMPDIR:-D:/tmp_gotest}"
mkdir -p "$TMP"

# 靶机就绪检查
code=$(curl -s -o /dev/null -m 6 -w '%{http_code}' "$BASE" 2>/dev/null || echo 000)
if [ "$code" != "200" ]; then
  echo "[FAIL] 靶机未就绪（$BASE -> $code）。先跑 bash scripts/ctf4_lab.sh start" >&2
  exit 2
fi
echo "[env] 靶机 $BASE / SSH $SSH_ADDR"

export CTF4_LAB_URL="$BASE"
export CTF4_SSH_ADDR="$SSH_ADDR"
[ -n "$USER_OPT" ] && export CTF4_SSH_USER="$USER_OPT"
[ -n "$PASS_OPT" ] && export CTF4_SSH_PASS="$PASS_OPT"

OUT="$TMP/lab_killchain.out"
cd "$REPO" || exit 2
go test -p 1 -count=1 -timeout 1800s -run TestLiveKillChain -v \
    ./internal/ctfplatform/ > "$OUT" 2>&1
rc=$?

echo ""
sed -n 's/.*killchain_test.go:[0-9]*: //p' "$OUT" | sed 's/^/  /'
echo ""

if [ "$rc" = "0" ]; then
  echo "[PASS] 已到达 root（日志：$OUT）"
else
  echo "[FAIL] 未到达 root（rc=$rc，日志：$OUT）"
  grep -E "FAIL|panic|错误" "$OUT" | head -5 | sed 's/^/  /'
fi
exit "$rc"
