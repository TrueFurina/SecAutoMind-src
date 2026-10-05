#!/usr/bin/env bash
# 决赛开赛「一键上膛」：把 runbook §1 的 8 行 export 收成一条命令，消灭"漏设一个开关就废一类能力"的手抖风险。
#
# 用法（三选一）：
#   source scripts/finals_arm.sh     # 在当前 shell 里设好全部开关 + 跑校验（推荐）
#   bash   scripts/finals_arm.sh      # 独立运行：只做校验与打印，不改父 shell 环境
#   bash   scripts/finals_arm.sh --print   # 只打印可粘贴的 export 清单（不跑校验）
#
# 纪律（AGENTS.md 第六条 / 记忆铁律）：
#   平台地址与 Token **只从环境变量读**，本脚本不写入任何文件、不 echo 明文，
#   只报告"已设置 / 未设置"。凭证一行都不进版本库。
#
# 为什么值得存在：CTF_POLL_ENABLED / CTF_AUTOSOLVE_SUBMIT / CTF_AUTO_BUILD_ENV 三个开关
# 默认关闭（安全默认），漏设 = 轮询器不启动 / 要人工抄 flag / 靶机题全 MISS。
# 这三个都是"不设就静默失能"，现场没有任何报错提示——正是最贵的失败方式。

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"

# ── 判定是被 source 还是被直接执行（source 时设置才作用于当前 shell）──────────
SOURCED=0
if [ -n "${BASH_SOURCE[0]:-}" ] && [ "${BASH_SOURCE[0]}" != "${0}" ]; then
  SOURCED=1
fi

# ── 平台凭证：只查在不在，绝不显示值 ───────────────────────────────────────────
BASE_URL="${DASCTF_BASE_URL:-}"
TOKEN="${CTF_AGENT_PLATFORM_TOKEN:-${DASCTF_TOKEN:-}}"

# host 可以显示（不是秘密），路径与查询串不显示。
# 必须真剥掉 scheme：sed 的捕获组是含 `https://` 的整段，直接用会把带 scheme 的地址
# 全部错判成"非官方域名"（第二次反向验证抓出）。故分两步：去 scheme → 去路径。
BASE_URL_HOST="$(printf '%s' "$BASE_URL" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##')"
# 地址健康判定：本地/回环地址是演练环境，拿它开赛 = 拉题全失败且极难当场定位
# 判定基于 host（已剥掉 scheme 与路径），不基于整串 —— 早期版本用 `*://*` 匹配"无 scheme"，
# 结果把所有合法 https 地址都判成演练地址（反向验证抓出），故改为按 host 分支。
ADDR_STATE="⚠ 未设置 —— 拉题会失败"
case "$BASE_URL_HOST" in
  127.0.0.1*|localhost*|0.0.0.0*)
    ADDR_STATE="❌ 本地/演练地址，开赛前必须换成官方地址" ;;
  pro.dasctf.com*)
    ADDR_STATE="✅ 官方地址" ;;
  "")
    ADDR_STATE="⚠ 未设置 —— 拉题会失败" ;;
  *)
    ADDR_STATE="⚠ 非官方域名，请与赛事通知核对" ;;
esac



# ── 开关：已存在的值不覆盖（允许现场调过间隔后重新上膛）──────────────────────
export CTF_POLL_ENABLED="${CTF_POLL_ENABLED:-true}"
export CTF_AUTOSOLVE_SUBMIT="${CTF_AUTOSOLVE_SUBMIT:-true}"
export CTF_AUTO_BUILD_ENV="${CTF_AUTO_BUILD_ENV:-true}"
export CTF_AUTO_FETCH_DETAIL="${CTF_AUTO_FETCH_DETAIL:-true}"
export CTF_AUTO_FETCH_ATTACHMENT="${CTF_AUTO_FETCH_ATTACHMENT:-true}"
export CTF_AUTO_RELEASE_ENV="${CTF_AUTO_RELEASE_ENV:-true}"
export CTF_POLL_INTERVAL="${CTF_POLL_INTERVAL:-20}"

print_list() {
  echo "# —— 平台凭证（脚本不会替你填，也绝不落盘）——"
  echo 'export DASCTF_BASE_URL="<官方平台地址>"'
  echo 'export CTF_AGENT_PLATFORM_TOKEN="<官方 Token>"   # 或 DASCTF_TOKEN'
  echo
  echo "# —— 自动化开关 ——"
  echo "export CTF_POLL_ENABLED=${CTF_POLL_ENABLED}"
  echo "export CTF_AUTOSOLVE_SUBMIT=${CTF_AUTOSOLVE_SUBMIT}"
  echo "export CTF_AUTO_BUILD_ENV=${CTF_AUTO_BUILD_ENV}"
  echo "export CTF_POLL_INTERVAL=${CTF_POLL_INTERVAL}"
  echo "export CTF_AUTO_FETCH_ATTACHMENT=${CTF_AUTO_FETCH_ATTACHMENT}"
  echo "export CTF_AUTO_FETCH_DETAIL=${CTF_AUTO_FETCH_DETAIL}"
  echo "export CTF_AUTO_RELEASE_ENV=${CTF_AUTO_RELEASE_ENV}"
}

if [ "${1:-}" = "--print" ]; then
  print_list
  exit 0
fi

echo "=========================================================================="
echo "决赛开赛上膛 · 确认表"
echo "=========================================================================="
printf "  %-28s %s\n" "DASCTF_BASE_URL" "${BASE_URL_HOST:-—}  ${ADDR_STATE}"
printf "  %-28s %s\n" "CTF_AGENT_PLATFORM_TOKEN" "$([ -n "$TOKEN" ] && echo '已设置（不显示）' || echo '⚠ 未设置 —— 提交会失败')"
for v in CTF_POLL_ENABLED CTF_AUTOSOLVE_SUBMIT CTF_AUTO_BUILD_ENV \
         CTF_AUTO_FETCH_DETAIL CTF_AUTO_FETCH_ATTACHMENT CTF_AUTO_RELEASE_ENV; do
  printf "  %-28s %s\n" "$v" "${!v}"
done
printf "  %-28s %s\n" "CTF_POLL_INTERVAL" "${CTF_POLL_INTERVAL}"

if [ "$SOURCED" -eq 0 ]; then
  echo
  echo "  ! 本次是独立运行（bash 直接调用），开关只在本进程内生效。"
  echo "    要让开关进入当前 shell，请改用：source scripts/finals_arm.sh"
fi

# ── 门禁校验（NO-GO 是正常结论，要如实显示而不是让脚本崩掉）──────────────────
PY=""
for cand in "python3" "python"; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  echo
  echo "  ! 未找到 python，跳过 finals_preflight 校验（开关已设置，请自行核对）"
  exit 0
fi

echo
echo "—— finals_preflight 校验 ——"
"$PY" "$ROOT/scripts/finals_preflight.py"
rc=$?
echo
if [ "$rc" -eq 0 ]; then
  echo "✅ GO：可上场"
else
  echo "❌ NO-GO：见上方阻塞项，**不要开赛**（处置见 runbook §4 降级清单）"
fi
exit $rc
