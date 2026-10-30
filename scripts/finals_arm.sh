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

# ── 平台派发（2026-10-24 补）：与 scripts/finals_preflight.py 的 pick_platform() 同口径 ──
# 本脚本原先**只认 DASCTF_***，而 10-24 19:00 的正式赛跑在 CTF²（CTF2_*）。
# 后果是**假绿**：DASCTF 作为备用地址一直设着，脚本会报「✅ 官方地址 / 已设置」，
# 而真正要用的 CTF² 凭证一个都没校验 —— 正是"确认表打了绿、门禁却没覆盖"那类失败。
# 规则与 preflight 保持一致：CTF² 地址+令牌都在 → ctf2；否则回退 dasctf。
# 显式覆盖优先：`CTF_PLATFORM=dasctf|ctf2`。
# 为什么需要（2026-10-24 羊城杯初赛现场）：自动派发是"CTF² 凭据齐就走 CTF²"，
# 而当天 CTF² 的令牌是好的、羊城杯才是正在打的比赛 → 想打羊城杯反而被派去 CTF²。
# 有覆盖开关后，打羊城杯只需 CTF_PLATFORM=dasctf，不必去 unset 一堆 CTF2_* 变量。
case "${CTF_PLATFORM:-auto}" in
  dasctf|DASCTF) WANT="dasctf" ;;
  ctf2|CTF2|ctf²) WANT="ctf2" ;;
  *) WANT="auto" ;;
esac

if [ "$WANT" = "auto" ] && [ -n "${CTF2_BASE_URL:-}" ] && [ -n "${CTF2_AGENT_TOKEN:-}" ]; then
  WANT="ctf2"
elif [ "$WANT" = "auto" ]; then
  WANT="dasctf"
fi

if [ "$WANT" = "ctf2" ]; then
  PLATFORM="ctf2"
  PLATFORM_LABEL="CTF² 竞技场"
  BASE_URL="${CTF2_BASE_URL}"
  TOKEN="${CTF2_AGENT_TOKEN}"
  BASE_VAR="CTF2_BASE_URL"
  TOKEN_VAR="CTF2_AGENT_TOKEN"
  TOKEN_PREFIX="ctf2_"
  TOKEN_HINT="ctf2_ + 约 64 位"
else
  PLATFORM="dasctf"
  PLATFORM_LABEL="DASCTF"
  BASE_URL="${DASCTF_BASE_URL:-}"
  TOKEN="${CTF_AGENT_PLATFORM_TOKEN:-${DASCTF_TOKEN:-}}"
  BASE_VAR="DASCTF_BASE_URL"
  TOKEN_VAR="CTF_AGENT_PLATFORM_TOKEN"
  TOKEN_PREFIX="ak_"
  TOKEN_HINT="ak_ + 约 40 位"
fi

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
  # 顺序要紧：pro 的具体分支必须在 *.dasctf.com 通配之前，否则永远匹配不到。
  pro.dasctf.com)
    # 记忆 2026-10-24 的坑：DASCTF_BASE_URL 默认就是 pro，而**羊城杯入口是 ycb-bk**。
    # 光看"✅ 官方地址"会以为在打羊城杯，实际打错平台。
    ADDR_STATE="✅ 官方地址（注意：羊城杯入口是 ycb-bk.dasctf.com，pro 是另一套）" ;;
  *.dasctf.com|dasctf.com)
    ADDR_STATE="✅ 官方地址" ;;
  "")
    ADDR_STATE="⚠ 未设置 —— 拉题会失败" ;;
  *)
    ADDR_STATE="⚠ 非官方域名，请与赛事通知核对" ;;
esac



# ── 结束方式（2026-10-24 实测事故修复）────────────────────────────────────────
# 本文档推荐的用法是 `source scripts/finals_arm.sh`。被 source 时脚本里的 `exit` 会
# **直接终止操作者的 shell**：交互终端窗口一关，先前 export 的开关随进程一起消失，
# 重开新终端又是全 OFF —— 「一键上膛」反而制造了它本该消灭的静默失能（poller 不启动、
# 不自动提交、靶机题全 MISS，且现场没有任何报错）。
# 故：被 source 时一律用 `return`（只退出脚本，保留当前 shell 的开关），
#     直接执行时才 `exit`。注意必须写在**脚本顶层**——包进函数里的 return 只退出函数。

# ── 开关：已存在的值不覆盖（允许现场调过间隔后重新上膛）──────────────────────
export CTF_POLL_ENABLED="${CTF_POLL_ENABLED:-true}"
export CTF_AUTOSOLVE_SUBMIT="${CTF_AUTOSOLVE_SUBMIT:-true}"
export CTF_AUTO_BUILD_ENV="${CTF_AUTO_BUILD_ENV:-true}"
export CTF_AUTO_FETCH_DETAIL="${CTF_AUTO_FETCH_DETAIL:-true}"
export CTF_AUTO_FETCH_ATTACHMENT="${CTF_AUTO_FETCH_ATTACHMENT:-true}"
export CTF_AUTO_RELEASE_ENV="${CTF_AUTO_RELEASE_ENV:-true}"
export CTF_ROBOT_AUTO_PREPARE="${CTF_ROBOT_AUTO_PREPARE:-true}"
export CTF_POLL_INTERVAL="${CTF_POLL_INTERVAL:-20}"

# 🔴 排行榜心跳（2026-10-31 补，源于 10-24 羊城杯 0 分复盘）
# 那场整场比赛我们**看不到自己在不在得分**：`ScoreboardSnapshot` 到 10-28 才接、
# 且按"新接线默认关"纪律默认 false → 赛中没有任何分数信号，只能靠人肉感觉。
# 上膛时显式打开：停轮打终报 + 每 5 分钟打一次周期快照（300s ≥ PollInterval 20s，合法）。
# 不改代码默认值（第八条纪律：新接线默认关），只在**赛时上膛**这一层打开。
export CTF_SCOREBOARD_SNAPSHOT="${CTF_SCOREBOARD_SNAPSHOT:-true}"
export CTF_SCOREBOARD_INTERVAL="${CTF_SCOREBOARD_INTERVAL:-300}"

print_list() {
  echo "# —— 平台凭证（脚本不会替你填，也绝不落盘）——"
  echo "# 当前平台：${PLATFORM_LABEL}"
  echo "export ${BASE_VAR}=\"<官方平台地址>\""
  echo "export ${TOKEN_VAR}=\"<官方 Token>\"   # 形态：${TOKEN_HINT}"
  echo
  echo "# —— 自动化开关 ——"
  echo "export CTF_POLL_ENABLED=${CTF_POLL_ENABLED}"
  echo "export CTF_AUTOSOLVE_SUBMIT=${CTF_AUTOSOLVE_SUBMIT}"
  echo "export CTF_AUTO_BUILD_ENV=${CTF_AUTO_BUILD_ENV}"
  echo "export CTF_POLL_INTERVAL=${CTF_POLL_INTERVAL}"
  echo "export CTF_AUTO_FETCH_ATTACHMENT=${CTF_AUTO_FETCH_ATTACHMENT}"
  echo "export CTF_AUTO_FETCH_DETAIL=${CTF_AUTO_FETCH_DETAIL}"
  echo "export CTF_AUTO_RELEASE_ENV=${CTF_AUTO_RELEASE_ENV}"
  echo "export CTF_ROBOT_AUTO_PREPARE=${CTF_ROBOT_AUTO_PREPARE}"
  echo "export CTF_SCOREBOARD_SNAPSHOT=${CTF_SCOREBOARD_SNAPSHOT}"
  echo "export CTF_SCOREBOARD_INTERVAL=${CTF_SCOREBOARD_INTERVAL}"
}

if [ "${1:-}" = "--print" ]; then
  print_list
  if [ "$SOURCED" -eq 1 ]; then return 0; else exit 0; fi
fi

echo "=========================================================================="
echo "决赛开赛上膛 · 确认表"
echo "=========================================================================="
printf "  %-28s %s\n" "目标平台" "${PLATFORM_LABEL}（${CTF_PLATFORM:-auto}）"
printf "  %-28s %s\n" "${BASE_VAR}" "${BASE_URL_HOST:-—}  ${ADDR_STATE}"
# 令牌形态：只判前缀，绝不回显值。前缀不对 = 多半填了别的令牌/门户口令。
if [ -z "$TOKEN" ]; then
  TOKEN_STATE="⚠ 未设置 —— 提交会失败"
elif [ "${TOKEN#"$TOKEN_PREFIX"}" = "$TOKEN" ]; then
  TOKEN_STATE="⚠ 已设置但不以 ${TOKEN_PREFIX} 开头（应形如 ${TOKEN_HINT}）—— 确认不是别的令牌"
else
  TOKEN_STATE="已设置（不显示，前缀 ${TOKEN_PREFIX} ✓）"
fi
printf "  %-28s %s\n" "${TOKEN_VAR}" "${TOKEN_STATE}"
for v in CTF_POLL_ENABLED CTF_AUTOSOLVE_SUBMIT CTF_AUTO_BUILD_ENV \
         CTF_AUTO_FETCH_DETAIL CTF_AUTO_FETCH_ATTACHMENT CTF_AUTO_RELEASE_ENV \
         CTF_ROBOT_AUTO_PREPARE; do
  printf "  %-28s %s\n" "$v" "${!v}"
done
printf "  %-28s %s\n" "CTF_POLL_INTERVAL" "${CTF_POLL_INTERVAL}"
printf "  %-28s %s\n" "CTF_SCOREBOARD_SNAPSHOT" "${CTF_SCOREBOARD_SNAPSHOT}"
printf "  %-28s %s\n" "CTF_SCOREBOARD_INTERVAL" "${CTF_SCOREBOARD_INTERVAL}"

if [ "$SOURCED" -eq 0 ]; then
  echo
  echo "  ! 本次是独立运行（bash 直接调用），开关只在本进程内生效。"
  echo "    要让开关进入当前 shell，请改用：source scripts/finals_arm.sh"
fi

# ── --table：只打确认表就返回，跳过门禁校验（快路径，供回归测试与赛前快速自检）──
# 为什么需要：完整上膛要跑 5 道门禁，单次 ~38s；回归测试要连跑多次确认表断言，
# 全套会到 260s+（CI 里就是 4 分钟）。--table 只做「打印 + 返回」，同一批断言 1s 内跑完。
if [ "${1:-}" = "--table" ]; then
  if [ "$SOURCED" -eq 1 ]; then return 0; else exit 0; fi
fi

# ── 门禁校验（NO-GO 是正常结论，要如实显示而不是让脚本崩掉）──────────────────
PY=""
for cand in "python3" "python"; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  echo
  echo "  ! 未找到 python，跳过 finals_preflight 校验（开关已设置，请自行核对）"
  if [ "$SOURCED" -eq 1 ]; then return 0; else exit 0; fi
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
if [ "$SOURCED" -eq 1 ]; then return "$rc"; else exit "$rc"; fi
