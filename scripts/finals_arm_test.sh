#!/usr/bin/env bash
# finals_arm_test.sh — finals_arm.sh 的语义回归（`bash -n` 抓不到的那类问题）
#
# 为什么要有这个文件（2026-10-24 实测事故）：
#   finals_arm.sh 的推荐用法是 `source scripts/finals_arm.sh`，但它末尾写的是 `exit $rc`。
#   被 source 时 `exit` 会**直接终止操作者的 shell**：交互终端窗口一关，先前 export 的
#   开关随进程消失；重开新终端又是全 OFF —— poller 不启动 / 不自动提交 / 靶机题全 MISS，
#   而且现场没有任何报错。**语法完全合法**，所以 CI 里原有的 `bash -n` 永远抓不到。
#
# 判据（每条都必须能独立失败）：
#   T1 source 之后父 shell 必须存活，且 7 个开关全部为 true
#   T2 source --print 分支也必须存活并返回 0（早期实现这里也有 exit 0）
#   T3 直接执行（bash scripts/finals_arm.sh）仍以 exit 结束，退出码可由调用方取到
#   T4 **因果自变异**：把一份「末尾 exit」的副本拿去 source，T1 的断言必须失败
#      —— 证明 T1 抓的是这个 bug，而不是恰好通过
#
# 用法：bash scripts/finals_arm_test.sh          # 0=全过，1=有失败

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
ARM="$ROOT/scripts/finals_arm.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok()   { pass=$((pass + 1)); printf '  [PASS] %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  [FAIL] %s\n' "$1"; }

echo "======================================================================"
echo "finals_arm.sh 语义回归（source 不得杀 shell）"
echo "----------------------------------------------------------------------"

if [ ! -f "$ARM" ]; then
  echo "  [FATAL] 找不到 $ARM" >&2
  exit 2
fi

# ── T1：source 后父 shell 存活 + 开关生效 ─────────────────────────────────────
# 注意：这里必须让 source 的**输出重定向**，不能接管道 —— `source x | tail` 会把 x 放进
# 子 shell，导出丢失，测出来的是假象（本次排查时先踩过这个坑）。
out="$(bash -c 'source "$1" >/dev/null 2>&1; echo "ALIVE"; echo "POLL=${CTF_POLL_ENABLED:-<unset>}"; echo "ROBOT=${CTF_ROBOT_AUTO_PREPARE:-<unset>}"' _ "$ARM" 2>&1)"
if printf '%s' "$out" | grep -q '^ALIVE$'; then
  ok "T1a source 之后父 shell 仍存活（末行 exit 未杀 shell）"
else
  bad "T1a source 之后 shell 已被终止（脚本末尾仍在 exit）—— 现场的开关会随窗口一起消失"
fi
if printf '%s' "$out" | grep -q '^POLL=true$' && printf '%s' "$out" | grep -q '^ROBOT=true$'; then
  ok "T1b source 之后开关进入当前 shell（CTF_POLL_ENABLED / CTF_ROBOT_AUTO_PREPARE = true）"
else
  bad "T1b 开关未进入当前 shell：$(printf '%s' "$out" | tr '\n' ' ')"
fi

# ── T2：--print 分支 ─────────────────────────────────────────────────────────
out2="$(bash -c 'source "$1" --print >/dev/null 2>&1; echo "ALIVE rc=$?"' _ "$ARM" 2>&1)"
if printf '%s' "$out2" | grep -q '^ALIVE rc=0$'; then
  ok "T2 source --print 正常返回 0 且 shell 存活"
else
  bad "T2 source --print 异常：$(printf '%s' "$out2" | tr '\n' ' ')"
fi

# ── T3：直接执行仍走 exit（退出码可被调用方取到）──────────────────────────────
bash "$ARM" >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; then
  ok "T3 直接执行退出码语义保留（rc=$rc；0=GO / 1=NO-GO）"
else
  bad "T3 直接执行退出码异常：rc=$rc（期望 0 或 1）"
fi

# ── T4：因果自变异 —— 把末尾守卫换回裸 exit，T1 的断言必须失败 ────────────────
# 变异必须**替换**末尾守卫、而不是追加一行：追加在 return 之后永远走不到，
# 那样 T4 会假过（本次实测先踩过：追加 exit 0 的副本照样让 shell 存活）。
sed 's|if \[ "\$SOURCED" -eq 1 \]; then return "\$rc"; else exit "\$rc"; fi|exit "$rc"|' \
  "$ARM" > "$TMP/arm_mut.sh"
if grep -qx 'exit "$rc"' "$TMP/arm_mut.sh"; then
  mut="$(bash -c 'source "$1" >/dev/null 2>&1; echo "ALIVE"' _ "$TMP/arm_mut.sh" 2>&1)"
  if printf '%s' "$mut" | grep -q '^ALIVE$'; then
    bad "T4 变异体（裸 exit）竟然没杀掉 shell —— T1 的断言是恒绿的，抓不到本 bug"
  else
    ok "T4 变异体（裸 exit）被抓住：shell 被终止，T1 断言非恒绿"
  fi
else
  bad "T4 变异未生效（末尾守卫的写法变了？请同步本测试的 sed 模式，否则 T4 是假绿）"
fi

# ── T5：平台派发 —— 有 CTF² 凭据时必须以 CTF² 为主平台 ─────────────────────────
# 2026-10-24 事故：本脚本原先只认 DASCTF_*，而当晚正式赛跑在 CTF²（CTF2_*）。
# DASCTF 作为备用地址一直设着 → 脚本报「✅ 官方地址 / 已设置」的**假绿**，
# 真正要用的 CTF² 凭证一个都没校验。
out5="$(CTF2_BASE_URL="https://ctf2.dasctf.com" CTF2_AGENT_TOKEN="ctf2_$(printf 'a%.0s' $(seq 1 60))"         bash "$ARM" --table 2>&1)"
if printf '%s' "$out5" | grep -q 'CTF² 竞技场' \
   && printf '%s' "$out5" | grep -q 'CTF2_BASE_URL' \
   && printf '%s' "$out5" | grep -q 'CTF2_AGENT_TOKEN'; then
  ok "T5 有 CTF² 凭据 → 确认表以 CTF² 为主平台并校验 CTF2_* 变量"
else
  bad "T5 有 CTF² 凭据却仍按 DASCTF 展示（假绿）：$(printf '%s' "$out5" | sed -n '4,6p' | tr '\n' ' ')"
fi

# ── T6：无 CTF² 凭据时回退 DASCTF（不能把 CTF² 当唯一路径）─────────────────────
out6="$(env -u CTF2_BASE_URL -u CTF2_AGENT_TOKEN bash "$ARM" --table 2>&1)"
if printf '%s' "$out6" | grep -q 'DASCTF' \
   && printf '%s' "$out6" | grep -q 'DASCTF_BASE_URL'; then
  ok "T6 无 CTF² 凭据 → 回退 DASCTF 并校验 DASCTF_BASE_URL"
else
  bad "T6 回退路径失效：$(printf '%s' "$out6" | sed -n '4,6p' | tr '\n' ' ')"
fi

# ── T7：令牌形态 —— 前缀不对必须告警（只判前缀，不回显值）──────────────────────
out7="$(CTF2_BASE_URL="https://ctf2.dasctf.com" CTF2_AGENT_TOKEN="wrongprefix_abc" \
        bash "$ARM" --table 2>&1)"
if printf '%s' "$out7" | grep -q '不以 ctf2_ 开头'; then
  ok "T7 令牌前缀不符 → 明确告警（不静默放行）"
else
  bad "T7 令牌前缀不符却没告警：$(printf '%s' "$out7" | sed -n '4,6p' | tr '\n' ' ')"
fi
# 反向：正确前缀不得误报
if printf '%s' "$out5" | grep -q '不以 ctf2_ 开头'; then
  bad "T7b 正确前缀 ctf2_ 被误报为不符（判据方向反了）"
else
  ok "T7b 正确前缀 ctf2_ 不误报"
fi

# ── T8：CTF_PLATFORM 显式覆盖（羊城杯现场：CTF² 令牌是好的，但当下要打 dasctf）──────
# 自动派发是"CTF² 凭据齐就走 CTF²"，没有覆盖开关就没法在不 unset 一堆变量的情况下打羊城杯。
out8="$(CTF_PLATFORM=dasctf \
        CTF2_BASE_URL="https://ctf2.dasctf.com" CTF2_AGENT_TOKEN="ctf2_$(printf 'a%.0s' $(seq 1 60))" \
        DASCTF_BASE_URL="https://ycb-bk.dasctf.com" CTF_AGENT_PLATFORM_TOKEN="ak_$(printf 'b%.0s' $(seq 1 38))" \
        bash "$ARM" --table 2>&1)"
if printf '%s' "$out8" | grep -q 'DASCTF（dasctf）' \
   && printf '%s' "$out8" | grep -q 'ycb-bk.dasctf.com'; then
  ok "T8 CTF_PLATFORM=dasctf 覆盖生效（有 CTF² 凭据也不被抢走）"
else
  bad "T8 覆盖失效，仍被自动派发到 CTF²：$(printf '%s' "$out8" | sed -n '4,6p' | tr '\n' ' ')"
fi

# ── T9：pro 与 ycb-bk 必须可区分（记忆 2026-10-24 的坑）──────────────────────
# DASCTF_BASE_URL 默认就是 pro.dasctf.com，而羊城杯入口是 ycb-bk —— 两者都"✅ 官方地址"，
# 光看绿勾会以为在打羊城杯，实际打错平台。
if printf '%s' "$out8" | grep -q '羊城杯入口是 ycb-bk'; then
  bad "T9 ycb-bk 地址被误报成「pro 是另一套」的提示（判据方向反了）"
else
  ok "T9 ycb-bk 地址不误报 pro 提示"
fi
out9="$(CTF_PLATFORM=dasctf DASCTF_BASE_URL="https://pro.dasctf.com" \
        CTF_AGENT_PLATFORM_TOKEN="ak_$(printf 'b%.0s' $(seq 1 38))" bash "$ARM" --table 2>&1)"
if printf '%s' "$out9" | grep -q '羊城杯入口是 ycb-bk'; then
  ok "T9b pro 地址给出「羊城杯入口是 ycb-bk」提示"
else
  bad "T9b pro 地址未提示羊城杯入口差异（会打错平台）"
fi

# ── T10：排行榜心跳（2026-10-24 羊城杯 0 分的直接补丁）────────────────────────
# 那场整场比赛看不到"在不在得分"：ScoreboardSnapshot 默认 false、且当时还没接线。
# 上膛必须显式打开，否则整场没有任何分数信号。
out10="$(bash "$ARM" --print 2>&1)"
if printf '%s' "$out10" | grep -qE 'CTF_SCOREBOARD_SNAPSHOT=true' \
   && printf '%s' "$out10" | grep -qE 'CTF_SCOREBOARD_INTERVAL=[0-9]+'; then
  ok "T10 上膛默认打开排行榜心跳（snapshot=true + 有间隔）"
else
  bad "T10 上膛没打开排行榜心跳：$(printf '%s' "$out10" | grep -E 'SCOREBOARD' | tr '\n' ' ')"
fi

# 间隔必须 >= PollInterval，否则 Go 侧会判定语义倒挂并静默降级为"只在收尾打一次"
# （poller.go:139 —— ScoreboardInterval < PollInterval 时置 0 并告警）。
poll="$(printf '%s' "$out10" | grep -oE 'CTF_POLL_INTERVAL=[0-9]+' | grep -oE '[0-9]+' | head -1)"
scb="$(printf '%s' "$out10" | grep -oE 'CTF_SCOREBOARD_INTERVAL=[0-9]+' | grep -oE '[0-9]+' | head -1)"
if [ -n "$poll" ] && [ -n "$scb" ] && [ "$scb" -ge "$poll" ]; then
  ok "T10b 心跳间隔($scb s) >= 轮询间隔($poll s)，不会被 Go 侧降级"
else
  bad "T10b 心跳间隔($scb) < 轮询间隔($poll)，Go 侧会静默降级为只在收尾打一次"
fi

# 反向：用户显式关掉时必须尊重（不能强行覆盖成 true）
out10c="$(CTF_SCOREBOARD_SNAPSHOT=false bash "$ARM" --print 2>&1)"
if printf '%s' "$out10c" | grep -qE 'CTF_SCOREBOARD_SNAPSHOT=false'; then
  ok "T10c 显式 CTF_SCOREBOARD_SNAPSHOT=false 被尊重（不强行覆盖）"
else
  bad "T10c 显式关闭被覆盖成 true（违反「已存在的值不覆盖」约定）"
fi

echo "----------------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
  echo "结论：PASS —— $(printf '%d' "$pass") 项全过（含 1 项因果自变异 + 平台派发/覆盖 7 项 + 排行榜心跳 3 项）"
  exit 0
fi
echo "结论：FAIL —— $fail 项未过"
exit 1
