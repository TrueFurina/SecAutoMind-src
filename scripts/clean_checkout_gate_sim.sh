#!/usr/bin/env bash
# =============================================================================
# clean_checkout_gate_sim.sh —— 干净检出门禁仿真（消除「本地 vs CI 环境不同」假红）
#
# 为什么需要（对应 MEMORY.md 环境坑）：
#   本仓 CI 在 Linux 上以纯 LF 检出运行；本地工作树是 CRLF。两类门禁会因此本地红、
#   CI 绿，产生"看起来全绿其实没验到"的假信号：
#     1. freeze-hash 类门禁（check_golden_freeze / check_final_artifacts_freeze）
#        对 golden 文件做**原始字节**哈希 —— 本地 CRLF、CI LF → 本地必红。
#     2. go 步骤：本 shell 缺 %AppData% → go 找不到 GOENV → module lookup disabled（假红）。
#     3. quant / suite-parity 门禁需 pycryptodome，得用 conda python。
#     4. go test 并行链大测试二进制会 OOM（[build failed] 假红）→ 必须 -p 1。
#     5. 重建安装包后 binary-gate 要求 exe 由 HEAD 构建（--shared 克隆，不能用 worktree）。
#     6. 若干门禁在「无 .git / 纯 LF」的归档里**结构性不可验或易误红**，已被
#        `local_gate_check.py` 在「非 git 检出」下自动 SKIP（带原因），请走真实克隆或 CI 核验：
#        - binary-gate（`check_binary_version.py`）：入口即 `git rev-parse HEAD`，归档无 .git → BLOCK；
#          且 exe 是 gitignored 构建产物，归档里没有。本地实跑已 PASS（exe 由 8010deb 构建）。
#        - line-endings-gate（`check_line_endings.py`）：默认 `git ls-files` 列文件，归档无 .git → 失败；
#          且纯 LF 归档会把 .bat/.cmd/.ps1 误判为应 CRLF。本地实跑已 PASS。
#          其自测 T7 跑默认（git）模式也需 .git，故主门禁与自测在归档里一并 SKIP；
#          其余三类（binary/cross-bench/quant）的自测不依赖 git，仍照常 [RUN]。
#        - cross-bench-manifest-gate（`check_cross_bench_manifest.py`）：C7 需 `git check-ignore`/`git ls-files`，
#          归档无 .git → 误红。本地实跑已 PASS。
#        - suite-parity-gate（`check_suite_parity.py --check`）：重型真跑门禁，21 个 wired 集各跑
#          python judge + `go test ./internal/ctfplatform/ -timeout 600s`；go test 依赖 gitignored
#          基准夹具（归档里缺 → 结构性失败），且耗时长（真仓 ~5-7min）。其 *_test.py 自测只用纯函数
#          + 读受跟踪的台账/汇总文件，无需 git/夹具，归档里仍照常 [RUN]。
#        - quant-gate（`check_quant_effect.py --full`）：重型真跑门禁（含 run_all_benchmarks 等），
#          需完整环境+时间，CI 专用（CI 实测 ~19s）。
#        它们的**自测**（*_test.py）多数不依赖 git/重型环境，仍在归档里照常运行；
#        例外是 **line-endings 的自测** T7 跑默认（git）模式也需 .git，故与主门禁一并 SKIP。
#
# 本脚本只做一件事：把仓库导成一份**纯 LF 的干净检出**，在那份检出里按 CI 同样的方式
# 跑门禁。它**不重复任何门禁命令**——直接调用已经存在的、权威的：
#   · scripts/local_gate_check.py  （从 .github/workflows/ci.yml 解析 run:，本地复刻 python+node 门禁）
#   · scripts/finals_preflight.py  （决赛 go/no-go：演练 + 口径 + 密钥 + 证据包 + 开关）
# 命令清单只有 ci.yml 一处真值源，永不漂移（local_gate_check 的设计意图）。
#
# 用法：
#   bash scripts/clean_checkout_gate_sim.sh            # python+node 门禁（快速，约 3~6 分钟）
#   bash scripts/clean_checkout_gate_sim.sh --list    # 只列将要跑的命令，不执行（验证抽取+解析）
#   bash scripts/clean_checkout_gate_sim.sh --go      # 追加 go 步骤（build + 演练台）
#   bash scripts/clean_checkout_gate_sim.sh --full    # 追加整包 go test -p 1（数分钟~十余分钟）
#       注：归档不含 gitignored 的 data/，本脚本会从工作树补入（约 22MB），
#       否则 ctfplatform 的 exec/cross-bench 用例会因缺夹具结构性假红（2026-10-22 实测）。
#   bash scripts/clean_checkout_gate_sim.sh --preflight  # 追加决赛预检（--phase pre）
#
# 退出码：0 = 仿真全绿；1 = 有失败；2 = 抽取/环境准备失败（fail-closed）。
#
# 纪律：不碰 .git（archive 抽取无 .git）；不 git add -A；抽取目录在 D:/tmp_ci_sim（与仓库无关）。
# =============================================================================
set -u

# ---- 定位仓库根（脚本在 scripts/ 下，根 = 上一级）---------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- 解析参数 --------------------------------------------------------------
LIST_ONLY=0
RUN_GO=0
RUN_FULL=0
RUN_PREFLIGHT=0
for a in "$@"; do
  case "$a" in
    --list) LIST_ONLY=1 ;;
    --go)   RUN_GO=1 ;;
    --full) RUN_FULL=1 ;;
    --preflight) RUN_PREFLIGHT=1 ;;
    *) echo "未知参数：$a（可选 --list|--go|--full|--preflight）" >&2; exit 2 ;;
  esac
done

# ---- 环境准备（对应 MEMORY.md 环境坑，缺一不可）-----------------------------
export APPDATA="$USERPROFILE/AppData/Roaming"
export PATH="/d/miniconda3_new:/d/DevCache/go/bin:$PATH"
# 三条**独立** export（禁止 TMP=TEMP=TMPDIR=x 多重赋值，会生成非法路径）
export TMP=/d/tmp_gotest
export TEMP=/d/tmp_gotest
export TMPDIR=/d/tmp_gotest
mkdir -p /d/tmp_gotest || { echo "[FAIL] 无法创建 $TMP" >&2; exit 2; }

# 校验关键工具
command -v git  >/dev/null 2>&1 || { echo "[FAIL] 找不到 git" >&2; exit 2; }
command -v tar  >/dev/null 2>&1 || { echo "[FAIL] 找不到 tar（Git Bash 应自带）" >&2; exit 2; }
command -v python >/dev/null 2>&1 || { echo "[FAIL] PATH 注入 conda 后仍找不到 python" >&2; exit 2; }

# ---- 抽取纯 LF 干净检出 -----------------------------------------------------
OUT=/d/tmp_ci_sim
echo "==> 抽取纯 LF 干净检出到 $OUT"
rm -rf "$OUT"
mkdir -p "$OUT" || { echo "[FAIL] 无法创建 $OUT" >&2; exit 2; }
# 关键：-c core.autocrlf=false 否则 git archive 仍按 autocrlf 导出 CRLF（见 MEMORY）
git -C "$REPO_ROOT" -c core.autocrlf=false archive HEAD | tar -x -C "$OUT"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
  echo "[FAIL] git archive 失败（仓库可能不干净或 git 不可用）" >&2
  exit 2
fi
if [ ! -f "$OUT/ci.yml" ] && [ ! -f "$OUT/.github/workflows/ci.yml" ]; then
  echo "[FAIL] 抽取结果缺少 ci.yml，抽取可能不完整" >&2
  exit 2
fi
echo "    抽取完成（$(find "$OUT" -type f | wc -l) 个文件，纯 LF）"

# 用工作树 scripts/ 覆盖抽取出的版本：git archive 只含已提交文件，未提交的门禁修复
# （如 binary-gate 在非 git 检出下自动 SKIP）不会进归档，会导致仿真失真。
# 仅覆盖 scripts/；数据类文件（golden/evidence 等 autocrlf 敏感项）仍取自纯 LF 归档。
cp -r "$REPO_ROOT/scripts/." "$OUT/scripts/" 2>/dev/null \
  || echo "    [warn] 覆盖 scripts/ 失败，沿用归档版本（门禁修复可能未生效）"

# 补入 gitignored 的 data/ 夹具：git archive 只含受跟踪文件，而 `go test ./internal/ctfplatform/`
# 的 exec / cross-bench / suite-parity 用例要读 data/ctf_benchmark/ 下的附件与题目。
# 缺了会报「读取附件 exec_git_repo 失败 … 执行基准集(文件型)命中 13/15，期望全命中」——
# 这是**结构性假红**（2026-10-22 实测），不是代码回归。data/ 约 22MB，复制成本可忽略；
# 只读不改，且 count_stats 已按目录名排除 data/questions_*_bench/，不会污染口径数字。
cp -r "$REPO_ROOT/data/." "$OUT/data/" 2>/dev/null \
  || echo "    [warn] 补入 data/ 失败，--go/--full 的 ctfplatform 用例可能结构性假红"

# ---- 在干净检出里跑门禁 -----------------------------------------------------
cd "$OUT" || { echo "[FAIL] 无法 cd 到 $OUT" >&2; exit 2; }

OVERALL_RC=0

if [ "$LIST_ONLY" -eq 1 ]; then
  echo "==> [LIST] 仅列出命令（不执行）"
  python scripts/local_gate_check.py --list
  exit $?
fi

echo "==> [1/4] python+node 门禁（local_gate_check，纯 LF 检出，go 步骤按设计跳过）"
python scripts/local_gate_check.py
rc=$?
OVERALL_RC=$((OVERALL_RC | rc))
echo "    local_gate_check rc=$rc"

if [ "$RUN_PREFLIGHT" -eq 1 ]; then
  echo "==> [preflight] 决赛预检（--phase pre，开关不阻塞）"
  python scripts/finals_preflight.py --phase pre
  rc=$?
  OVERALL_RC=$((OVERALL_RC | rc))
  echo "    finals_preflight rc=$rc"
fi

if [ "$RUN_GO" -eq 1 ]; then
  echo "==> [2/4] go build ./..."
  go build ./...
  rc=$?
  OVERALL_RC=$((OVERALL_RC | rc))
  echo "    go build rc=$rc"
  echo "==> [3/4] 演练台（rehearsal）"
  go test -count=1 -run TestRehearsal ./internal/ctfplatform/
  rc=$?
  OVERALL_RC=$((OVERALL_RC | rc))
  echo "    rehearsal rc=$rc"
fi

if [ "$RUN_FULL" -eq 1 ]; then
  echo "==> [4/4] 整包 go test -p 1 ./...（防 OOM 假红）"
  go test -count=1 -p 1 ./...
  rc=$?
  OVERALL_RC=$((OVERALL_RC | rc))
  echo "    go test full rc=$rc"
fi

echo "==================================================================="
if [ "$OVERALL_RC" -eq 0 ]; then
  echo " 干净检出门禁仿真：全部通过 ✅（go 步骤若未加 --go/--full 仍请以 CI 为准）"
else
  echo " 干净检出门禁仿真：存在失败 ❌（rc=$OVERALL_RC；区分真实红与网络/环境失败）"
fi
echo "==================================================================="
exit $OVERALL_RC
