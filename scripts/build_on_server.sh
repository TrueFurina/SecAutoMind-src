#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build_on_server.sh —— 在实验服务器上交叉编译 Windows 交付 exe，回传后本地打包安装包
#
# 为什么需要它（2026-10-24 实锤）
#   本机 16 GB 内存，并行会话跑测试时只剩 2.3 GB，`go build` 两次报
#   `fatal error: runtime: cannot allocate memory`（compile 与 link 各一次）。
#   换到服务器（128 GB / 128 核 / Go 1.25.4）26 秒编完。**这是环境问题，不是代码问题**。
#
# 为什么不能只传 git bundle（踩过的坑）
#   `git bundle` 只带被点名的 ref，tag 图不完整 → Go 的 VCS 版本推导退化成
#   `v0.0.0-<ts>-<sha>`，而 `installer/build_installer.py` 的 `_PSEUDO_RE` 只认
#   `vX.Y.Z-0.<ts>-<sha>` → `--verify-only` 直接拒收。
#   实测：**整份 `.git` 同步**后才产出规范版本（commit == HEAD、无 dirty）。
#   ⇒ 本脚本传的是 `.git` 全量 tar，不是 bundle。
#
# 用法：
#   bash scripts/build_on_server.sh --check-env     # 只探服务器（ssh / go / 磁盘 / 内存）
#   bash scripts/build_on_server.sh                 # 全流程：服务器编译 → 回传 → 本地 makensis → 自证
#   HOST=user@1.2.3.4 bash scripts/build_on_server.sh
#
# 退出码：0 = 产物已生成且自证通过；非 0 = 任一步失败（绝不静默放过）
# ---------------------------------------------------------------------------
set -euo pipefail

HOST="${HOST:-user@172.16.222.99}"
REMOTE_DIR="${REMOTE_DIR:-sm_server_build}"
GO_BIN="${GO_BIN:-/home/user/go1.25.4/bin/go}"
MAKENSIS="${MAKENSIS:-D:/nsis_env/NSIS/makensis.exe}"
TMP_TAR="${TMP_TAR:-/d/tmp_git_sync.tar.gz}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say() { printf '\n=== %s ===\n' "$*"; }
die() { printf '[BLOCK] %s\n' "$*" >&2; exit 1; }

check_env() {
  say "服务器环境探测（$HOST）"
  # 带引号 heredoc：不在本地展开任何 $，全部交给远端 shell
  ssh -o BatchMode=yes -o ConnectTimeout=12 \
      "$HOST" "GO_BIN='$GO_BIN' bash -s" <<'REMOTE'
echo "go: $("$GO_BIN" version 2>/dev/null || echo '未找到 '"$GO_BIN")"
echo "cpu: $(nproc) 核"
free -m | awk '/内存|Mem/ {printf "mem: total=%sMB available=%sMB\n", $2, $7}'
df -h / | awk 'NR==2 {print "disk(/): avail="$4" used="$5}'
REMOTE
  echo "[OK] 探测完成（这一步不构建，安全）"
}

full_build() {
  local head short ver
  head="$(git rev-parse HEAD)"
  short="${head:0:8}"

  say "0/5 前置检查"
  if [ -n "$(git status --porcelain -- '*.go' go.mod go.sum)" ]; then
    die "Go 源码有未提交改动 —— 先提交再构建（否则会打 +dirty）"
  fi
  [ -f config.share.yaml ] || die "缺 config.share.yaml（版本号真值源）"
  echo "[OK] HEAD=$short，Go 源码无未提交改动"

  say "1/5 同步完整 .git（bundle 不够，必须整份）"
  tar czf "$TMP_TAR" .git
  scp -o BatchMode=yes -o ConnectTimeout=20 "$TMP_TAR" "$HOST:/tmp/git_sync.tar.gz" >/dev/null
  echo "[OK] 已上传 $(du -h "$TMP_TAR" | cut -f1)"

  say "2/5 服务器侧还原工作树并交叉编译"
  ssh -o BatchMode=yes -o ConnectTimeout=20 \
      "$HOST" "HEAD_SHA='$head' REMOTE_DIR='$REMOTE_DIR' GO_BIN='$GO_BIN' bash -s" <<'REMOTE'
set -e
rm -rf "$HOME/$REMOTE_DIR" && mkdir -p "$HOME/$REMOTE_DIR"
tar xzf /tmp/git_sync.tar.gz -C "$HOME/$REMOTE_DIR"
cd "$HOME/$REMOTE_DIR"
git reset --hard -q "$HEAD_SHA"
export GOROOT="$(dirname "$(dirname "$GO_BIN")")"
export PATH="$GOROOT/bin:/home/user/bin:$PATH"
export GOPATH=/home/user/gopath
export GOPROXY=https://goproxy.cn,direct
export GOFLAGS=-mod=mod
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-H windowsgui -w -s" -o /tmp/secautomind-ai.exe ./cmd/server
echo "[OK] 服务器构建完成"
ls -l /tmp/secautomind-ai.exe | awk '{print "    exe bytes:",$5}'
python3 - <<'PY'
import re
d = open('/tmp/secautomind-ai.exe', 'rb').read()
m = re.search(rb'mod\tsecautomind-ai\t([^\t\x00-\x1f]+)', d)
print('    mod version:', m.group(1).decode() if m else 'NOT FOUND')
PY
REMOTE

  say "3/5 回传 exe"
  scp -o BatchMode=yes -o ConnectTimeout=20 "$HOST:/tmp/secautomind-ai.exe" \
      "$ROOT/installer/secautomind-ai.exe" >/dev/null
  echo "[OK] -> installer/secautomind-ai.exe"

  say "4/5 本地 makensis 打安装包（轻量，不受内存影响）"
  ver="$(grep -m1 -E '^[[:space:]]*version:' config.share.yaml \
        | sed -E 's/.*version:[[:space:]]*"?([0-9A-Za-z.\-]+)"?.*/\1/')"
  [ -n "$ver" ] || die "取不到版本号"
  # config.share.yaml 里是 "v1.7.28"，而产物名与 .nsi 的 OutFile 用裸版本号 → 必须剥 v
  # （build_installer.py 的 read_version() 同样 lstrip("vV")；此处漏剥会产出
  #  SecAutoMind-Setup-v1.7.28-x64.exe，随后 --verify-only 找不到预期文件而 BLOCK）
  ver="${ver#v}"; ver="${ver#V}"
  [ -f "$MAKENSIS" ] || die "找不到 makensis：$MAKENSIS"
  # ⚠️ Git Bash 会把 /DAPP_VERSION=... 当路径转换 → 必须关掉参数转换
  ( cd installer && MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 \
      "$MAKENSIS" "/DAPP_VERSION=$ver" /V2 SecAutoMind-Setup.nsi >/dev/null )
  echo "[OK] -> installer/SecAutoMind-Setup-$ver-x64.exe"

  say "5/5 自证来源（commit 必须 == HEAD 且无 dirty）"
  python installer/build_installer.py --verify-only
  python scripts/check_binary_version.py | tail -4
}

case "${1:-}" in
  --check-env) check_env ;;
  "")          full_build ;;
  *)           die "未知参数：$1（可用：--check-env，或不带参数跑全流程）" ;;
esac
