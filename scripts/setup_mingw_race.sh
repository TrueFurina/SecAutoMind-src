#!/usr/bin/env bash
# setup_mingw_race.sh —— 为 `go test -race` 准备一个**可用**的 mingw gcc。
#
# 为什么需要这个脚本（2026-10-23 实测，不是推测）
# ------------------------------------------------
# 本机 conda 自带的 mingw gcc 5.3.0（`D:/miniconda3_new/Library/mingw-w64/bin`）
# 的 `cc1.exe` 在 Win11 上**直接访问违例**（0xC0000005 / bash 报 Segmentation fault）：
#     $ gcc -c t.c -o t.o   → rc=1，零输出
#     $ cc1.exe --version   → rc=139
# 因此 `go build -race` / `go test -race` 一律失败：
#     runtime/cgo: ...cgo.exe: exit status 2
# 而 `-race` 在 Windows 上必须走 cgo，所以**没有可用 gcc 就等于没有 race 检测**。
#
# 解法：从 conda-forge 装一份**新版**工具链（GCC 16.2.0，binutils 2.46.1）到隔离目录，
# 用 `CC=x86_64-w64-mingw32-gcc` 指定。注意新包只提供带前缀的可执行文件名，
# **没有 `gcc.exe` 这个别名**——只加 PATH 不设 CC 会静默回落到那个坏掉的 5.3.0。
#
# 用法：
#   bash scripts/setup_mingw_race.sh          # 确保工具链存在并打印导出语句
#   eval "$(bash scripts/setup_mingw_race.sh --export)"   # 直接在当前 shell 生效
#   bash scripts/setup_mingw_race.sh --verify # 装好后自检（gcc 版本 + race 构建）
#
# 产物：D:/mingw64-gcc16（约 696 MB，**不入仓库**，gitignore 也不必管——在 D 盘根）
set -uo pipefail

PREFIX="${MINGW_RACE_PREFIX:-/d/mingw64-gcc16}"
CONDA="${CONDA_EXE:-/d/miniconda3_new/Scripts/conda.exe}"
GO="${GO_BIN:-/d/DevCache/go/bin/go.exe}"
CC_NAME="x86_64-w64-mingw32-gcc"

say() { printf '%s\n' "$*" >&2; }

have_toolchain() {
  [ -x "$PREFIX/Library/bin/$CC_NAME.exe" ]
}

install_toolchain() {
  if [ ! -x "$CONDA" ]; then
    say "[FAIL] 找不到 conda：$CONDA（可用 CONDA_EXE=... 覆盖）"
    return 1
  fi
  say "[INFO] 安装 mingw gcc 到 $PREFIX（conda-forge，约 700MB，首次 2-3 分钟）"
  # 注：conda-forge 的 m2w64-gcc 会解析到新版 gcc_impl_win-64（16.x），
  # 而不是那个在 Win11 上崩溃的 5.3.0。
  "$CONDA" create -y -p "$PREFIX" -c conda-forge m2w64-gcc --override-channels >/dev/null 2>&1
  local rc=$?
  if [ $rc -ne 0 ] || ! have_toolchain; then
    say "[FAIL] 安装失败（rc=$rc）——检查网络/镜像，或手动指定 MINGW_RACE_PREFIX 指向已有工具链"
    return 1
  fi
  say "[OK] 工具链就绪：$PREFIX/Library/bin/$CC_NAME.exe"
}

verify() {
  local cc="$PREFIX/Library/bin/$CC_NAME.exe"
  local ver
  ver="$("$cc" --version 2>&1 | head -1)"
  say "[CHECK] $ver"
  case "$ver" in
    *" 5.3.0"*)
      say "[FAIL] 仍是 5.3.0 —— 那是本机崩掉的那一版，不能用"
      return 1 ;;
  esac

  if [ ! -x "$GO" ]; then
    say "[WARN] 找不到 go（$GO），跳过 race 构建自检"
    return 0
  fi
  # 关键：cgo 是按 PATH 找编译器的，必须把工具链目录放进 PATH（只设 CC 不够）
  local tmp="/d/tmp_race_verify"
  mkdir -p "$tmp"
  printf 'package main\nimport "C"\nfunc main(){ _ = C.int(1) }\n' > "$tmp/m.go"
  ( cd "$tmp" && PATH="$PREFIX/Library/bin:$PATH" CC="$CC_NAME" GO111MODULE=off "$GO" build -race -o "$tmp/out.exe" m.go ) 2>"$tmp/err"
  local rc=$?
  if [ $rc -ne 0 ]; then
    say "[FAIL] race 构建失败（rc=$rc）："
    sed -n '1,10p' "$tmp/err" >&2
    return 1
  fi
  rm -f "$tmp/m.go" "$tmp/err" "$tmp/out.exe"
  say "[OK] go build -race 通过"
}

case "${1:-}" in
  --export)
    have_toolchain || install_toolchain || exit 1
    printf 'export PATH="%s/Library/bin:$PATH"\n' "$PREFIX"
    printf 'export CC=%s\n' "$CC_NAME"
    ;;
  --verify)
    have_toolchain || install_toolchain || exit 1
    verify
    ;;
  *)
    have_toolchain || install_toolchain || exit 1
    say ""
    say "在当前 shell 生效："
    say "    eval \"\$(bash scripts/setup_mingw_race.sh --export)\""
    say "然后："
    say "    go test ./internal/ctfplatform/ -race -count=1"
    say ""
    say "注意：只加 PATH 不设 CC 会静默回落到坏掉的 gcc 5.3.0（新包没有 gcc.exe 别名）。"
    ;;
esac
