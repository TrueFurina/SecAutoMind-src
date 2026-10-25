#!/bin/bash
# P0-4 多通道 LLM 评测运行器（服务器侧，detached 用）
#
# 凭证通道（安全约定）：本机 Windows 用户环境变量 → ssh 加密管道 → 服务器 tmpfs
# （/dev/shm，RAM 非磁盘）600 权限文件 → 本脚本 source 后**立即删除**。
# key 全程不进 argv、不进日志、不落磁盘。
#
# 为什么不用 stdin：detached（nohup）进程继承 ssh 通道 fd 时，主 shell 一退
# sshd 就拆通道 → read 读到空 → 测试静默 SKIP（2026-10-25 实锤，日志只有 5 行）。
# tmpfs 文件由同步 ssh 写入，reader 无竞争。
set -u
ENVFILE="${ENVFILE:-/dev/shm/.llmenv}"
if [ -f "$ENVFILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENVFILE"
  set +a
  rm -f "$ENVFILE"
fi

export LLM_EVAL_BASE_URL="https://developer.amd.com.cn/radeon/api/v1"
export LLM_EVAL_MODEL="DeepSeek-V4-Flash"
export LLM_EVAL_LIMIT="${LIMIT:-3}"
# P0-4 通道 failover：主通道用尽后最多再试 N 个备用通道；单通道内重试 M 次
export LLM_EVAL_FAILOVER_MAX="${FAILOVER_MAX:-3}"
export LLM_EVAL_CHANNEL_RETRIES="${CHAN_RETRIES:-2}"
export PATH=~/go/bin:$PATH
export GOPATH=~/gopath
export GOROOT=~/go
export GOPROXY=https://goproxy.cn,direct

cd ~/secauto || exit 9
timeout 2700 go test -count=1 -timeout 40m -v -run TestLLMAutoSolve ./internal/ctfplatform/ 2>&1
