//go:build !linux

package procenv

// Harden 在非 Linux 上是空操作（Windows/macOS 的进程环境不可被同用户
// 无权限读取，或没有 prctl 这一档语义；解题只在 Linux 服务器跑，
// 见 AGENTS.md 第零条）。保留函数是为了调用方不必写平台分支。
func Harden() error { return nil }
