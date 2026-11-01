//go:build linux

package procenv

import "syscall"

// prSetDumpable = PR_SET_DUMPABLE（linux/prctl.h）。
const prSetDumpable = 4

// Harden 让**本进程以外**的同 uid 进程读不到本进程的 /proc/<pid>/*。
//
// 为什么需要（2026-11-01 事故的残口）：`procenv.ChildEnv` 只挡住了「子进程继承」，
// 但 `/proc/<pid>/environ` 是内核保存的**初始**环境快照 —— 子进程 `open()` 它，
// 或者更简单地跑一句 `ps eww -p <父pid>`，同样能拿到 API key / 平台令牌。
// `os.Unsetenv` 对此无效（快照不随 setenv 更新），围栏也只能挡文件路径，
// 挡不住 `ps` 这个子进程。
//
// `PR_SET_DUMPABLE=0` 会让 /proc/<pid>/ 下的敏感文件（environ、mem、fd…）
// 变成 root 拥有且 0600 —— 同 uid 的普通进程读不到。这是内核提供的
// 「同用户互相不可见」开关，比赛机上正是需要的那一档。
//
// 副作用：本进程不可被 gdb/ptrace、不产生 core dump。runner 不需要这些。
func Harden() error {
	return setDumpable(0)
}

// setDumpable 是 Harden 的底层（1 = 恢复默认），供测试还原全局状态用。
func setDumpable(v int) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, uintptr(v), 0); errno != 0 {
		return errno
	}
	return nil
}
