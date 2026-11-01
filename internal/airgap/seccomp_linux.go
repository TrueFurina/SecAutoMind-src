//go:build linux

package airgap

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// runChild 是包装子进程的实现：装 seccomp 过滤器，然后原地 exec 目标命令。
// 用 exec（而非 fork+exec）是为了让信号/退出码/信号量原样透传 —— 上层看到的就是
// 真正目标进程的行为，包装层不引入任何可观测差异（除了断网本身）。
func runChild(target string, args []string) {
	if err := installSocketFilter(); err != nil {
		// fail-closed：开了闸却装不上过滤器，绝不能"当作装好了"继续跑，
		// 否则评测结果会被联网污染，且没有任何信号提示。
		fmt.Fprintf(os.Stderr, "[airgap] seccomp 安装失败，拒绝执行（fail-closed）: %v\n", err)
		os.Exit(97)
	}
	if err := syscall.Exec(target, append([]string{target}, args...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "[airgap] exec 目标失败: %v\n", err)
		os.Exit(98)
	}
}

const (
	prSetNoNewPrivs = 38
	prSetSeccomp    = 22
	seccompModeFilt = 2

	retAllow = 0x7fff0000
	retErrno = 0x00050000

	auditArchX8664 = 0xc000003e
	auditArchArm64 = 0xc00000b7

	sysSocketAmd64 = 41
	sysSocketArm64 = 198

	afInet  = 2
	afInet6 = 10
)

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

func bpf(code uint16, k uint32, jt, jf uint8) sockFilter {
	return sockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// filterProgram 生成「拦 socket(AF_INET/AF_INET6)，其余放行」的 BPF 程序。
//
// 返回 EPERM 而不是 KILL：进程被打死会让上层看到空输出，反而更难归因；
// EPERM 会让模型自己写的 requests/urllib 抛正常异常，日志里一眼能看出"被拦了"。
// AF_UNIX 必须放行：本地进程通信、部分工具链依赖它，且它不是外网出口。
func filterProgram(arch, sockSyscall uint32) []sockFilter {
	return []sockFilter{
		// 0 ld arch
		bpf(0x20, 4, 0, 0),
		// 1 jeq ARCH jt=0 jf=5 → 架构不匹配直接放行（过滤器只为断网，
		//   不该因为跑在别的架构上就把进程打死；架构门是为了别错判系统调用号）
		bpf(0x15, arch, 0, 5),
		// 2 ld nr
		bpf(0x20, 0, 0, 0),
		// 3 jeq socket jt=0 jf=4 → 非 socket 系统调用放行
		bpf(0x15, sockSyscall, 0, 4),
		// 4 ld arg0
		bpf(0x20, 16, 0, 0),
		// 5 jeq AF_INET jt=1 jf=0 → 命中跳到 7（拒绝）
		bpf(0x15, afInet, 1, 0),
		// 6 jeq AF_INET6 jt=0 jf=1 → 命中跳到 7（拒绝），否则 8（放行）
		bpf(0x15, afInet6, 0, 1),
		// 7 ret EPERM
		bpf(0x06, retErrno|uint32(syscall.EPERM), 0, 0),
		// 8 ret ALLOW
		bpf(0x06, retAllow, 0, 0),
	}
}

// archAndSocketNr 按编译目标决定 seccomp 的 arch 常量与 socket 系统调用号。
// 不支持的目标架构**返回错误**而不是猜一个：猜错等于闸门静默失效（fail-closed）。
func archAndSocketNr() (arch, sock uint32, err error) {
	switch runtime.GOARCH {
	case "amd64":
		return auditArchX8664, sysSocketAmd64, nil
	case "arm64":
		return auditArchArm64, sysSocketArm64, nil
	}
	return 0, 0, fmt.Errorf("airgap 不支持该架构: %s", runtime.GOARCH)
}

// installSocketFilter 装 seccomp。非 root 也可用（PR_SET_NO_NEW_PRIVS 之后不需要权能）。
func installSocketFilter() error {
	arch, sock, err := archAndSocketNr()
	if err != nil {
		return err
	}
	prog := filterProgram(arch, sock)
	fprog := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}

	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", errno)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilt,
		uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("PR_SET_SECCOMP: %w", errno)
	}
	return nil
}
