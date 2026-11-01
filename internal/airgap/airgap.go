// Package airgap 给「会执行模型/题目代码的子进程」装一道**系统调用级**断网闸。
//
// 为什么需要（2026-11-01 实测）：外部题池 40 道里有 **16 道**，其公开源仓库的
// `challenge/flag.txt` 的 sha256 与题集登记的真值**逐位相等** —— 只要子进程能联网，
// 一条 `curl` 就能拿到答案，任何"解出率"都是假的。审计题源、剔除题目都不解决问题
// （剔除后池子几乎清空），唯一干净的解法是**执行期断网**。
//
// 为什么不能用 HTTP 层方案：`RUNNER_LLM_AIRGAP` 只作用于 read_attachment 的 HTTP 客户端，
// 模型走 python_session 里自己写的 requests/urllib 直连，绕得干干净净（真机事故）。
// 服务器上 `unshare -n` 也不可用（uid_map 写失败、无 sudo）。因此只能落到 seccomp：
// 非 root 也能装，拦的是 socket(AF_INET/AF_INET6) 本身，与上层用什么库无关。
//
// 为什么默认关：赛时要连靶机/远程服务，断网等于自废武功。这个闸只用于
// **离线题集的能力评测**（`CTF_AIRGAP=1`），不许在比赛模式打开。
package airgap

import (
	"os"
	"os/exec"
	"sync/atomic"
)

// childMark 是包装子进程的识别标记，必须是参数而非环境变量：
// 环境变量会被 procenv 白名单过滤掉，标记就丢了。
const childMark = "--airgap-child"

// registered 标记「本进程的 main 已声明支持包装」。
// 关键防御：Wrap 只有在注册后才改写命令。否则一个没接入口的二进制被 Wrap 之后
// 会以 `--airgap-child ...` 启动自己，把参数当正常参数跑，行为错乱且难查。
var registered atomic.Bool

// RegisterMain 在 main 开头调用一次，声明本二进制支持包装子进程。
func RegisterMain() { registered.Store(true) }

// Enabled 读 CTF_AIRGAP（"1"/"true"/"on" 视为开）。默认关。
func Enabled() bool {
	switch os.Getenv("CTF_AIRGAP") {
	case "1", "true", "on", "TRUE", "yes":
		return true
	}
	return false
}

// IsChild 表示当前进程是包装子进程（即已装断网闸）。
func IsChild() bool { return len(os.Args) > 2 && os.Args[1] == childMark }

// Active 表示「本进程是包装子进程」或「已开闸」，调用方据此决定是否记录日志。
func Active() bool { return Enabled() || IsChild() }

// MaybeRunChild 在 main 开头调用：若当前进程是包装子进程，
// 就装 seccomp 并把自身 exec 成真正的目标命令。正常情况下立即返回。
func MaybeRunChild() {
	if len(os.Args) < 3 || os.Args[1] != childMark {
		return
	}
	runChild(os.Args[2], os.Args[3:])
}

// Wrap 把 cmd 改写为「先起包装子进程（装 seccomp）→ 再 exec 原命令」。
// 未开闸或本二进制未注册时什么都不做，保持原有行为。
func Wrap(cmd *exec.Cmd) {
	if cmd == nil || !Enabled() || !registered.Load() {
		return
	}
	self, err := os.Executable()
	if err != nil || self == "" {
		return
	}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	args := make([]string, 0, len(cmd.Args)+3)
	args = append(args, self, childMark, cmd.Path)
	args = append(args, cmd.Args[1:]...)
	cmd.Path = self
	cmd.Args = args
	cmd.Env = env
}
