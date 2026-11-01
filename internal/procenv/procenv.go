// Package procenv 给「被模型驱动的子进程」构造一份**失敏**的环境变量。
//
// 事故（2026-11-01 09:04，真机，非推演）：
//
//	llmbench 跑 aes_ecb_penguin 时，模型第 6 轮直接执行
//	    for k, v in os.environ.items(): print(k, '=', v)
//	于是 `RUNNER_LLM_API_KEY` 的明文被当成「工具输出」回给了模型 ——
//	也就是**发给了模型提供商**。同一条路上还躺着 `CTF2_AGENT_TOKEN`
//	（比赛平台令牌）与 `SSH_AUTH_SOCK`（等于把 ssh-agent 借出去）。
//
// 为什么路径围栏挡不住：围栏管的是「读文件」，`os.environ` 一次调用不碰任何路径。
// 这是两个正交的出口 —— 把仓库根挡住，不等于把进程环境挡住。
//
// 同理 `/proc/self/environ` 也是同一个出口的文件形态（见 path_fence 的 deny 表）。
//
// 策略是**白名单**：只下发解释器真正需要的那几个变量。
// 黑名单（名字里含 KEY/TOKEN 就丢）看着聪明，但漏掉一个不带这些词的机密就前功尽弃；
// 白名单的失败模式是「忘了加某个变量」，后果可预测、可复现、可修。
package procenv

import (
	"os"
	"strings"
)

// allowExact 子进程需要的精确变量名。
var allowExact = map[string]bool{
	// 基本运行环境
	"PATH": true, "HOME": true, "PWD": true, "OLDPWD": true,
	"USER": true, "LOGNAME": true, "SHELL": true, "TERM": true,
	"TMPDIR": true, "TMP": true, "TEMP": true,
	// 解释器与动态库
	"PYTHONPATH": true, "PYTHONHOME": true, "PYTHONIOENCODING": true,
	"PYTHONDONTWRITEBYTECODE": true, "PYTHONUNBUFFERED": true,
	"VIRTUAL_ENV": true, "LD_LIBRARY_PATH": true,
}

// allowPrefix 前缀白名单：语言环境（LC_*/LANG）与 Python 调优（PYTHON*）。
var allowPrefix = []string{"LC_", "LANG", "PYTHON"}

// ChildEnv 返回可安全下发给「模型可写」子进程的环境变量。
//
// 调用点（三处，全是 exec python）：
//   - internal/runnerl3/py_session.go（python_session 常驻 REPL）
//   - cmd/runner/pyskill_bridge.go（execute_python → skill 子进程）
//
// 新增任何「模型能影响其行为」的子进程，都必须走这里。
func ChildEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if allowExact[k] {
			out = append(out, kv)
			continue
		}
		for _, p := range allowPrefix {
			if strings.HasPrefix(k, p) {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}
