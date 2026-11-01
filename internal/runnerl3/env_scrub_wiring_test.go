package runnerl3

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestPythonSessionEnvIsScrubbed 锁死 2026-11-01 09:04 的真机事故。
//
// 事故原形（llmbench 跑 aes_ecb_penguin，真实 token，服务器 Linux）：
// 模型第 6 轮直接执行 `for k, v in os.environ.items(): print(k, '=', v)`，
// 于是 `RUNNER_LLM_API_KEY` 的明文被当作「工具输出」回给了模型，
// 也就是发给了模型提供商。这不是模型越狱，是它最自然的信息收集动作。
//
// 为什么路径围栏拦不住：`os.environ` 不碰任何路径。两条出口正交，
// 所以这里必须是**行为断言**（子进程里真的读不到），而不是查源码里有没有某行。
func TestPythonSessionEnvIsScrubbed(t *testing.T) {
	t.Setenv("RUNNER_LLM_API_KEY", "sk-should-never-reach-child")
	t.Setenv("CTF2_AGENT_TOKEN", "tok-should-never-reach-child")

	mgr := newPySessionMgr(zap.NewNop())
	defer mgr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := "import os\n" +
		"print('APIKEY=' + os.environ.get('RUNNER_LLM_API_KEY', 'ABSENT'))\n" +
		"print('TOKEN=' + os.environ.get('CTF2_AGENT_TOKEN', 'ABSENT'))\n" +
		"print('PATHOK=' + ('yes' if os.environ.get('PATH') else 'no'))"

	out, err := mgr.Exec(ctx, code, false)
	if err != nil {
		t.Skipf("本机无可用 Python 会话，跳过环境失敏验证：%v", err)
	}
	if !strings.Contains(out, "PATHOK=yes") {
		t.Fatalf("PATH 被误删（解释器将无法工作）：out=%q", out)
	}
	if !strings.Contains(out, "APIKEY=ABSENT") {
		t.Fatalf("API key 下发给模型可写子进程了（事故原形）：out=%q", out)
	}
	if !strings.Contains(out, "TOKEN=ABSENT") {
		t.Fatalf("平台令牌下发给模型可写子进程了：out=%q", out)
	}
}

// TestFenceDeniesProcEnviron 是同一事故的文件形态出口：
// 即便环境变量已白名单化，`/proc/<pid>/environ` 仍能读到**父进程**的全量环境。
func TestFenceDeniesProcEnviron(t *testing.T) {
	t.Setenv("RUNNER_PY_FENCE", "")
	f := newPathFence("/tmp/secautomind_sess_7")
	for _, code := range []string{
		`open('/proc/self/environ','rb').read()`,
		`open('/proc/1/environ','rb').read()`,
	} {
		if v := f.violations(code); len(v) == 0 {
			t.Fatalf("/proc/*/environ 必须被拒（否则白名单化形同虚设）：%q", code)
		}
	}
	// 反例：普通 /proc 只读信息仍要放行，否则会误伤正常运行。
	if v := f.violations(`open('/proc/cpuinfo').read()[:10]`); len(v) != 0 {
		t.Fatalf("普通 /proc 读取不应被挡：%v", v)
	}
}
