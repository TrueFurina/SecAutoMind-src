//go:build linux

package airgap

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestMain 让「测试二进制自身」也能充当包装子进程。
// Wrap 的实现是「把自己 re-exec 成包装层」——测试里那个"自己"就是测试二进制，
// 所以它必须在跑用例前调用 MaybeRunChild，否则子进程会把 childMark 当普通参数。
func TestMain(m *testing.M) {
	RegisterMain()
	MaybeRunChild() // 包装子进程：装 seccomp 后 exec 目标，不会返回
	os.Exit(m.Run())
}

func havePython3(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("无 python3，跳过端到端断网用例")
	}
	return p
}

// 核心用例：开闸后，子进程里 python 的 socket() 必须被内核拒绝。
//
// 这条用例的意义不在"代码能跑"，而在**证明闸门真的生效**：外部池 16/40 道题
// 的官方仓库里有真值，只要子进程能建 socket，评测数字就不可信。
func TestAirgapBlocksInetSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp 仅 Linux")
	}
	py := havePython3(t)
	t.Setenv("CTF_AIRGAP", "1")

	cmd := exec.Command(py, "-c", "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM); print('LEAK_OK')")
	Wrap(cmd)
	out, err := cmd.CombinedOutput()
	s := string(out)
	if err == nil && strings.Contains(s, "LEAK_OK") {
		t.Fatalf("开闸后仍能建 AF_INET socket —— 闸门失效！输出: %s", s)
	}
	if !strings.Contains(s, "PermissionError") && !strings.Contains(s, "not permitted") {
		t.Fatalf("应因 EPERM 失败，实际输出: %s (err=%v)", s, err)
	}
}

// 对照组：不开闸时必须**能**联网。否则上面的红无法归因到"闸门"，
// 可能只是环境本来就没网（这正是本项目踩过的坑：拿环境故障当代码缺陷）。
func TestAirgapDisabledAllowsInetSocket(t *testing.T) {
	py := havePython3(t)
	t.Setenv("CTF_AIRGAP", "")

	cmd := exec.Command(py, "-c", "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); print('OK'); s.close()")
	Wrap(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("环境本身建不了 socket（%v / %s），本用例无法作为对照", err, out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Fatalf("未开闸应正常建 socket，实际: %s", out)
	}
}

// AF_UNIX 必须放行：断网只针对外网出口，本地进程通信/工具链依赖它。
func TestAirgapAllowsUnixSocket(t *testing.T) {
	py := havePython3(t)
	t.Setenv("CTF_AIRGAP", "1")

	cmd := exec.Command(py, "-c", "import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('UNIX_OK'); s.close()")
	Wrap(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "UNIX_OK") {
		t.Fatalf("AF_UNIX 不应被拦: %s (err=%v)", out, err)
	}
}

// 未开闸时 Wrap 不得改写命令（否则等于给所有跑批偷偷加了一层包装）。
func TestWrapNoopWhenDisabled(t *testing.T) {
	t.Setenv("CTF_AIRGAP", "")
	cmd := exec.Command("true")
	origPath, origArgs := cmd.Path, len(cmd.Args)
	Wrap(cmd)
	if cmd.Path != origPath || len(cmd.Args) != origArgs {
		t.Fatalf("未开闸却改写了命令: path=%s args=%v", cmd.Path, cmd.Args)
	}
}
