//go:build linux

package procenv

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestHardenBlocksParentEnviron 是 2026-11-01 事故「残口」的行为断言。
//
// 事故链：模型 `print(os.environ)` 拿走 API key（已由 ChildEnv 修掉）；
// 但 `/proc/<pid>/environ` 是内核的**初始**环境快照，`os.Unsetenv` 清不掉，
// 子进程一句 `cat /proc/<ppid>/environ`、或者 `ps eww`（读的就是这个文件），
// 照样能拿到全量环境 —— 包括比赛平台的 `CTF2_AGENT_TOKEN`。
//
// 断言方式：真的起一个同 uid 的子进程去 `cat /proc/<本进程pid>/environ`，
// 必须是**读失败**。这不是查源码有没有调 Harden，而是查内核认不认。
func TestHardenBlocksParentEnviron(t *testing.T) {
	if err := Harden(); err != nil {
		t.Skipf("本环境不允许 prctl(PR_SET_DUMPABLE,0)（容器/权限限制），跳过：%v", err)
	}
	// 测试进程全局状态被改动，跑完必须还原，否则同包其它用例可能受影响。
	t.Cleanup(func() { _ = setDumpable(1) })

	pid := os.Getpid()
	out, err := exec.Command("sh", "-c", fmt.Sprintf("cat /proc/%d/environ", pid)).CombinedOutput()
	if err == nil {
		t.Fatalf("加固后同 uid 子进程仍能读到父进程 environ（泄露原形）：%d 字节", len(out))
	}
	// 反例：普通 /proc 信息仍可读，证明确实只挡了敏感文件而非整体不可用。
	if _, statErr := os.Stat(fmt.Sprintf("/proc/%d/status", pid)); statErr != nil {
		t.Fatalf("加固把普通 /proc 信息也挡了（过度）：%v", statErr)
	}
}

// TestHardenIdempotent 重复调用不应报错（生产入口可能被多处调用）。
func TestHardenIdempotent(t *testing.T) {
	if err := Harden(); err != nil {
		t.Skipf("本环境不允许 prctl：%v", err)
	}
	t.Cleanup(func() { _ = setDumpable(1) })
	if err := Harden(); err != nil {
		t.Fatalf("重复调用 Harden 失败：%v", err)
	}
}
