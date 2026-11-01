package runnerl3

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestPythonSessionExecActuallyAppliesFence 测的是**接线**，不是判据函数。
//
// 为什么必须单独再测一次：path_fence_test.go 只验证 `violations()` 的判定逻辑，
// 把 py_session.go 里 Exec 的那段拦截删掉，那 13 个子用例**照样全绿** ——
// 这正是「门禁看起来有效、实际没锁上」的经典形态。本用例直接走 Exec，
// 删掉接线即 FAIL（已做变异验证）。
func TestPythonSessionExecActuallyAppliesFence(t *testing.T) {
	mgr := newPySessionMgr(zap.NewNop())
	defer mgr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 先证明会话本身是活的（否则下面的"拒绝"可能只是会话起不来造成的假绿）。
	out, err := mgr.Exec(ctx, "print('hi')", false)
	if err != nil {
		t.Skipf("本机无可用 Python 会话，跳过接线验证：%v", err)
	}
	if !strings.Contains(out, "hi") {
		t.Fatalf("会话未正常工作，后续断言无意义：out=%q", out)
	}

	// 关键断言：越界路径必须被 Exec 拒下，而不是真的执行掉。
	bad := "open('/home/user/.bashrc').read()[:10]"
	out, err = mgr.Exec(ctx, bad, false)
	if err == nil {
		t.Fatalf("Exec 放行了越界路径访问（out=%q）—— 围栏没接进 Exec", out)
	}
	if !strings.Contains(err.Error(), "本题工作区之外") {
		t.Fatalf("拒因不明：%v", err)
	}
	// 会话不应因为一次拒绝就死掉（否则模型会卡在原地）。
	if out, err := mgr.Exec(ctx, "print('still-alive')", false); err != nil ||
		!strings.Contains(out, "still-alive") {
		t.Fatalf("被拒后会话应当仍可用：out=%q err=%v", out, err)
	}
}
