package runnerl3

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// P1-2 有状态会话测试。
// 无 Python 解释器时整体 Skip（与 cmd/runner/pyskill_rich_test.go 同口径 —— 不伪造绿）。

func requireSession(t *testing.T) *pySessionMgr {
	t.Helper()
	if ResolvePython() == "" {
		t.Skip("无可用 Python 解释器（python3/python/venv 均不在），跳过会话测试")
	}
	m := newPySessionMgr(zap.NewNop())
	t.Cleanup(m.Close)
	return m
}

// 核心语义：变量跨调用保持（一次性 skill 调用做不到这点）。
func TestPySessionVariablesPersist(t *testing.T) {
	m := requireSession(t)
	ctx := context.Background()

	if _, err := m.Exec(ctx, "x = 41 + 1", false); err != nil {
		t.Fatalf("第一次执行失败: %v", err)
	}
	out, err := m.Exec(ctx, "print(x)", false)
	if err != nil {
		t.Fatalf("第二次执行失败: %v", err)
	}
	if !strings.Contains(out, "42") {
		t.Fatalf("变量应跨调用保持（期望 42），实际输出: %s", out)
	}
}

// cwd 跨调用保持：第一步写文件，第二步能读到（多步分析的基础）。
func TestPySessionCwdPersists(t *testing.T) {
	m := requireSession(t)
	ctx := context.Background()

	if _, err := m.Exec(ctx, "open('note.txt','w').write('hello')", false); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	out, err := m.Exec(ctx, "import os; print(os.path.exists('note.txt'), open('note.txt').read())", false)
	if err != nil {
		t.Fatalf("读文件失败: %v", err)
	}
	if !strings.Contains(out, "True") || !strings.Contains(out, "hello") {
		t.Fatalf("cwd/文件应跨调用保持，实际: %s", out)
	}
}

// import 也跨调用保持（避免每步重复 import 的独白式重述）。
func TestPySessionImportsPersist(t *testing.T) {
	m := requireSession(t)
	ctx := context.Background()

	if _, err := m.Exec(ctx, "import base64", false); err != nil {
		t.Fatalf("import 失败: %v", err)
	}
	out, err := m.Exec(ctx, "print(base64.b64encode(b'ctf').decode())", false)
	if err != nil {
		t.Fatalf("第二次使用 import 的模块失败: %v", err)
	}
	if !strings.Contains(out, "Y3Rm") {
		t.Fatalf("模块应跨调用可用，实际: %s", out)
	}
}

// reset 清空变量但保留 cwd（语义必须精确，否则模型会误判）。
func TestPySessionResetClearsVarsKeepsCwd(t *testing.T) {
	m := requireSession(t)
	ctx := context.Background()

	if _, err := m.Exec(ctx, "secret = 7; open('keep.txt','w').write('k')", false); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	out, err := m.Exec(ctx, "import os; print(os.path.exists('keep.txt'))", true)
	if err != nil {
		t.Fatalf("reset 后执行失败: %v", err)
	}
	if !strings.Contains(out, "True") {
		t.Fatalf("reset 应保留 cwd 下的文件，实际: %s", out)
	}
	if _, err := m.Exec(ctx, "print(secret)", false); err == nil {
		t.Fatalf("reset 后变量 secret 应已被清空（应报错）")
	}
}

// 语法/运行错误必须如实报错，且**不杀掉会话**（后续调用仍可用）。
func TestPySessionErrorKeepsSessionAlive(t *testing.T) {
	m := requireSession(t)
	ctx := context.Background()

	if _, err := m.Exec(ctx, "1/0", false); err == nil {
		t.Fatalf("除零必须报错")
	}
	out, err := m.Exec(ctx, "y = 5; print(y*2)", false)
	if err != nil {
		t.Fatalf("报错后会话应仍可用，实际失败: %v", err)
	}
	if !strings.Contains(out, "10") {
		t.Fatalf("报错后会话应仍可用，实际: %s", out)
	}
}

// 超时：会话被销毁且**如实告知状态丢失**；下次调用惰性重启可用（不假装还在）。
func TestPySessionTimeoutDestroysAndRestarts(t *testing.T) {
	m := requireSession(t)

	if _, err := m.Exec(context.Background(), "z = 1", false); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	// 睡眠超过命令超时 → 触发超时分支
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := m.Exec(ctx, "import time; time.sleep(5)", false); err == nil {
		t.Fatalf("超时必须报错")
	}

	// 重启后可用，但状态已丢（z 不存在）
	if _, err := m.Exec(context.Background(), "print(z)", false); err == nil {
		t.Fatalf("会话重启后旧变量应不存在（状态确实丢了，必须如实反映）")
	}
	out, err := m.Exec(context.Background(), "print('revived')", false)
	if err != nil {
		t.Fatalf("会话应能重启并继续服务: %v", err)
	}
	if !strings.Contains(out, "revived") {
		t.Fatalf("重启后应可用，实际: %s", out)
	}
	if m.restarts == 0 {
		t.Fatalf("超时后应记录一次会话重建（restarts）")
	}
}

// Close 后不得再使用（防僵尸与泄漏）。
func TestPySessionCloseIsFinal(t *testing.T) {
	m := requireSession(t)
	m.Close()
	if _, err := m.Exec(context.Background(), "print(1)", false); err == nil {
		t.Fatalf("Close 后必须拒绝执行")
	}
}

// 工具层：schema + 路由（空 code 拦截、reset 字符串解析）。
func TestPythonSessionToolRouting(t *testing.T) {
	ff := newTestFallback(&fakeModel{}, 2, 2)
	sess := newPySessionMgr(zap.NewNop())
	defer sess.Close()

	// 缺 code → schema 拦截
	got := ff.executeTool(context.Background(), schema.ToolCall{
		ID:       "c1",
		Function: schema.FunctionCall{Name: "python_session", Arguments: `{"reset":"true"}`},
	}, testChallenge(), newFactLedger(), sess)
	if !isToolError(got) {
		t.Fatalf("缺 code 必须判工具错误步，实际 %q", got)
	}

	// 未知参数 → schema 拦截
	got2 := ff.executeTool(context.Background(), schema.ToolCall{
		ID:       "c2",
		Function: schema.FunctionCall{Name: "python_session", Arguments: `{"code":"print(1)","shell":"bash"}`},
	}, testChallenge(), newFactLedger(), sess)
	if !isToolError(got2) || !strings.Contains(got2, "参数校验失败") {
		t.Fatalf("未知参数必须被 schema 拦截，实际 %q", got2)
	}

	// 空 code（绕过 schema 直达实现时也要拦）
	if out := ff.toolPythonSession(context.Background(), map[string]any{"code": "  "}, sess); !isToolError(out) {
		t.Fatalf("空 code 必须拦，实际 %q", out)
	}
}

// 端到端：模型两步调用会话，第二步依赖第一步的变量 —— 这是 P1-2 的核心收益场景。
func TestSolveUsesStatefulSessionAcrossSteps(t *testing.T) {
	if ResolvePython() == "" {
		t.Skip("无可用 Python 解释器，跳过端到端会话测试")
	}
	m := &fakeModel{resps: []*schema.Message{
		toolResp("python_session", `{"code":"total = 6 * 7"}`),
		toolResp("python_session", `{"code":"print('flag{session_' + str(total) + '}')"}`),
		textResp("答案是 flag{session_42}"),
	}}
	ff := newTestFallback(m, 12, 12)

	flags, err := ff.Solve(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("Solve 不应报错: %v", err)
	}
	if len(flags) == 0 {
		t.Fatalf("两步会话应产出候选（第二步依赖第一步的变量 total），实际为空")
	}
	if flags[0] != "flag{session_42}" {
		t.Fatalf("候选不符：%v", flags)
	}
}
