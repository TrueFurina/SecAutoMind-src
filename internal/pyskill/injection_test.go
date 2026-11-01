package pyskill

// skill 桥接层的代码注入防护（2026-11-01）。
//
// 为什么在这一层再测一遍：`internal/runnerl3` 已经有入参校验（validateSkillName），
// 但**真正把名字拼进 Python 源码**的是这里的 `execSkillSubprocess`：
//
//	scriptTpl: `import %s as s`  ← skillName 来自模型
//
// 只守住上层等于"假设所有调用方都记得校验"。本用例直接在拼源码的那一处动手，
// 任何新增调用方（L2 编排、脚本、未来工具）都自动被覆盖。
//
// 判据不是"返回了好听的错误"，而是：
//   ok == false            —— 子进程代码没有以"成功"收口；
//   输出里没有 INJECTED     —— 注入语句根本没执行。
// 载荷故意写成 'INJ'+'ECTED'，避免与拒因回显混淆。

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newInjectionTestRunner(t *testing.T) *Runner {
	t.Helper()
	py := ""
	for _, c := range []string{"python3", "python"} {
		if p, err := exec.LookPath(c); err == nil {
			py = p
			break
		}
	}
	if py == "" {
		t.Skip("本机无 python，跳过（Linux 服务器/CI 覆盖）")
	}

	dir := t.TempDir()
	// 对照用正常 skill：证明"拦截"没有把正常调用一起打死。
	okSkill := "def run(params):\n    return {\"solved\": True, \"flag\": \"flag{probe_ok}\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "probe_ok.py"), []byte(okSkill), 0o644); err != nil {
		t.Fatalf("写对照 skill 失败：%v", err)
	}

	return &Runner{
		pythonPath: py,
		skillsDir:  dir,
		timeout:    20 * time.Second,
		logger:     zap.NewNop(),
	}
}

// 注入载荷：拼进模板后等价于
//
//	import os as s
//	import sys
//	print('INJ'+'ECTED')
//	sys.exit(0)
//	import os as s
//
// 进程以 0 退出 ⇒ 修复前 out 会带回 "INJECTED"、ok=true。
//
// 载荷只打印常量、不读文件：**代码执行**本身就是根能力（读任意文件、
// 起子进程都是它的下游），而"读哪个文件"会让用例依赖平台路径
// （Windows 没有 /etc/hostname ⇒ 变成 FileNotFoundError ⇒ 变异验证假绿）。
// 注入载荷（用分号而不是换行拼多条语句，纯 Python 简单语句语法即可）：
// 拼进模板后等价于
//
//	import os as s; import sys; print('INJ'+'ECTED'); sys.exit(0); import os as s
//
// 进程以 0 退出 ⇒ 修复前 out 会带回 "INJECTED"、ok=true。
//
// 载荷只打印常量、不读文件：**代码执行**本身就是根能力（读任意文件、
// 起子进程都是它的下游），而"读哪个文件"会让用例依赖平台路径
// （Windows 没有 /etc/hostname ⇒ 变成 FileNotFoundError ⇒ 变异验证假绿）。
const injectionPayload = "os as s; import sys; print('INJ'+'ECTED'); sys.exit(0); import os"

func TestExecSkillSubprocessRejectsInjectedName(t *testing.T) {
	r := newInjectionTestRunner(t)

	out, ok := r.execSkillSubprocess(context.Background(), injectionPayload, map[string]any{})
	if ok {
		t.Fatalf("注入名被当成成功执行（out=%q）—— 拼源码处没有拦截", out)
	}
	if strings.Contains(out, "INJECTED") {
		t.Fatalf("注入语句真的执行了：%q", out)
	}
}

// 对照：合法 skill 名照常执行，且结果原样返回（证明拦截不是"一刀切关死"）。
func TestExecSkillSubprocessStillRunsValidSkill(t *testing.T) {
	r := newInjectionTestRunner(t)

	out, ok := r.execSkillSubprocess(context.Background(), "probe_ok", map[string]any{})
	if !ok {
		t.Fatalf("合法 skill 执行失败：%q", out)
	}
	if !strings.Contains(out, "flag{probe_ok}") {
		t.Fatalf("skill 输出未回传：%q", out)
	}
}

// 结构断言（不依赖 python）：名字校验只放行标识符。
func TestSkillNameIdentRe(t *testing.T) {
	good := []string{"probe_ok", "zip_crack", "ctf_sage_t1_coppersmith", "_x", "A1"}
	bad := []string{
		injectionPayload,
		"os as s",
		"a.b",
		"a b",
		"1abc",
		"",
		"a;b",
		"a-b",
		"os\n",
	}
	for _, g := range good {
		if !skillNameIdentRe.MatchString(g) {
			t.Errorf("合法标识符被拒：%q", g)
		}
	}
	for _, b := range bad {
		if skillNameIdentRe.MatchString(b) {
			t.Errorf("非法名被放行：%q", b)
		}
	}
}
