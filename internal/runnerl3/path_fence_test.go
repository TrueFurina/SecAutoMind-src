package runnerl3

import (
	"os"
	"path"
	"strings"
	"testing"
)

// TestPathFenceBlocksForeignPaths 锁死「模型不许碰别人地盘」这条红线。
//
// 存在理由（2026-11-01 服务器真机取证，非理论推演）：
// 解 ycb12085_vvmm 时模型 23 次工具调用零次落在自己工作目录，反而读了
// 别人会话的私钥 /tmp/bench_keys_*/agent_*_private.pem 与 /home/user。
// 后果之一是 KPI 污染（从别人残留文件里翻到 flag 会被 sha256 判成真 HIT），
// 之二是横向越权（比赛机上就是事故）。本测试把这两类路径钉死。
func TestPathFenceBlocksForeignPaths(t *testing.T) {
	sessDir := "/tmp/secautomind_sess_123"
	workDir := "/tmp/llmbench_work/ycb12085_vvmm"
	f := newPathFence(sessDir, workDir)
	if !f.enabled {
		t.Fatalf("围栏默认必须是开启的（RUNNER_PY_FENCE 未设 = 开）")
	}

	cases := []struct {
		name      string
		code      string
		wantBlock bool
	}{
		{"会话自己的临时目录允许", `open('/tmp/secautomind_sess_123/x.bin','rb')`, false},
		{"题目工作目录允许", `open('/tmp/llmbench_work/ycb12085_vvmm/VVMM.exe','rb')`, false},
		{"只读系统路径允许", `import subprocess; subprocess.run(['/usr/bin/objdump','-d',f])`, false},
		{"相对路径不受限", `open('VVMM.exe','rb').read()[:64]`, false},
		{"无路径允许", `print(sum(range(10)))`, false},
		{"别人会话的题必须挡", `subprocess.run(['/tmp/current_time_travel/time_travel','x'])`, true},
		{"别人基准残留必须挡", `open('/tmp/deser_range_54d7y8uy/app.log')`, true},
		{"别人的私钥必须挡", `open('/tmp/bench_keys_rl18ydxq/agent_1_private.pem').read()`, true},
		{"主目录必须挡", `os.listdir('/home/user')`, true},
		{"root 必须挡", `open('/root/.ssh/id_rsa')`, true},
		{"var 数据区必须挡", `open('/var/log/syslog')`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := len(f.violations(c.code)) > 0
			if got != c.wantBlock {
				t.Fatalf("violations(%q) 拦截=%v, want %v（实际拦到的路径：%v）",
					c.code, got, c.wantBlock, f.violations(c.code))
			}
		})
	}
}

// TestPathFenceOptOutAndNonAbsolute 覆盖两个容易被改坏的点：
// ① RUNNER_PY_FENCE=0 逃逸阀真的能关（未来合法跨目录用法不会被一棍子打死）；
// ② 相对路径 / 纯算术里的斜杠不会被误伤（否则围栏会把正常解题卡死）。
func TestPathFenceOptOutAndNonAbsolute(t *testing.T) {
	f := newPathFence("/tmp/sess_x")
	const bad = `open('/home/user/secret')`
	if len(f.violations(bad)) == 0 {
		t.Fatalf("默认应拦截 /home/user")
	}
	t.Setenv("RUNNER_PY_FENCE", "0")
	f2 := newPathFence("/tmp/sess_x")
	if len(f2.violations(bad)) != 0 {
		t.Fatalf("RUNNER_PY_FENCE=0 应关闭围栏，但仍拦截")
	}
	if f2.enabled {
		t.Fatalf("RUNNER_PY_FENCE=0 时 enabled 应为 false")
	}
	// 误伤防护：相对目录、除法、含斜杠的普通表达式都不算绝对路径。
	for _, ok := range []string{
		`os.chdir('sub/dir')`,
		`print(10/2)`,
		`a = "./data/x.bin"`,
	} {
		if v := f.violations(ok); len(v) != 0 {
			t.Fatalf("相对路径被误判为越界：%q → %v", ok, v)
		}
	}
	_ = os.Getenv("RUNNER_PY_FENCE")
	_ = strings.TrimSpace("")
}

// TestPathFenceDeniesAnswerFilesInsideAllowedRoot 锁死 2026-11-01 的伪造分数线。
//
// 事故形态：围栏按进程 cwd 建白名单，而 harness 对纯文本题不 chdir ⇒ cwd=仓库根 ⇒
// 整个仓库放行 ⇒ 模型能读 data/answers/*.json（明文真值）⇒ 读了再提交必然 sha256 匹配。
// 假端点已实锤（读到的内容是真值 JSON 片段），所以这条必须以**拒绝**为断言。
func TestPathFenceDeniesAnswerFilesInsideAllowedRoot(t *testing.T) {
	t.Setenv("RUNNER_PY_FENCE", "") // 默认开启
	repo := "/home/user/SecAutoMind"
	f := newPathFence(repo, "/tmp/secautomind_sess_1")

	for _, bad := range []string{
		`open('/home/user/SecAutoMind/data/answers/ycb2026_truth.json')`,
		`open('/home/user/SecAutoMind/data/answers/anything.json')`,
		`open('/home/user/SecAutoMind/.git/config')`,
		`open('/home/user/SecAutoMind/keys/agent_1_private.pem')`,
	} {
		if v := f.violations(bad); len(v) == 0 {
			t.Fatalf("敏感路径必须在 allowed 根内也被拒：%q", bad)
		}
	}

	// 反例：普通题目文件仍要放行，否则误挡会把正常解题卡死。
	for _, ok := range []string{
		`open('/home/user/SecAutoMind/data/ctf_benchmark/real_benchmark.json')`,
		`open('/tmp/secautomind_sess_1/tmp.txt')`,
	} {
		if v := f.violations(ok); len(v) != 0 {
			t.Fatalf("普通路径不应被误挡：%q → %v", ok, v)
		}
	}
}

// TestFenceWorkdirRefusesProjectSourceTree 锁死 2026-11-01 的第二条伪造分数线。
//
// 事故形态（生产路径，不是推演）：runbook 用 `cd ~/SecAutoMind_verify && ./runner`
// 启动 ⇒ runner 进程 cwd = 仓库根 ⇒ fenceWorkdir() 把整个仓库当题目工作区。
// denyFragments 只挡已知文件名模式，挡不住 docs/evidence/西湖论剑归档_*/solutions
// 里那批 writeup —— 71 个文件里 22 个含 flag 形态明文（本轮实点）。
//
// 断言分三档：真·仓库根 → 拒绝当工作区；只有 go.mod 的题目附件目录 → 必须放行
// （否则逆向/源码题会被自身围栏锁死）；显式 env 放行 → 恢复旧行为（留痕降级）。
func TestFenceWorkdirRefusesProjectSourceTree(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("取 cwd 失败: %v", err)
	}
	// 不用 t.TempDir()：Windows 上它注册的 RemoveAll 会在本测试的 chdir 恢复
	// **之前**执行（LIFO），删不掉"当前目录"⇒ 假 FAIL。自己建、自己先 chdir 再删。
	base, err := os.MkdirTemp("", "fence_repo_")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
		_ = os.RemoveAll(base)
	}()

	write := func(dir, name string) {
		t.Helper()
		if err := os.WriteFile(path.Join(dir, name), []byte("x\n"), 0o644); err != nil {
			t.Fatalf("写 %s 失败: %v", name, err)
		}
	}

	// ① 真·仓库根（go.mod + AGENTS.md）→ 不许当工作区
	repo := path.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("建 repo 失败: %v", err)
	}
	write(repo, "go.mod")
	write(repo, "AGENTS.md")
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir 失败: %v", err)
	}
	t.Setenv("RUNNER_PY_FENCE_ALLOW_REPO", "")
	if got := fenceWorkdir(); got != "" {
		t.Fatalf("仓库根不得作为题目工作区，实得 %q", got)
	}

	// ② 只有 go.mod 的目录（= 源码题附件）→ 必须仍是工作区
	chal := path.Join(base, "chal")
	if err := os.MkdirAll(chal, 0o755); err != nil {
		t.Fatalf("建 chal 失败: %v", err)
	}
	write(chal, "go.mod")
	if err := os.Chdir(chal); err != nil {
		t.Fatalf("chdir 失败: %v", err)
	}
	if got := fenceWorkdir(); got == "" {
		t.Fatalf("只含 go.mod 的题目工作区被误判为仓库根 —— 这道题的附件会被自身围栏锁死")
	}

	// ③ 显式放行 → 恢复旧行为（有痕降级）
	t.Setenv("RUNNER_PY_FENCE_ALLOW_REPO", "1")
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir 失败: %v", err)
	}
	if got := fenceWorkdir(); got == "" {
		t.Fatalf("RUNNER_PY_FENCE_ALLOW_REPO=1 时应放行仓库根")
	}
}

// TestFenceDeniesArchivedWriteups 是 ① 的纵深防御断言：
// 即便某个入口仍把仓库子目录塞进白名单，归档 writeup 也必须被 deny 表挡住。
func TestFenceDeniesArchivedWriteups(t *testing.T) {
	t.Setenv("RUNNER_PY_FENCE", "")
	f := newPathFence("/home/user/SecAutoMind", "/tmp/secautomind_sess_9")
	code := `open('/home/user/SecAutoMind/docs/evidence/西湖论剑归档_20260821/solutions/pwn1.md')`
	if v := f.violations(code); len(v) == 0 {
		t.Fatalf("归档 writeup 必须被拒（内含 flag 明文，读到即伪造分数）：%q", code)
	}
}
