package runnerl3

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// 附件收件箱的验收（2026-11-01）。
//
// 这里要同时钉住两件互相拉扯的事：
//   1. read_attachment 给的路径**必须**能被 python_session 打开（否则附件题不可解）；
//   2. 围栏**不得**因此放行整个 /tmp（否则刚堵上的跨会话越权原路重开）。
//
// 只测 1（不收件箱）与只测 2（不排除 inbox）都会用另一侧的真实事故换测绿。

func TestAttachmentInboxIsNotTempRoot(t *testing.T) {
	dir := attachmentInboxDir()
	tmp := filepath.ToSlash(os.TempDir())
	got := filepath.ToSlash(dir)

	if got == tmp {
		t.Fatalf("收件箱退化成临时目录根 %q —— 等于把整个 /tmp 加进围栏白名单", got)
	}
	if !strings.HasPrefix(got, tmp+"/") {
		t.Fatalf("收件箱应在临时目录之下，实际 %q", got)
	}
	// 目录必须真的存在（否则下载会失败成"附件不可用"，看起来像题目不支持附件）
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("收件箱未创建：%v", err)
	}
}

// 同进程内工作目录不同 ⇒ 桶不同。否则 llmbench 顺序跑多题时，
// 上一题的附件（如 flag.txt）会留在同一桶里被下一题读到。
func TestAttachmentInboxIsPerWorkdir(t *testing.T) {
	base, err := os.MkdirTemp("", "inbox_bucket_test_")
	if err != nil {
		t.Fatalf("建临时目录失败：%v", err)
	}
	defer os.RemoveAll(base)

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("取 cwd 失败：%v", err)
	}
	defer func() { _ = os.Chdir(orig) }()

	first := attachmentInboxDir()

	second := ""
	sub := filepath.Join(base, "second")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("建子目录失败：%v", err)
	}
	if err := os.Chdir(sub); err != nil {
		t.Fatalf("chdir 失败：%v", err)
	}
	second = attachmentInboxDir()

	if filepath.ToSlash(first) == filepath.ToSlash(second) {
		t.Fatalf("两个不同工作目录共用了同一个收件箱 %q —— 附件会跨题串味", first)
	}
}

// 核心断言：工具写进去的路径，围栏必须放行；而 /tmp 下别的目录必须仍被挡。
func TestFenceAllowsInboxButStillBlocksOtherTempDirs(t *testing.T) {
	f := newPathFence("/tmp/some_sess_dir", "/tmp/some_problem_dir", attachmentInboxFenceRoot())
	if f == nil || !f.enabled {
		t.Fatal("围栏应默认启用（RUNNER_PY_FENCE 未置 0）")
	}

	inboxFile := path.Join(attachmentInboxFenceRoot(), "vvmm.zip")
	okCode := fmt.Sprintf("import zipfile\nprint(zipfile.ZipFile(%q).namelist())", inboxFile)
	if bad := f.violations(okCode); len(bad) > 0 {
		t.Fatalf("收件箱里的附件被围栏自己挡下 %v —— 附件题会变成不可解", bad)
	}

	// 反例：别的 /tmp 子目录（并行会话残留、别人的私钥所在区）必须继续被挡。
	for _, evil := range []string{
		"/tmp/bench_keys_abc/agent_1_private.pem",
		"/tmp/current_time_travel/loot.txt",
		"/tmp/deser_range_r5key0pt/app.log",
	} {
		code := fmt.Sprintf("print(open(%q).read())", evil)
		if bad := f.violations(code); len(bad) == 0 {
			t.Errorf("围栏放行了 /tmp 下的第三方目录：%s", evil)
		}
	}
}

// 端到端：真的发一次 HTTP、真的落盘，然后证明落盘路径就在收件箱里、且围栏放行。
// 用假端点而不是公网，避免测试依赖网络；被测的是"路径口径"，不是下载能力。
func TestReadAttachmentWritesIntoInbox(t *testing.T) {
	const payload = "ATTACH\nflag{inbox_wiring_ok}\nEND"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	ff := &LLMFallback{}
	out := ff.toolReadAttachment(t.Context(), map[string]any{"attachment_url": srv.URL + "/vvmm_case.zip"})
	if !strings.Contains(out, "附件下载成功") {
		t.Fatalf("下载失败：%s", out)
	}

	inbox := attachmentInboxFenceRoot()
	want := path.Join(inbox, "vvmm_case.zip")
	if !strings.Contains(out, want) {
		t.Fatalf("工具回执里的路径不是收件箱形态\n want 含: %s\n got: %s", want, firstLines(out, 3))
	}
	if _, err := os.Stat(filepath.FromSlash(want)); err != nil {
		t.Fatalf("回执说写到了 %s，实际不存在：%v", want, err)
	}
	// 遗留清理：别在共享 /tmp 里留垃圾（本测试自身产生的文件）
	defer os.Remove(filepath.FromSlash(want))

	f := newPathFence(attachmentInboxFenceRoot())
	if bad := f.violations(fmt.Sprintf("open(%q)", want)); len(bad) > 0 {
		t.Fatalf("工具自己产出的路径被围栏拒绝 %v —— 接线断开", bad)
	}
}

func firstLines(s string, n int) string {
	parts := strings.Split(s, "\n")
	if len(parts) > n {
		parts = parts[:n]
	}
	return strings.Join(parts, " | ")
}
