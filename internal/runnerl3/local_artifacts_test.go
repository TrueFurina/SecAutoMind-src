package runnerl3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chdirTemp 切到临时目录并在测试结束后回到原目录。
// 注意：收尾必须回到原 cwd —— 围栏（fenceWorkdir）读的就是进程 cwd，
// 串了会让同包其它测试拿到错误白名单。
func chdirTemp(t *testing.T) string {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

func TestLocalArtifactHintListsFilesInCwd(t *testing.T) {
	dir := chdirTemp(t)
	mustWrite(t, filepath.Join(dir, "VVMM.exe"), 2048)
	mustWrite(t, filepath.Join(dir, "readme.txt"), 10)

	hint := localArtifactHint()
	if hint == "" {
		t.Fatal("有工件时应给出清单")
	}
	for _, want := range []string{"VVMM.exe", "readme.txt"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("清单应含 %q，实际：\n%s", want, hint)
		}
	}
	// 必须是**绝对路径**：python_session 的 cwd 是会话临时目录（py_session.go 里
	// os.chdir(sys.argv[1])），不等于工件目录。2026-11-01 假端点实测：只给相对名
	// 会让模型 open('VVMM.exe') 直接 FileNotFoundError。
	absWant := filepath.ToSlash(filepath.Join(dir, "VVMM.exe"))
	if !strings.Contains(hint, absWant) {
		t.Fatalf("清单必须给绝对路径 %q，实际：\n%s", absWant, hint)
	}
	// 必须显式说明 cwd 差异，否则模型会按"当前目录"理解。
	if !strings.Contains(hint, "cwd") || !strings.Contains(hint, "os.chdir") {
		t.Fatalf("清单必须说明 python_session 的 cwd 与工件目录不同，实际：\n%s", hint)
	}
}

func TestLocalArtifactHintSkipsHiddenAndCapsDepth(t *testing.T) {
	dir := chdirTemp(t)
	mustWrite(t, filepath.Join(dir, ".hidden.bin"), 8)
	mustWrite(t, filepath.Join(dir, "a", "b", "c", "deep.bin"), 8)

	hint := localArtifactHint()
	if strings.Contains(hint, ".hidden.bin") {
		t.Fatalf("隐藏文件不应出现在清单：\n%s", hint)
	}
	if strings.Contains(hint, "deep.bin") {
		t.Fatalf("超过 2 层的深层文件不应出现在清单（有界性）：\n%s", hint)
	}
}

func TestLocalArtifactHintDisabledByEnv(t *testing.T) {
	dir := chdirTemp(t)
	mustWrite(t, filepath.Join(dir, "VVMM.exe"), 16)

	t.Setenv("RUNNER_LOCAL_ARTIFACT_HINT", "0")
	if hint := localArtifactHint(); hint != "" {
		t.Fatalf("关闭后应返回空串，got：\n%s", hint)
	}
}

// TestBuildUserPromptMentionsLocalArtifacts 是**接线**测试：只测 localArtifactHint
// 本身的单测在 BuildUserPrompt 不调用它时会全绿，所以这里必须锁住调用关系。
func TestBuildUserPromptMentionsLocalArtifacts(t *testing.T) {
	dir := chdirTemp(t)
	mustWrite(t, filepath.Join(dir, "challenge_binary_xyz"), 4096)

	f := &LLMFallback{}
	out := f.buildUserPrompt(testChallenge())
	if !strings.Contains(out, "challenge_binary_xyz") {
		t.Fatalf("buildUserPrompt 应带上本地工件清单，实际：\n%s", out)
	}
}

func mustWrite(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}
