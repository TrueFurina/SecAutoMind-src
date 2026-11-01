package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrepareWorkdirChdirsEvenWithoutArtifacts 锁死 2026-11-01 的伪造分数线。
//
// 原实现对"无附件"的题直接 return、不 chdir ⇒ cwd 停在启动目录（通常是仓库根）
// ⇒ 路径围栏把整个仓库当白名单 ⇒ 模型能读 data/answers/ 的明文真值。
// 所以这条断言的不是"有没有复制附件"，而是**cwd 一定落在本题的干净目录里**。
func TestPrepareWorkdirChdirsEvenWithoutArtifacts(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// 不用 t.TempDir：Windows 上删不掉"仍是 cwd"的目录，清理会误报失败。
	base, err := os.MkdirTemp("", "llmbench_test_")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig); _ = os.RemoveAll(base) })

	p := problem{ID: "textonly_1", Cid: 1, Description: "纯文本题，无附件"}

	hasAtt, err := prepareWorkdir(base, p, "")
	if err != nil {
		t.Fatal(err)
	}
	if hasAtt {
		t.Fatal("无附件时 hasAtt 应为 false")
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, sanitizeID(p.ID))
	if filepath.Clean(cwd) != filepath.Clean(want) {
		t.Fatalf("无附件题也必须 chdir 进本题目录：cwd=%q want=%q", cwd, want)
	}
	if filepath.Clean(cwd) == filepath.Clean(orig) {
		t.Fatalf("cwd 不得停留在启动目录（否则仓库根会被围栏放行）")
	}

	// 目录必须是**干净**的：只应含 CHALLENGE.md，不得残留上一轮任何文件。
	ents, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() != "CHALLENGE.md" {
			t.Fatalf("工作目录应干净（只含 CHALLENGE.md），发现残留：%s", e.Name())
		}
	}
}

// TestPrepareWorkdirWipesPreviousRun 真实复现"复用同名目录"的场景：
// 上一轮留下的 flag.txt 必须在下一轮开始前被清掉（否则同目录残留可被相对路径读到，
// 围栏挡不住 —— 它只判绝对路径越界）。
func TestPrepareWorkdirWipesPreviousRun(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("", "llmbench_test_")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig); _ = os.RemoveAll(base) })

	p := problem{ID: "reuse_1", Cid: 7, Description: "d"}

	if _, err := prepareWorkdir(base, p, ""); err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	if err := os.WriteFile(filepath.Join(cwd, "flag.txt"), []byte("flag{leftover}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := prepareWorkdir(base, p, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "flag.txt")); !os.IsNotExist(err) {
		t.Fatalf("上一轮残留 flag.txt 未被清除（err=%v）", err)
	}
}

func TestSanitizeIDKeepsSafeChars(t *testing.T) {
	got := sanitizeID("ycb/12085 vvmm.exe")
	if strings.ContainsAny(got, "/\\ ") {
		t.Fatalf("sanitizeID 必须去掉路径分隔符与空格：%q", got)
	}
	if got == "" {
		t.Fatal("sanitizeID 不应返回空串")
	}
}
