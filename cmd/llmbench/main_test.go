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

// TestPrepareWorkdirCopiesAttachmentFiles 锁死 2026-11-01 第二个静默阉割。
//
// 事故形态（真机，非推演）：external_bench.json 40 题**全部**用 `attachment_files`
// 字段声明附件，而 prepareWorkdir 只认 `artifacts`。字段名不匹配 ⇒
// `len(p.Artifacts)==0` ⇒ 整段复制被跳过 ⇒ 40/40 题的工作目录里只有 CHALLENGE.md。
// 因为连条件都没进，`[WARN] 工件缺失` 也不会打 —— 跑批看起来一切正常，实际
// 所有附件题都退化成"看题面硬猜"，唯一那条命中是模型背出来的公开题答案。
//
// 断言两层：① 声明了就必须真落盘；② 落盘的是不是**那个文件**（按内容比对，
// 不只看文件名，否则"建个同名空文件"也能骗过）。
func TestPrepareWorkdirCopiesAttachmentFiles(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("", "llmbench_att_test_")
	if err != nil {
		t.Fatal(err)
	}
	attRoot, err := os.MkdirTemp("", "llmbench_attroot_")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig); _ = os.RemoveAll(base); _ = os.RemoveAll(attRoot) })

	const id = "ext_demo_1"
	const payload = "PADDING {not a flag} chal-bytes"
	srcDir := filepath.Join(attRoot, id)
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "chal.bin"), []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	p := problem{
		ID:          id,
		Description: "带附件的题",
		AttachmentFiles: []struct {
			Name string `json:"name"`
		}{{Name: "chal.bin"}},
	}

	hasAtt, err := prepareWorkdir(base, p, attRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAtt {
		t.Fatal("声明了 attachment_files 却没复制成功 ⇒ 该题被静默阉割成无附件")
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(cwd, "chal.bin"))
	if err != nil {
		t.Fatalf("附件没落进工作目录（cwd=%s）：%v", cwd, err)
	}
	if string(got) != payload {
		t.Fatalf("落盘内容与源文件不一致：got=%q", string(got))
	}
}

// TestPrepareWorkdirWarnsWhenAttachmentSourceMissing 反向：声明了但源文件不存在时，
// hasAtt 必须是 false（让上层知道这题退化了），而不是假装有附件。
func TestPrepareWorkdirWarnsWhenAttachmentSourceMissing(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("", "llmbench_attmiss_")
	if err != nil {
		t.Fatal(err)
	}
	attRoot, err := os.MkdirTemp("", "llmbench_attrootmiss_")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig); _ = os.RemoveAll(base); _ = os.RemoveAll(attRoot) })

	p := problem{
		ID: "ext_demo_missing",
		AttachmentFiles: []struct {
			Name string `json:"name"`
		}{{Name: "nope.bin"}},
	}
	hasAtt, err := prepareWorkdir(base, p, attRoot)
	if err != nil {
		t.Fatal(err)
	}
	if hasAtt {
		t.Fatal("源文件不存在时 hasAtt 必须为 false —— 否则上层会把退化题当附件题统计")
	}
}
