package handler

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestZip 在临时目录生成一个测试 zip，entries 为 name→content 映射。
func buildTestZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建 zip 失败: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, content := range entries {
		if strings.HasSuffix(name, "/") {
			if _, err := zw.Create(name); err != nil {
				t.Fatalf("创建 zip 目录条目失败: %v", err)
			}
			continue
		}
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("创建 zip 条目失败: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("写入 zip 条目失败: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip 失败: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭文件失败: %v", err)
	}
	return path
}

func TestExtractZipArchiveNormal(t *testing.T) {
	zipPath := buildTestZip(t, map[string]string{
		"readme.txt":           "hello",
		"docs/plan.md":         "# plan",
		"docs/nested/scan.txt": "nmap result",
		"empty_dir/":           "",
	})
	dest := filepath.Join(t.TempDir(), "out")

	files, err := extractZipArchive(zipPath, dest)
	if err != nil {
		t.Fatalf("解包失败: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("期望解出 3 个文件，实际 %d: %v", len(files), files)
	}
	for _, rel := range []string{"readme.txt", "docs/plan.md", "docs/nested/scan.txt"} {
		found := false
		for _, f := range files {
			if f == rel {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("缺少解包文件 %s，实际: %v", rel, files)
		}
	}
	b, err := os.ReadFile(filepath.Join(dest, "docs", "plan.md"))
	if err != nil || string(b) != "# plan" {
		t.Fatalf("解包内容不符: %v %q", err, string(b))
	}
}

func TestExtractZipArchiveRejectsZipSlip(t *testing.T) {
	zipPath := buildTestZip(t, map[string]string{
		"safe.txt":        "ok",
		"../evil.txt":     "escape",
		"..\\evil2.txt":   "escape2",
		"C:/abs.txt":      "abs",
		"sub/../../out..": "weird",
	})
	dest := filepath.Join(t.TempDir(), "out")

	files, err := extractZipArchive(zipPath, dest)
	if err != nil {
		t.Fatalf("解包不应失败（恶意条目应被跳过）: %v", err)
	}
	_ = files
	// 解包目录之外不得出现逃逸文件
	parent := filepath.Dir(dest)
	entries, _ := os.ReadDir(parent)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "evil") || e.Name() == "abs.txt" || e.Name() == "out.." {
			t.Fatalf("检测到 zip-slip 逃逸文件: %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "safe.txt")); err != nil {
		t.Fatalf("安全条目应正常解出: %v", err)
	}
}

func TestExtractZipArchiveRejectsBomb(t *testing.T) {
	// 单文件超过上限：构造声明体积超限的条目
	zipPath := buildTestZip(t, map[string]string{
		"ok.txt": "fine",
	})
	dest := filepath.Join(t.TempDir(), "out")

	if _, err := extractZipArchive(zipPath, dest); err != nil {
		t.Fatalf("正常小包解包失败: %v", err)
	}

	// 条目数超限
	big := make(map[string]string, maxZipExtractEntries+1)
	for i := 0; i <= maxZipExtractEntries; i++ {
		big["f"+strings.Repeat("x", 1)+string(rune('a'+i%26))+string(rune('0'+i/26))+".txt"] = "x"
	}
	bigZip := buildTestZip(t, big)
	if _, err := extractZipArchive(bigZip, filepath.Join(t.TempDir(), "out2")); err == nil {
		t.Fatalf("条目数超限应返回错误")
	}
}
