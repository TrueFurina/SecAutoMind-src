package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveBeforeInitKeepsRelativePath(t *testing.T) {
	Reset()
	if got := Resolve("data/conversations.db"); got != "data/conversations.db" {
		t.Fatalf("未初始化时应原样返回，得到 %q", got)
	}
}

func TestResolveEmptyAndAbsolute(t *testing.T) {
	Reset()
	if got := Resolve(""); got != "" {
		t.Fatalf("空串应返回空串，得到 %q", got)
	}
	abs := filepath.Join(t.TempDir(), "x.db")
	if got := Resolve(abs); got != filepath.Clean(abs) {
		t.Fatalf("绝对路径应原样返回，得到 %q", got)
	}
}

func TestInitPrefersEnvHome(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	want := t.TempDir()
	t.Setenv(EnvHome, want)
	if got := Init(filepath.Join(t.TempDir(), "config.yaml")); got != filepath.Clean(want) {
		t.Fatalf("应使用 %s，得到 %s", want, got)
	}
	if got := Resolve("data/a.db"); got != filepath.Join(filepath.Clean(want), "data", "a.db") {
		t.Fatalf("相对路径应归到数据根，得到 %q", got)
	}
}

func TestInitKeepsExistingDataDir(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	t.Setenv(EnvHome, "")
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Init(filepath.Join(base, "config.yaml")); got != filepath.Clean(base) {
		t.Fatalf("既有 data/ 应沿用配置目录 %s，得到 %s", base, got)
	}
}

func TestInitUsesWritableConfigDir(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	t.Setenv(EnvHome, "")
	base := t.TempDir()
	if got := Init(filepath.Join(base, "config.yaml")); got != filepath.Clean(base) {
		t.Fatalf("可写目录应作为数据根 %s，得到 %s", base, got)
	}
}

func TestInitFallsBackWhenConfigDirNotWritable(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	t.Setenv(EnvHome, "")

	orig := probeDir
	probeDir = func(string) bool { return false }
	t.Cleanup(func() { probeDir = orig })

	base := t.TempDir()
	got := Init(filepath.Join(base, "config.yaml"))
	if got == filepath.Clean(base) {
		t.Fatalf("不可写目录不应被选为数据根")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("回退目录必须是绝对路径，得到 %q", got)
	}
	if want := userDataDir(); want != "" && got != filepath.Clean(want) {
		t.Fatalf("应回退到用户数据目录 %s，得到 %s", want, got)
	}
}

func TestAbsBeforeInitUsesWorkingDir(t *testing.T) {
	Reset()
	got, err := Abs("data/a.db")
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(wd, "data", "a.db") {
		t.Fatalf("未初始化时 Abs 应相对 CWD，得到 %q", got)
	}
}

func TestAbsAfterInitUsesHome(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	home := t.TempDir()
	SetHome(home)
	got, err := Abs("data/a.db")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(filepath.Clean(home), "data", "a.db") {
		t.Fatalf("初始化后 Abs 应相对数据根，得到 %q", got)
	}
}

func TestResolveAllSkipsEmpty(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	home := t.TempDir()
	SetHome(home)
	// 绝对路径必须用当前平台真实存在的绝对路径：Windows 上 "/abs/b" 不是绝对路径
	// （filepath.IsAbs 返回 false），会被当相对路径归到数据根。
	absPath := filepath.Join(t.TempDir(), "b")
	got := ResolveAll([]string{"data/a", "", "  ", absPath})
	want := []string{
		filepath.Join(filepath.Clean(home), "data", "a"),
		"",
		"  ",
		filepath.Clean(absPath),
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 项应为 %q，得到 %q", i, want[i], got[i])
		}
	}
	if ResolveAll(nil) != nil {
		t.Fatalf("nil 应返回 nil")
	}
}

func TestUserDataDirIsAbsolute(t *testing.T) {
	if d := userDataDir(); d != "" && !filepath.IsAbs(d) {
		t.Fatalf("用户数据目录必须是绝对路径，得到 %q", d)
	}
}

func TestEnsureHomeCreatesDir(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	if h, err := EnsureHome(); err != nil || h != "" {
		t.Fatalf("未初始化时 EnsureHome 应返回空串且不报错，得到 %q / %v", h, err)
	}
	home := filepath.Join(t.TempDir(), "nested", "root")
	SetHome(home)
	got, err := EnsureHome()
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(got); err != nil || !fi.IsDir() {
		t.Fatalf("数据根未创建：%q / %v", got, err)
	}
	if !strings.HasSuffix(got, "root") {
		t.Fatalf("返回路径异常：%q", got)
	}
}

func TestConfigPathKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("server: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ConfigPath(p); got != filepath.Clean(p) {
		t.Fatalf("已存在的配置不应被迁移，得到 %q", got)
	}
}

func TestConfigPathUsesWritableDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if got := ConfigPath(p); got != filepath.Clean(p) {
		t.Fatalf("可写目录应保留原路径，得到 %q", got)
	}
}

func TestConfigPathFallsBackWhenDirNotWritable(t *testing.T) {
	orig := probeDir
	probeDir = func(string) bool { return false }
	t.Cleanup(func() { probeDir = orig })

	dir := t.TempDir()
	got := ConfigPath(filepath.Join(dir, "config.yaml"))
	if !filepath.IsAbs(got) {
		t.Fatalf("回退路径必须是绝对路径，得到 %q", got)
	}
	if filepath.Dir(got) == filepath.Clean(dir) {
		t.Fatalf("不可写目录不应作为配置落点，得到 %q", got)
	}
	if filepath.Base(got) != "config.yaml" {
		t.Fatalf("回退后应保留文件名，得到 %q", got)
	}
	if want := userDataDir(); want != "" && filepath.Dir(got) != filepath.Clean(want) {
		t.Fatalf("应回退到用户数据目录 %s，得到 %s", want, filepath.Dir(got))
	}
}

func TestConfigPathDefaultsToConfigYaml(t *testing.T) {
	Reset()
	got := ConfigPath("")
	if filepath.Base(got) != "config.yaml" {
		t.Fatalf("空输入应默认 config.yaml，得到 %q", got)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("应返回绝对路径，得到 %q", got)
	}
}
