package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// makeBigCode 构造超过阈值的源码
func makeBigCode(n int) string {
	chunk := "# pad\nimport json\nprint('hello')\n"
	for len(chunk) < n {
		chunk += "# padding line for threshold testing\n"
	}
	return chunk
}

func TestEstimatedCommandLineLen(t *testing.T) {
	if got := estimatedCommandLineLen([]string{"a", "b c", "d"}); got < 5 {
		t.Fatalf("估算异常: %d", got)
	}
}

func TestMaterializeInlineScript_NonWindowsNoOp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("仅验证非 Windows 路径")
	}
	cmd, args, err := materializeInlineScript("python3", []string{"-c", makeBigCode(60000)})
	if err != nil {
		t.Fatalf("非 Windows 应直接返回: %v", err)
	}
	if cmd != "python3" || len(args) != 2 || args[0] != "-c" {
		t.Fatalf("非 Windows 不应改写: cmd=%s args=%v", cmd, args)
	}
}

func TestMaterializeInlineScript_ShortCodeNoOp(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 专属行为")
	}
	code := "print('hi')"
	cmd, args, err := materializeInlineScript("python3", []string{"-c", code})
	if err != nil {
		t.Fatalf("短代码不应报错: %v", err)
	}
	if cmd != "python3" || len(args) != 2 || args[0] != "-c" || args[1] != code {
		t.Fatalf("短代码不应改写: %v", args)
	}
}

func TestMaterializeInlineScript_NonPythonNoOp(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 专属行为")
	}
	// bash 不落盘（命令过长但非 python）→ 返回 error，保持原样
	long := makeBigCode(60000)
	cmd, args, err := materializeInlineScript("bash", []string{"-c", long})
	if err == nil {
		t.Fatal("非 python 超长命令应返回错误提示")
	}
	if cmd != "bash" || len(args) != 2 || args[0] != "-c" {
		t.Fatalf("非 python 不应改写: cmd=%s args=%d", cmd, len(args))
	}
}

func TestMaterializeInlineScript_PythonHugeCode(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 专属行为")
	}
	code := makeBigCode(60000)
	cmd, args, err := materializeInlineScript("python3", []string{"-c", code, "--url", "http://x/"})
	if err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	if cmd != "python3" {
		t.Fatalf("command 不应改变: %s", cmd)
	}
	if len(args) != 3 {
		t.Fatalf("期望 [脚本, --url, url]，实际 %v", args)
	}
	if strings.Contains(args[0], "-c") || args[0] == "-c" {
		t.Fatalf("args[0] 应为脚本路径: %v", args[0])
	}
	if args[1] != "--url" || args[2] != "http://x/" {
		t.Fatalf("后续参数应原样保留: %v", args)
	}
	// 校验落盘内容与源码一致
	data, err := os.ReadFile(args[0])
	if err != nil {
		t.Fatalf("读取落盘脚本失败: %v", err)
	}
	if string(data) != code {
		t.Fatalf("落盘内容与源码不一致: got %d want %d", len(data), len(code))
	}
	// 幂等：再次调用得到相同路径
	_, args2, err2 := materializeInlineScript("python3", []string{"-c", code, "--url", "http://x/"})
	if err2 != nil {
		t.Fatalf("二次落盘失败: %v", err2)
	}
	if args2[0] != args[0] {
		t.Fatalf("幂等失败: %s vs %s", args2[0], args[0])
	}
}

func TestMaterializeInlineScript_CacheDirCreated(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 专属行为")
	}
	dir, err := inlineScriptCacheDir()
	if err != nil {
		t.Fatalf("创建缓存目录失败: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("缓存目录不存在或非目录: %v", err)
	}
	if filepath.Base(dir) != "secautomind-inline" {
		t.Fatalf("目录名异常: %s", dir)
	}
}

func TestMaterializeInlineScript_PythonExeSuffix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 专属行为")
	}
	code := makeBigCode(60000)
	cmd, args, err := materializeInlineScript("C:\\Python\\python3.exe", []string{"-c", code})
	if err != nil {
		t.Fatalf("exe 后缀 python 应可落盘: %v", err)
	}
	if cmd == "" || len(args) != 1 {
		t.Fatalf("改写异常: cmd=%s args=%v", cmd, args)
	}
	if !strings.HasSuffix(args[0], ".py") {
		t.Fatalf("应为 .py 落盘: %s", args[0])
	}
}
