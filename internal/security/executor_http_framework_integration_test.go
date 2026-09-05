//go:build integration

package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secautomind-ai/internal/config"
	"secautomind-ai/internal/mcp"

	"go.uber.org/zap"
)

// TestExecutor_HttpFrameworkTest_Integration 端到端验证 Windows 命令行长度保护：
// 真实加载 tools/http-framework-test.yaml（约 50KB 内联 python3 -c），经 Executor 执行一次
// 本地 HTTP 请求。修复前该工具在 Windows 上 100% 失败（cmdline-too-long 23 次 + python3-not-found 16 次）。
//
// 前置条件：
//   - 本机 pytools venv 在 PATH（含 python3.exe + httpx 0.28 + charset_normalizer）
//   - 本地有可达的 HTTP 端点（默认 http://127.0.0.1:18086/）
//
// 运行：go test -tags integration ./internal/security/ -run TestExecutor_HttpFrameworkTest_Integration -v
func TestExecutor_HttpFrameworkTest_Integration(t *testing.T) {
	if os.Getenv("SAM_E2E_SKIP") != "" {
		t.Skip("SAM_E2E_SKIP set")
	}
	// 确保 python3 可解析（pytools venv）。
	// 注意：必须用绝对路径。Go 1.19+ 的 dot 保护会拒绝执行 LookPath 解析为相对
	// 当前目录的可执行文件（报 "cannot run executable found relative to current directory"），
	// go test 的 cwd 是包目录 internal/security，相对 PATH 条目会命中该保护。
	pytools, err := filepath.Abs(filepath.Join("..", "..", ".workbuddy", "toolchain", "pytools", "Scripts"))
	if err != nil {
		t.Fatalf("解析 pytools 绝对路径失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pytools, "python3.exe")); err != nil {
		t.Skipf("pytools python3 不可用: %v", err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", pytools+string(os.PathListSeparator)+oldPath)

	// 真实加载 tools 目录配置
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("定位仓库根失败: %v", err)
	}
	toolsDir := filepath.Join(root, "tools")
	cfg := &config.SecurityConfig{ToolsDir: toolsDir}
	dirTools, err := config.LoadToolsFromDir(toolsDir)
	if err != nil {
		t.Fatalf("加载工具配置失败: %v", err)
	}
	cfg.Tools = dirTools

	logger := zap.NewNop()
	mcpServer := mcp.NewServer(logger)
	executor := NewExecutor(cfg, mcpServer, logger)

	// 找到 http-framework-test 且确认其确实为巨型内联（证明修复前必败）
	var target *config.ToolConfig
	for i := range cfg.Tools {
		if cfg.Tools[i].Name == "http-framework-test" {
			target = &cfg.Tools[i]
			break
		}
	}
	if target == nil {
		t.Fatalf("tools 目录未找到 http-framework-test")
	}
	inlineLen := 0
	for i, a := range target.Args {
		if a == "-c" && i+1 < len(target.Args) {
			inlineLen = len(target.Args[i+1])
		}
	}
	t.Logf("http-framework-test 内联源码长度: %d bytes", inlineLen)
	if inlineLen <= inlineScriptThresholdBytes {
		t.Fatalf("内联源码应远超阈值 %d（否则该测试无意义）", inlineScriptThresholdBytes)
	}

	ctx := context.Background()
	result, err := executor.ExecuteTool(ctx, "http-framework-test", map[string]interface{}{
		"url":                 "http://127.0.0.1:18086/",
		"method":              "GET",
		"response_max_lines":  3,
		"response_max_bytes":  600,
		"show_summary":        false,
	})
	if err != nil {
		t.Fatalf("ExecuteTool 返回错误: %v", err)
	}
	if result.IsError {
		t.Fatalf("ExecuteTool 标记为错误: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	t.Logf("工具输出前 300 字符:\n%s", truncateForLog(text, 300))
	if !strings.Contains(text, "Response #1") && !strings.Contains(text, "HTTP") {
		t.Fatalf("输出不符合预期（未看到请求响应）: %s", text)
	}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
