package security

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk/filesystem"
)

func TestEinoStreamingShell_StreamsStderrBeforeStdoutEOF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell streaming 依赖 /bin/sh（shell_execute_stream.go），仅类 Unix 环境覆盖；CI Linux job 执行")
	}
	shell := NewEinoStreamingShell()
	cmd := PrepareNonInteractiveShellCommand("echo err-only >&2; exit 1")
	sr, err := shell.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if resp != nil && resp.Output != "" {
			got.WriteString(resp.Output)
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("expected fast completion, took %v", time.Since(start))
	}
	if !strings.Contains(got.String(), "err-only") {
		t.Fatalf("expected stderr in output, got: %q", got.String())
	}
}

func TestEinoStreamingShell_SudoFailsFast(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell streaming 依赖 /bin/sh（shell_execute_stream.go），仅类 Unix 环境覆盖；CI Linux job 执行")
	}
	shell := NewEinoStreamingShell()
	cmd := PrepareNonInteractiveShellCommand("sudo whoami && sudo cat /etc/os-release")
	sr, err := shell.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if resp == nil {
			continue
		}
		got.WriteString(resp.Output)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("sudo should fail quickly, took %v output=%q", time.Since(start), got.String())
	}
	out := got.String()
	if strings.Contains(out, "command exited with non-zero code") {
		t.Fatalf("legacy exit line present: %q", out)
	}
	if !strings.Contains(out, "sudo") && !strings.Contains(out, "password") && !strings.Contains(out, "terminal") {
		t.Fatalf("expected sudo error text, got: %q", out)
	}
}

func TestEinoStreamingShell_StderrWhileStdoutBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell streaming 依赖 /bin/sh（shell_execute_stream.go），仅类 Unix 环境覆盖；CI Linux job 执行")
	}
	shell := NewEinoStreamingShell()
	// 模拟 sudo：stderr 先有输出，stdout 侧进程仍挂起；旧 eino local 在首包 stderr 前不会向流写任何内容。
	cmd := PrepareNonInteractiveShellCommand(`echo "password prompt" >&2; sleep 30`)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sr, err := shell.ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			break
		}
		if resp != nil && resp.Output != "" {
			got.WriteString(resp.Output)
			if strings.Contains(got.String(), "password prompt") {
				break
			}
		}
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("expected stderr promptly, took %v output=%q", time.Since(start), got.String())
	}
	if !strings.Contains(got.String(), "password prompt") {
		t.Fatalf("expected early stderr, got: %q", got.String())
	}
}

// TestEinoStreamingShell_BackgroundJobDoesNotHoldPipe 模拟 cmd & 后继续前台逻辑：重定向后应快速结束。
func TestEinoStreamingShell_BackgroundJobDoesNotHoldPipe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell integration in -short")
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell streaming 依赖 /bin/sh（shell_execute_stream.go），仅类 Unix 环境覆盖；CI Linux job 执行")
	}
	shell := NewEinoStreamingShell()
	cmd := `(sh -c 'printf x; sleep 120') & echo started; sleep 0`
	sr, err := shell.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: cmd})
	if err != nil {
		t.Fatalf("ExecuteStreaming: %v", err)
	}
	defer sr.Close()

	start := time.Now()
	var got strings.Builder
	for {
		resp, rerr := sr.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if resp != nil && resp.Output != "" {
			got.WriteString(resp.Output)
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("expected fast completion, took %v output=%q", time.Since(start), got.String())
	}
	if !strings.Contains(got.String(), "started") {
		t.Fatalf("expected foreground echo, got: %q", got.String())
	}
}

// TestResolveStreamingShell 平台中立：类 Unix 须解析到 /bin/sh；
// Windows 无 Git Bash 时允许失败但错误须可读（含 sh 提示），有 sh 则返回路径。
func TestResolveStreamingShell(t *testing.T) {
	shellPath, err := resolveStreamingShell()
	if err != nil {
		if runtime.GOOS != "windows" {
			t.Fatalf("resolveStreamingShell on %s: %v", runtime.GOOS, err)
		}
		if !strings.Contains(err.Error(), "sh") {
			t.Fatalf("windows shell error should mention sh/install hint, got: %v", err)
		}
		return
	}
	if shellPath == "" {
		t.Fatal("resolveStreamingShell returned empty path")
	}
}
