package ctfplatform

// rangeproc_test.go —— 测试用靶场进程清理工具。
//
// 背景（2026-10-21 实测）：靶场用例用 `exec.Command("python", range.py, port)` 起服务，
// 结束时 `cmd.Process.Kill()` 在 Windows 上**不一定杀干净**——实测留下
// `python.exe ssrf_range.py 18220` 持续 LISTENING，导致下一次运行绑不上固定端口，
// 表现为 "靶场未就绪" 或打到陈旧实例（数据不同 → flag 不匹配）。
//
// 对策：① 启动前先清掉占用该端口的残留监听；② 结束时用 taskkill /T /F 杀进程树；
// ③ 就绪等待期间捕获子进程输出、进程提前退出即失败（否则崩溃原因完全不可见）。

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// killProcessTree 杀掉 pid 及其子进程（Windows 用 taskkill /T，其他平台退回 Kill）。
func killProcessTree(pid int) {
	if pid <= 0 {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T", "/F").Run()
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

// killPortListeners 杀掉所有正在 LISTEN 指定端口的进程（仅 Windows 实现）。
// 用于"上一轮残留"的防御性清理；取不到就静默跳过，不影响测试语义。
func killPortListeners(port int) {
	if runtime.GOOS != "windows" {
		return
	}
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return
	}
	target := ":" + strconv.Itoa(port)
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, target) || !strings.Contains(line, "LISTENING") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		pid := f[len(f)-1]
		if seen[pid] || pid == "0" {
			continue
		}
		seen[pid] = true
		_ = exec.Command("taskkill", "/PID", pid, "/T", "/F").Run()
	}
}

// procOutput 是并发安全的子进程输出缓冲（stdout 与 stderr 会同时写入）。
type procOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *procOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

// Tail 返回末尾至多 n 字节的输出，用于失败时定位崩溃原因。
func (o *procOutput) Tail(n int) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	b := o.buf.Bytes()
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.TrimSpace(string(b))
}

// waitRangeReady 启动靶场进程并等待 HTTP 就绪，返回清理函数。
//
// 与「裸轮询 10 秒再报未就绪」的区别（2026-10-22 实测驱动）：
//   - 捕获 stdout/stderr：此前 python 崩溃（如端口占用抛 OSError）完全不可见，
//     只能看到「未就绪」，无法区分「起得慢」与「已经崩了」；
//   - 进程提前退出立即失败，不再白等满超时；
//   - 用例失败时自动把靶场输出打到测试日志（就绪之后才崩也能看见）；
//   - 清理时杀进程树并等待其真正退出，避免与下一个用例的启动重叠。
func waitRangeReady(t *testing.T, cmd *exec.Cmd, baseURL string, timeout time.Duration) (func(), error) {
	t.Helper()
	out := &procOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动靶场失败: %w", err)
	}
	pid := cmd.Process.Pid

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	cleanup := func() {
		killProcessTree(pid)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
		}
	}

	detail := func() string {
		if s := out.Tail(1200); s != "" {
			return s
		}
		return "（子进程无任何输出）"
	}

	// 就绪之后靶场仍可能崩（实测：起来后立刻拒绝连接，表现为命中 0/3 且 got 为空）。
	// 用例失败时把子进程输出带进日志，否则这类故障永远是黑盒。
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("靶场进程输出（%s，末 2000 字节）:\n%s", baseURL, out.Tail(2000))
		}
	})

	deadline := time.Now().Add(timeout)
	cl := webClient(1 * time.Second)
	for {
		// 进程已退出：立刻失败并带上它的输出，不要白等到超时
		select {
		case err := <-exited:
			return nil, fmt.Errorf("靶场进程提前退出（%v）: %s", err, detail())
		default:
		}
		if code, _ := httpQuickGet(context.Background(), cl, baseURL+"/"); code == http.StatusOK {
			return cleanup, nil
		}
		if time.Now().After(deadline) {
			cleanup()
			return nil, fmt.Errorf("靶场 %.0fs 未就绪: %s；子进程输出: %s",
				timeout.Seconds(), baseURL, detail())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
