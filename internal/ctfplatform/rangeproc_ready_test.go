package ctfplatform

// waitRangeReady 的自测：用「re-exec 测试二进制」当子进程替身，不依赖 python。
// 覆盖三种情形：① 子进程启动即崩 → 快速失败且错误里带它的 stderr；
// ② 子进程活着但不起服务 → 超时报错且带输出；③ 正常就绪 → 返回 cleanup 且能杀掉子进程。

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRangeProcChildHelper 是子进程替身，仅由本文件用例通过 re-exec 启动。
func TestRangeProcChildHelper(t *testing.T) {
	mode := os.Getenv("RANGEPROC_CHILD_MODE")
	if mode == "" {
		t.Skip("仅作为子进程替身使用")
	}
	switch mode {
	case "fail":
		fmt.Fprintln(os.Stderr, "OSError: [WinError 10048] 通常每个套接字地址只允许使用一次")
		os.Exit(3)
	case "hang":
		time.Sleep(60 * time.Second)
	case "serve":
		port := os.Getenv("RANGEPROC_CHILD_PORT")
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		_ = http.ListenAndServe("127.0.0.1:"+port, mux)
	}
}

func childCmd(mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=TestRangeProcChildHelper")
	cmd.Env = append(os.Environ(), "RANGEPROC_CHILD_MODE="+mode)
	return cmd
}

// ① 子进程启动即崩：必须快速失败，且错误里带上它的 stderr。
func TestWaitRangeReady_FailsFastOnChildCrash(t *testing.T) {
	start := time.Now()
	cleanup, err := waitRangeReady(t, childCmd("fail"), "http://127.0.0.1:59998", 10*time.Second)
	elapsed := time.Since(start)

	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("子进程已退出，waitRangeReady 应当报错")
	}
	if cleanup != nil {
		t.Error("失败时不应返回 cleanup")
	}
	if elapsed > 5*time.Second {
		t.Errorf("没有快速失败，耗时 %v（应远小于 10s 超时）", elapsed)
	}
	// 核心价值：python 崩溃原因可见（此前完全不可见）
	if !strings.Contains(err.Error(), "10048") {
		t.Errorf("错误未携带子进程输出，无法定位崩溃原因: %v", err)
	}
}

// ② 子进程活着但不起服务：超时报错，并说明「无输出」而不是空错误。
func TestWaitRangeReady_TimeoutReportsOutput(t *testing.T) {
	start := time.Now()
	cleanup, err := waitRangeReady(t, childCmd("hang"), "http://127.0.0.1:59997", 1200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("超时应当报错")
	}
	if !strings.Contains(err.Error(), "未就绪") {
		t.Errorf("错误文案应说明未就绪: %v", err)
	}
	if elapsed > 8*time.Second {
		t.Errorf("超时后未及时返回，耗时 %v", elapsed)
	}
}

// ③ 正常就绪：返回可用的 cleanup，且能真正杀掉子进程。
func TestWaitRangeReady_SuccessThenCleanup(t *testing.T) {
	// 取一个空闲端口
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	cmd := childCmd("serve")
	cmd.Env = append(cmd.Env, "RANGEPROC_CHILD_PORT="+strconv.Itoa(port))

	cleanup, err := waitRangeReady(t, cmd, "http://127.0.0.1:"+strconv.Itoa(port), 15*time.Second)
	if err != nil {
		t.Fatalf("应当就绪: %v", err)
	}
	if cleanup == nil {
		t.Fatal("就绪时必须返回 cleanup")
	}
	cleanup()

	// 清理后端口不应再监听
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cl := webClient(500 * time.Millisecond)
		if code, _ := httpQuickGet(t.Context(), cl, "http://127.0.0.1:"+strconv.Itoa(port)+"/"); code == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("cleanup 后端口仍在监听（子进程未被真正终止）")
}
