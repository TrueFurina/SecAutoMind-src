package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"secautomind-ai/internal/config"

	"go.uber.org/zap"
)

func TestIsConnectionDeadError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof", io.EOF, true},
		{"wrapped eof", fmt.Errorf("connection closed: %w", io.EOF), true},
		{"client closing", errors.New(`calling "tools/list": client is closing: EOF`), true},
		{"connection reset", errors.New("read tcp: connection reset by peer"), true},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
		{"other", errors.New("invalid params"), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isConnectionDeadError(tc.err); got != tc.want {
				t.Fatalf("isConnectionDeadError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestLazySDKClient_MarkDisconnected(t *testing.T) {
	c := &lazySDKClient{status: "connected"}
	c.inner = &sdkClient{status: "connected"}
	c.markDisconnected()
	if c.IsConnected() {
		t.Fatal("expected disconnected after markDisconnected")
	}
	if c.GetStatus() != "disconnected" {
		t.Fatalf("expected status disconnected, got %s", c.GetStatus())
	}
}

func TestHandleConnectionDead_MarksLazyClientDisconnected(t *testing.T) {
	logger := zap.NewNop()
	m := NewExternalMCPManager(logger)

	name := "dead-mcp"
	cfg := config.ExternalMCPServerConfig{
		Type:              "http",
		URL:               "http://example.com/mcp",
		ExternalMCPEnable: true,
	}
	m.mu.Lock()
	m.configs[name] = cfg
	client := newLazySDKClient(cfg, logger)
	client.inner = &sdkClient{status: "connected"}
	client.status = "connected"
	m.clients[name] = client
	m.mu.Unlock()

	deadErr := errors.New(`connection closed: calling "tools/list": client is closing: EOF`)

	// 预置退避状态，挡住 handleConnectionDead 内 spawn 的 tryReconnect goroutine：
	// 该 goroutine 走到 startClient 会 delete(m.errors, name)（重连启动清旧错，
	// external_manager.go:348，产品语义正确）。若它在断言前抢先执行，GetError
	// 断言就偶发失败（2026-09-28 CI 实锤 run 534ebd0：-race + 共享 runner 下
	// 调度窗口被命中）。预置 attempts=10 → backoff=5min → goroutine 被限流闸门
	// 偏转进 scheduleReconnectAfter，只挂一个测试期内不会触发的定时器，
	// 断言窗口内 errors 必然完好；测试自身语义（断言 markDisconnected + 记错）不受影响。
	m.reconnectMu.Lock()
	m.reconnectAttempts[name] = 10
	m.reconnectLastTry[name] = time.Now()
	m.reconnectMu.Unlock()

	m.handleConnectionDead(name, client, deadErr)

	if client.IsConnected() {
		t.Fatal("expected disconnected after handleConnectionDead")
	}
	if m.GetError(name) == "" {
		t.Fatal("expected error message to be recorded")
	}
	counts := m.GetToolCounts()
	if counts[name] != 0 {
		t.Fatalf("expected tool count 0 after disconnect, got %d", counts[name])
	}
}

func TestReconnectBackoff(t *testing.T) {
	t.Parallel()
	if d := (&ExternalMCPManager{}).reconnectBackoff(0); d != 0 {
		t.Fatalf("attempt 0: got %v", d)
	}
	if d := (&ExternalMCPManager{}).reconnectBackoff(1); d != externalReconnectMinInterval {
		t.Fatalf("attempt 1: got %v", d)
	}
	if d := (&ExternalMCPManager{}).reconnectBackoff(10); d != externalReconnectMaxBackoff {
		t.Fatalf("attempt 10: got %v, want cap %v", d, externalReconnectMaxBackoff)
	}
}

func TestTryReconnect_RateLimited(t *testing.T) {
	logger := zap.NewNop()
	m := NewExternalMCPManager(logger)

	name := "rate-limited"
	m.reconnectMu.Lock()
	m.reconnectLastTry[name] = time.Now()
	m.reconnectAttempts[name] = 2
	m.reconnectMu.Unlock()

	m.tryReconnect(name)

	m.reconnectMu.Lock()
	attempts := m.reconnectAttempts[name]
	m.reconnectMu.Unlock()
	if attempts != 2 {
		t.Fatalf("rate limited reconnect should not increment attempts, got %d", attempts)
	}
}

func TestTryReconnect_SkipsWhenDisabled(t *testing.T) {
	logger := zap.NewNop()
	m := NewExternalMCPManager(logger)

	name := "disabled-mcp"
	m.mu.Lock()
	m.configs[name] = config.ExternalMCPServerConfig{
		Type:              "http",
		URL:               "http://example.com/mcp",
		ExternalMCPEnable: false,
	}
	m.mu.Unlock()

	m.tryReconnect(name)

	m.reconnectMu.Lock()
	attempts := m.reconnectAttempts[name]
	m.reconnectMu.Unlock()
	if attempts != 0 {
		t.Fatalf("disabled MCP should not increment reconnect attempts, got %d", attempts)
	}
}

func TestTryReconnect_SkipsWhenConnecting(t *testing.T) {
	logger := zap.NewNop()
	m := NewExternalMCPManager(logger)

	name := "connecting-mcp"
	cfg := config.ExternalMCPServerConfig{
		Type:              "http",
		URL:               "http://example.com/mcp",
		ExternalMCPEnable: true,
	}
	client := newLazySDKClient(cfg, logger)
	client.setStatus("connecting")

	m.mu.Lock()
	m.configs[name] = cfg
	m.clients[name] = client
	m.mu.Unlock()

	m.tryReconnect(name)

	m.reconnectMu.Lock()
	attempts := m.reconnectAttempts[name]
	m.reconnectMu.Unlock()
	if attempts != 0 {
		t.Fatalf("connecting MCP should not increment reconnect attempts, got %d", attempts)
	}
}

func TestStartClientAutoReconnect_SkipsWhenDisabled(t *testing.T) {
	logger := zap.NewNop()
	m := NewExternalMCPManager(logger)
	m.stopRefresh = make(chan struct{})

	name := "stopped"
	m.mu.Lock()
	m.configs[name] = config.ExternalMCPServerConfig{
		Type:              "http",
		URL:               "http://example.com/mcp",
		ExternalMCPEnable: false,
	}
	m.mu.Unlock()

	if err := m.startClient(name, true); err != nil {
		t.Fatalf("startClient: %v", err)
	}

	m.mu.RLock()
	cfg := m.configs[name]
	_, hasClient := m.clients[name]
	m.mu.RUnlock()
	if cfg.ExternalMCPEnable {
		t.Fatal("auto reconnect should not enable stopped MCP")
	}
	if hasClient {
		t.Fatal("auto reconnect should not create client when disabled")
	}
}

func TestOnClientConnected_ClearsReconnectState(t *testing.T) {
	m := &ExternalMCPManager{
		reconnectAttempts: map[string]int{"x": 3},
		reconnectLastTry:  map[string]time.Time{"x": time.Now()},
		reconnecting:      map[string]bool{"x": true},
	}
	m.onClientConnected("x")

	m.reconnectMu.Lock()
	defer m.reconnectMu.Unlock()
	if len(m.reconnectAttempts) != 0 || len(m.reconnectLastTry) != 0 || len(m.reconnecting) != 0 {
		t.Fatal("expected reconnect state cleared")
	}
}
