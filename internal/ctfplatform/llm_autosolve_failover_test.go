package ctfplatform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"secautomind-ai/internal/llmchannel"
)

// 评测侧通道 failover 的端到端验证（P0-4）。
//
// 存在理由：2026-10-25 全量评测里，单通道 429 抖动触发 37 次重试、
// 3 次耗尽杀掉 2003/2008/2011。只验证"代码能编译"是不够的 ——
// 必须证明「主通道死 → 换通道 → 题继续做下去」这条因果链真的通。

func chatServer(t *testing.T, status int, body string, hits *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits++
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func okChatBody() string {
	return `{"choices":[{"message":{"content":"{\"action\":\"answer\",\"flag\":\"flag{x}\"}"}}],"usage":{"total_tokens":10}}`
}

func TestLLMSolverFailoverSwitchesChannel(t *testing.T) {
	hits1, hits2 := 0, 0
	s1 := chatServer(t, 429, `{"error":{"message":"rate limit"}}`, &hits1)
	defer s1.Close()
	s2 := chatServer(t, 200, okChatBody(), &hits2)
	defer s2.Close()

	s := newLLMSolver(s1.URL, "k1", "m1", 8)
	s.channels = []llmchannel.Channel{
		{ID: "primary", BaseURL: s1.URL, Model: "m1", APIKey: "k1"},
		{ID: "zhipu", BaseURL: s2.URL, Model: "m2", APIKey: "k2"},
	}
	s.maxChannels = 2
	s.perChanRetries = 1 // 省去 5s 退避等待，测试要快

	raw, _, err := s.callLLMWithRetry(context.Background(), []map[string]string{{"role": "user", "content": "hi"}})
	if err != nil {
		t.Fatalf("应切到备用通道并成功，实际 err=%v", err)
	}
	if raw == "" {
		t.Fatal("备用通道应答为空")
	}
	if hits1 != 1 || hits2 != 1 {
		t.Fatalf("切换未发生：主通道命中 %d（应为 1），备用命中 %d（应为 1）", hits1, hits2)
	}
	s.mu.Lock()
	sw := s.switches
	use := s.chanUse["zhipu"]
	s.mu.Unlock()
	if sw != 1 {
		t.Fatalf("换通道次数应记 1，实际 %d", sw)
	}
	if use != 1 {
		t.Fatalf("备用通道应答计数应为 1，实际 %d", use)
	}
}

func TestLLMSolverFailoverAllDeadCountsInfra(t *testing.T) {
	hits1, hits2 := 0, 0
	s1 := chatServer(t, 429, `{"error":{"message":"rate"}}`, &hits1)
	defer s1.Close()
	s2 := chatServer(t, 503, `{"error":{"message":"down"}}`, &hits2)
	defer s2.Close()

	s := newLLMSolver(s1.URL, "k1", "m1", 8)
	s.channels = []llmchannel.Channel{
		{ID: "primary", BaseURL: s1.URL, Model: "m1", APIKey: "k1"},
		{ID: "zhipu", BaseURL: s2.URL, Model: "m2", APIKey: "k2"},
	}
	s.maxChannels = 2
	s.perChanRetries = 1

	if _, _, err := s.callLLMWithRetry(context.Background(), []map[string]string{{"role": "user", "content": "hi"}}); err == nil {
		t.Fatalf("全部通道失败必须报错（调用方据此计入 infra，不与能力混算）")
	}
	if hits1 != 1 || hits2 != 1 {
		t.Fatalf("两个通道都应被尝试：hits1=%d hits2=%d", hits1, hits2)
	}
}

func TestLLMSolverPermanentErrorDoesNotSwitch(t *testing.T) {
	hits1, hits2 := 0, 0
	s1 := chatServer(t, 400, `{"error":{"message":"bad request"}}`, &hits1)
	defer s1.Close()
	s2 := chatServer(t, 200, okChatBody(), &hits2)
	defer s2.Close()

	s := newLLMSolver(s1.URL, "k1", "m1", 8)
	s.channels = []llmchannel.Channel{
		{ID: "primary", BaseURL: s1.URL, Model: "m1", APIKey: "k1"},
		{ID: "zhipu", BaseURL: s2.URL, Model: "m2", APIKey: "k2"},
	}
	s.maxChannels = 2
	s.perChanRetries = 2

	if _, _, err := s.callLLMWithRetry(context.Background(), []map[string]string{{"role": "user", "content": "hi"}}); err == nil {
		t.Fatalf("400 必须报错")
	}
	if hits1 != 1 {
		t.Fatalf("400 应在第一次调用后即失败，主通道命中 %d", hits1)
	}
	if hits2 != 0 {
		t.Fatalf("永久错误不得触发切通道（会白烧免费额度），备用命中 %d", hits2)
	}
}

// TestHTTPStatusErrorClassification 锁住「按精确状态码判定」这条口径：
// 401/403（key 无效）、404（该通道没这个模型）都是通道专属失败，必须切通道；
// 400（payload 错）任何通道都一样错，不许切。
func TestHTTPStatusErrorClassification(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{400, false},
		{401, true},
		{402, true},
		{403, true},
		{404, true},
		{408, true},
		{409, true},
		{425, true},
		{429, true},
		{500, true},
		{502, true},
		{503, true},
		{504, true},
	}
	for _, c := range cases {
		err := &httpStatusError{code: c.code, body: "x"}
		if got := isTransientHTTPErr(err); got != c.want {
			t.Errorf("HTTP %d: isTransientHTTPErr = %v, want %v", c.code, got, c.want)
		}
		if got := llmchannel.StatusTransient(c.code); got != c.want {
			t.Errorf("HTTP %d: llmchannel.StatusTransient = %v, want %v", c.code, got, c.want)
		}
	}
}
