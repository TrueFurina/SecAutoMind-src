package ctfplatform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// newTestPlatform 构造测试用 DasCTFPlatform（小退避 + 短 TTL，保证测试确定性）。
func newTestPlatform(t *testing.T, baseURL string) *DasCTFPlatform {
	t.Helper()
	p := NewDasCTFPlatform(baseURL, "", zap.NewNop())
	p.MaxRetries = 5
	p.RetryBackoff = time.Millisecond
	p.WAFTimeout = 300 * time.Second
	p.listCacheTTL = 200 * time.Millisecond
	return p
}

// ── 官方协议契约（错一条即 0 分，必须逐条锁死）──────────────────

// 契约①：提交只发 {} 内内容（手工册第 7 条）。
func TestStripFlagWrapper(t *testing.T) {
	cases := map[string]string{
		"flag{synthetic_case}": "synthetic_case",
		"DASCTF{abc-123}":      "abc-123",
		"FLAG{upper}":          "upper",
		"ctf{lower}":           "lower",
		"raw_value_no_braces":  "raw_value_no_braces",
		"  flag{trimmed}  ":    "trimmed",
		"flag{inner{brace}}":   "inner{brace}",
		"flag{}":               "flag{}", // 内部为空 → 回退原值，绝不提交空串
		"":                     "",
	}
	for in, want := range cases {
		if got := StripFlagWrapper(in); got != want {
			t.Errorf("StripFlagWrapper(%q) = %q, want %q", in, got, want)
		}
	}
}

// 契约②：成功码**只认字符串 "00000"**（严格对齐真源 dasctf.py:562 `str(code) == "00000"`）。
// 2026-09-13 深度复检：原实现 int/string 双兼容（`0` / `"0"` 判成功）属目标侧单边放宽，已回退。
func TestCodeIsSuccess(t *testing.T) {
	cases := map[string]bool{
		`"00000"`: true,
		`0`:       false, // 真源 str(0)="0" != "00000" → 不算成功
		`"0"`:     false,
		`"10001"`: false,
		`500`:     false,
		`""`:      false,
		`null`:    false,
	}
	for raw, want := range cases {
		if got := codeIsSuccess(json.RawMessage(raw)); got != want {
			t.Errorf("codeIsSuccess(%s) = %v, want %v", raw, got, want)
		}
	}
}

// 契约③：提交 body 键名为 flag（非 answer）+ exerciseId 为数值 + 剥离外壳。
// 断言里显式检查 answer 键**不存在**，防止回归。
func TestSubmitBodyProtocol(t *testing.T) {
	var mu sync.Mutex
	var raw map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(body, &m)
		mu.Lock()
		raw = m
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":true,"remainingAttempts":49}}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	res, err := p.SubmitFlag(context.Background(), "1001", "flag{rsa_small_e_2026}")
	if err != nil {
		t.Fatalf("SubmitFlag 失败: %v", err)
	}
	if !res.Correct || !res.Accepted {
		t.Fatalf("应判定正确并接受，实际正确=%v 接受=%v detail=%q", res.Correct, res.Accepted, res.Detail)
	}
	if res.RemainingAttempts != 49 {
		t.Errorf("remainingAttempts 应解析为 49，实际 %d", res.RemainingAttempts)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, hasAnswer := raw["answer"]; hasAnswer {
		t.Error("提交 body 不得含 answer 键（官方契约键名为 flag）")
	}
	if got, _ := raw["flag"].(string); got != "rsa_small_e_2026" {
		t.Errorf("flag 值应为剥离外壳后的内容，实际 %q", got)
	}
	// exerciseId 必须是 JSON 数值而非字符串
	if _, ok := raw["exerciseId"].(float64); !ok {
		t.Errorf("exerciseId 应为数值类型，实际 %T(%v)", raw["exerciseId"], raw["exerciseId"])
	}
}

// 错误 flag：code 成功但 isCorrect=false → Correct=false 且 Accepted=false。
func TestSubmitWrongFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":false,"message":"答案错误"}}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	res, err := p.SubmitFlag(context.Background(), "1001", "flag{wrong}")
	if err != nil {
		t.Fatalf("不应返回传输层错误: %v", err)
	}
	if res.Correct || res.Accepted {
		t.Fatal("错误 flag 不得判为正确/接受")
	}
	if res.RequestFailed {
		t.Fatal("业务码成功时不得标记 request_failed")
	}
	if res.Detail != "答案错误" {
		t.Errorf("detail 应取 message，实际 %q", res.Detail)
	}
}

// 短响应体（<200 字节）曾因 string(data)[:200] 直接 panic —— 回归锁。
func TestSubmitShortBodyNoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`)) // 2 字节
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	if _, err := p.SubmitFlag(context.Background(), "1", "flag{x}"); err != nil {
		t.Fatalf("空对象响应不应报错: %v", err)
	}
}

// ── 列表解析：corpus 嵌套展平（静默错解高风险点）──────────────────

func TestFlattenCorpusNesting(t *testing.T) {
	payload := `{"code":"00000","data":[
		{"id":1,"name":"CRYPTO","order":1,"corpus":[
			{"id":1001,"name":"CRYPTO-01","order":1,"isOpen":true,"hasSolved":false,"description":"题目描述 A"},
			{"id":1002,"name":"CRYPTO-02","order":2}
		]},
		{"id":2,"name":"MISC","order":2,"corpus":[]},
		{"id":1003,"name":"WEB-01","title":"WEB-01","category":"web","description":"题目描述 B"}
	]}`
	var resp struct {
		Code json.RawMessage `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatal(err)
	}
	list, ok := flattenChallenges(resp.Data)
	if !ok {
		t.Fatal("合法数组应返回 ok=true")
	}
	if len(list) != 3 {
		t.Fatalf("应展平出 3 道题（空 corpus 容器不产出），实际 %d: %+v", len(list), list)
	}
	byID := map[string]Challenge{}
	for _, c := range list {
		byID[c.ID] = c
	}
	// 分类容器自身不得被当成题目
	if _, exists := byID["1"]; exists {
		t.Error("分类容器 id=1 不应作为题目出现")
	}
	c1, has1 := byID["1001"]
	if !has1 {
		t.Fatalf("缺少题 1001，实得 %+v", list)
	}
	if c1.Title != "CRYPTO-01" {
		t.Errorf("1001 标题应为 CRYPTO-01，实际 %q", c1.Title)
	}
	if c1.Category != "crypto" {
		t.Errorf("1001 题型应从标题前缀归一化为 crypto，实际 %q", c1.Category)
	}
	if c1.Description != "题目描述 A" {
		t.Errorf("1001 描述解析错误: %q", c1.Description)
	}
	// 纯标识符标题不做 description 兜底（保 no-data 快速止损）
	if c2 := byID["1002"]; c2.Description != "" {
		t.Errorf("1002 纯标识符标题不应兜底为描述，实际 %q", c2.Description)
	}
	if c3 := byID["1003"]; c3.Category != "web" {
		t.Errorf("1003 题型应为 web，实际 %q", c3.Category)
	}
}

// 合法空列表必须算成功（赛前放题窗口常态），不得误判为故障。
func TestEmptyListIsOK(t *testing.T) {
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	list, err := p.ListChallenges(context.Background())
	if err != nil {
		t.Fatalf("空列表不应报错: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("应为空，实际 %d", len(list))
	}
	if !p.LastListOK() {
		t.Error("200 空列表应标记 lastListOK=true")
	}
}

// ── 抗打击治理 ①–⑦ ──────────────────────────────────────

func TestComputeBackoff(t *testing.T) {
	cases := []struct {
		name     string
		backoff  time.Duration
		attempt  int
		retryAft string
		want     time.Duration
	}{
		{"retry_after_preferred", 2 * time.Second, 1, "5", 5 * time.Second},
		// Retry-After: 0 不被采纳（只有 >0 才优先），回落指数退避 1ms*2^1=2ms
		{"retry_after_zero_falls_back", 2 * time.Second, 1, "0", 4 * time.Second},
		{"exp_backoff_attempt1", 2 * time.Second, 1, "", 4 * time.Second},
		{"exp_backoff_capped", 2 * time.Second, 3, "", 15 * time.Second}, // 16s → 上限 15s
		{"retry_after_non_numeric", 2 * time.Second, 1, "Wed, 21 Oct", 4 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := computeBackoff(c.backoff, c.attempt, c.retryAft); got != c.want {
				t.Errorf("computeBackoff = %v, want %v", got, c.want)
			}
		})
	}
}

// ②⑦ 429 重试 + Retry-After + 连续计数 + 成功后重置
func TestRetryBackoffAndRetryAfter(t *testing.T) {
	var mu sync.Mutex
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	data, status, err := p.doRequest(context.Background(), "GET", "challenges", nil)
	if err != nil {
		t.Fatalf("重试后应成功: %v", err)
	}
	if status != http.StatusOK || len(data) == 0 {
		t.Fatalf("status=%d data=%q", status, data)
	}
	mu.Lock()
	total := calls
	mu.Unlock()
	if total != 3 {
		t.Errorf("应共 3 次请求（1 + 2 重试），实际 %d", total)
	}
	if p.Consec429() != 0 {
		t.Errorf("成功后连续 429 计数应重置为 0，实际 %d", p.Consec429())
	}
	if p.BackoffSuggestion(0) != 0 {
		t.Error("无 429 时退避建议应为 0（不干预）")
	}
}

// ② 重试耗尽 → 返回错误且计数累计（不能假装成功）
func TestRetryExhausted(t *testing.T) {
	var mu sync.Mutex
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	if _, _, err := p.doRequest(context.Background(), "GET", "challenges", nil); err == nil {
		t.Fatal("重试耗尽应返回错误")
	}
	mu.Lock()
	total := calls
	mu.Unlock()
	if total != 6 { // 首次 + 5 次重试
		t.Errorf("应共 6 次请求，实际 %d", total)
	}
	// 6 次请求全部被 429 → 连续 429 计数 = 6（阶梯退避据此升级到 60s 档）
	if p.Consec429() != 6 {
		t.Errorf("连续 429 应为 6，实际 %d", p.Consec429())
	}
	if p.BackoffSuggestion(0) != 60 { // ≥5 → 60s
		t.Errorf("6 次连续 429 应给出 60s 退避建议，实际 %v", p.BackoffSuggestion(0))
	}
}

// ④ 阶梯退避建议
func TestBackoffSuggestionStaircase(t *testing.T) {
	p := newTestPlatform(t, "http://example.invalid")
	cases := map[int]float64{0: 0, 2: 0, 3: 30, 5: 60, 8: 120, 12: 300, 13: 300}
	for n, want := range cases {
		p.mu.Lock()
		p.consec429 = n
		p.mu.Unlock()
		if got := p.BackoffSuggestion(0); got != want {
			t.Errorf("consec429=%d → 建议 %v，期望 %v", n, got, want)
		}
	}
}

// ⑤ 403 WAF 冷却：冷却期内不再打扰平台，冷却到期后恢复正常请求
func TestWAF403Freeze(t *testing.T) {
	var mu sync.Mutex
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		// 仅首次 403（模拟 WAF 命中），之后恢复正常 —— 否则无法验证"冷却后恢复"
		if n == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	p.WAFTimeout = 50 * time.Millisecond

	if _, err := p.ListChallenges(context.Background()); err == nil {
		t.Fatal("403 应返回错误")
	}
	if p.WafBlockedSeconds() <= 0 {
		t.Fatal("403 后应进入 WAF 冷却")
	}
	mu.Lock()
	c1 := calls
	mu.Unlock()
	if c1 != 1 {
		t.Fatalf("首次应命中平台 1 次，实际 %d", c1)
	}

	// 冷却期内：冻结，不打扰平台
	if _, err := p.ListChallenges(context.Background()); err == nil {
		t.Fatal("冷却期内应被冻结拦截")
	}
	mu.Lock()
	c2 := calls
	mu.Unlock()
	if c2 != 1 {
		t.Fatalf("冷却期内不应再请求平台，实际 %d", c2)
	}

	time.Sleep(60 * time.Millisecond)
	if p.WafBlockedSeconds() != 0 {
		t.Fatal("冷却到期应自动清零")
	}
	if _, err := p.ListChallenges(context.Background()); err != nil {
		t.Fatalf("冷却后应恢复: %v", err)
	}
	mu.Lock()
	c3 := calls
	mu.Unlock()
	if c3 != 2 {
		t.Fatalf("冷却后应第 2 次命中平台，实际 %d", c3)
	}
}

// ⑤ 详情请求也必须走治理通道（否则"WAF 冻结所有请求"是假承诺）
func TestWAFBlocksDetailRequest(t *testing.T) {
	var mu sync.Mutex
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	p.WAFTimeout = 50 * time.Millisecond
	_ = p.WafBlockedSeconds() // 触发一次读取

	// 先触发一次 403（走 ListChallenges）
	if _, err := p.ListChallenges(context.Background()); err == nil {
		t.Fatal("403 应报错")
	}
	mu.Lock()
	after := calls
	mu.Unlock()

	// 冷却期内详情请求必须被拦截，且不新增网络请求
	if _, err := p.GetChallenge(context.Background(), "1001"); err == nil {
		t.Fatal("冷却期内详情请求应被拦截")
	}
	mu.Lock()
	final := calls
	mu.Unlock()
	if final != after {
		t.Fatalf("冷却期内详情请求不应打到平台，实际 %d → %d", after, final)
	}
}

// ⑥ 列表 TTL 缓存
func TestListCacheTTL(t *testing.T) {
	var mu sync.Mutex
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":[{"id":"1","name":"t","description":"d","category":"misc"}]}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	p.listCacheTTL = 150 * time.Millisecond

	if _, err := p.ListChallenges(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ListChallenges(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	c1 := calls
	mu.Unlock()
	if c1 != 1 {
		t.Fatalf("TTL 内应只请求 1 次，实际 %d", c1)
	}

	time.Sleep(160 * time.Millisecond)
	if _, err := p.ListChallenges(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	c2 := calls
	mu.Unlock()
	if c2 != 2 {
		t.Fatalf("TTL 过期后应请求 2 次，实际 %d", c2)
	}
}

// ⑥ last_list_ok 在失败时必须为 false（否则上层会把"拉取失败"当"无新题"）
func TestLastListOKFalseOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	_, err := p.ListChallenges(context.Background())
	if err == nil {
		t.Fatal("403 应报错")
	}
	if p.LastListOK() {
		t.Error("拉取失败时 last_list_ok 必须为 false")
	}
}

// ⑦ HTTP 连接复用
func TestHTTPClientReuse(t *testing.T) {
	p := newTestPlatform(t, "http://example.invalid")
	if p.HTTPClient == nil {
		t.Fatal("HTTPClient 应被创建")
	}
	if p.HTTPClient != p.HTTPClient {
		t.Fatal("HTTPClient 应复用同一实例（连接池）")
	}
}

// ── Poller 闭环 ─────────────────────────────────────────

// Poller 自动解题 + 提交（确定性求解器，避免 presolve 候选顺序造成 flaky）
func TestPollerAutoSolveAndSubmit(t *testing.T) {
	var mu sync.Mutex
	var submits int
	var lastAnswer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slab-match/api/v1/agent/ctf/exercise-list":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":[{"id":"1001","name":"misc-1","description":"答案就在这里：flag{auto_solve_2026}","category":"misc"}]}`))
		case "/slab-match/api/v1/agent/answer-panel/answer":
			body, _ := io.ReadAll(r.Body)
			var req map[string]interface{}
			_ = json.Unmarshal(body, &req)
			mu.Lock()
			submits++
			if s, ok := req["flag"].(string); ok {
				lastAnswer = s
			}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":true}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
		}
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
		return FilterFlagCandidates(ExtractFlags(ch.Description)), nil
	}

	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.MaxConcurrency = 1
	poller := NewPoller(p, solver, pc, zap.NewNop())
	poller.SetAdvisor(p)

	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 失败: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("应处理 1 题，实际 %d", len(records))
	}
	if !records[0].Accepted {
		t.Fatalf("flag 应被平台接受，rec=%+v", records[0])
	}
	mu.Lock()
	s, ans := submits, lastAnswer
	mu.Unlock()
	if s != 1 {
		t.Fatalf("应提交 1 次，实际 %d", s)
	}
	// 关键契约：提交的是剥离外壳后的内容
	if ans != "auto_solve_2026" {
		t.Fatalf("应提交剥离外壳后的内容 auto_solve_2026，实际 %q", ans)
	}
}

// Poller 不自动提交 → 绝不触碰提交端点
func TestPollerNoAutoSubmit(t *testing.T) {
	var mu sync.Mutex
	var submits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slab-match/api/v1/agent/answer-panel/answer" {
			mu.Lock()
			submits++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/slab-match/api/v1/agent/ctf/exercise-list" {
			_, _ = w.Write([]byte(`{"code":"00000","data":[{"id":"1001","name":"misc-1","description":"答案：flag{no_submit_2026}","category":"misc"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
		return FilterFlagCandidates(ExtractFlags(ch.Description)), nil
	}
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = false
	pc.MaxConcurrency = 1
	poller := NewPoller(p, solver, pc, zap.NewNop())

	if _, err := poller.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 失败: %v", err)
	}
	mu.Lock()
	s := submits
	mu.Unlock()
	if s != 0 {
		t.Fatalf("SubmitAfterSolve=false 时不应提交，实际 %d 次", s)
	}
}

// 误提交闸门：非 flag 形态候选必须被拦下，不得发往平台
func TestPollerBlocksNonFlagCandidates(t *testing.T) {
	var mu sync.Mutex
	var submits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slab-match/api/v1/agent/answer-panel/answer" {
			mu.Lock()
			submits++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/slab-match/api/v1/agent/ctf/exercise-list" {
			_, _ = w.Write([]byte(`{"code":"00000","data":[{"id":"1001","name":"misc-1","description":"d","category":"misc"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	// 求解器故意返回非 flag 文本
	solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
		return []string{"hash_crack: x=weak", "md5=abc"}, nil
	}
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.MaxConcurrency = 1
	poller := NewPoller(p, solver, pc, zap.NewNop())

	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 失败: %v", err)
	}
	mu.Lock()
	s := submits
	mu.Unlock()
	if s != 0 {
		t.Fatalf("非 flag 形态候选必须被拦截，实际提交 %d 次", s)
	}
	if len(records) != 1 || records[0].Error == "" {
		t.Fatalf("应记录拦截原因，rec=%+v", records)
	}
}

// 去重：同一题第二轮不再处理
func TestPollerDedup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/slab-match/api/v1/agent/ctf/exercise-list" {
			_, _ = w.Write([]byte(`{"code":"00000","data":[{"id":"1001","name":"misc-1","description":"d","category":"misc"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	solver := func(ctx context.Context, ch *Challenge) ([]string, error) { return nil, nil }
	pc := DefaultPollerConfig()
	pc.PollInterval = 10 * time.Millisecond
	poller := NewPoller(p, solver, pc, zap.NewNop())

	if _, err := poller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("第二轮应无新题，实际 %d", len(records))
	}
}

// 集成器平台接线：nil → 报错；真实平台 → 委托提交
func TestIntegratorSubmitWiring(t *testing.T) {
	integNil := NewPresolveAgentIntegrator(NewPresolver(zap.NewNop()), NewTaskAnalyzer(), nil, zap.NewNop())
	if integNil.Platform() != nil {
		t.Fatal("未接线时 Platform() 应为 nil")
	}
	if _, err := integNil.SubmitFlag(context.Background(), "1", "flag{x}"); err == nil {
		t.Fatal("nil 平台 SubmitFlag 应报错")
	}

	var mu sync.Mutex
	var submits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		submits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":true}}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	integ := NewPresolveAgentIntegrator(NewPresolver(zap.NewNop()), NewTaskAnalyzer(), p, zap.NewNop())
	if integ.Platform() == nil {
		t.Fatal("接线后 Platform() 不应为 nil")
	}
	res, err := integ.SubmitFlag(context.Background(), "1", "flag{x}")
	if err != nil {
		t.Fatalf("真实平台 SubmitFlag 应成功: %v", err)
	}
	if !res.Correct {
		t.Fatal("应标记 correct=true")
	}
	mu.Lock()
	s := submits
	mu.Unlock()
	if s != 1 {
		t.Fatalf("应向平台提交 1 次，实际 %d", s)
	}
}

// presolve 层冒烟（不掺入候选顺序断言，避免 flaky）
func TestPresolveExtractsFlagFromChallenge(t *testing.T) {
	presolver := NewPresolver(zap.NewNop())
	ch := &Challenge{ID: "1", Category: "misc", Description: "题目：flag{presolve_smoke_2026} 结束"}
	res := presolver.Presolve(context.Background(), ch, nil)
	if !res.Solved {
		t.Fatal("presolve 应命中题面 flag")
	}
	found := false
	for _, f := range res.Flags {
		if f == "flag{presolve_smoke_2026}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应抽到题面 flag，实际 %v", res.Flags)
	}
}
