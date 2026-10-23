package ctfplatform

// CTF² 平台客户端的**离线**协议单测（httptest 模拟平台，不碰网络）。
//
// 为什么需要这一层（2026-10-23，正式赛前一天）：
//   ctf2.go 有 999 行协议实现，但当时唯一的测试是 ctf2_live_smoke_test.go —— 它
//   在缺 CTF2_BASE_URL/CTF2_AGENT_TOKEN 时直接 t.Skip。也就是说 CI 里这个客户端
//   **一行都没被执行过**：路径拼错、鉴权头写错、`confirmation` 丢了，全都要等到
//   赛场上打真平台才会暴露。本文件用 httptest 把"平台"搬到本地，把这些断言钉死。
//
// 覆盖的失败模式（都是真实会致命的）：
//   1. 端点前缀/比赛模式路径拼错 → 404；
//   2. 鉴权头不是 `Authorization: Bearer <token>` → 401；
//   3. 提交少了 `confirmation: true` → 平台拒收（防误交的硬要求）；
//   4. 响应字段名与 OpenAPI 不一致 → 静默解析成零值（"提交成功"其实没交上）；
//   5. 429/403 治理失效 → 赛时被打爆（初赛 37 次 429 的教训）。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// newCTF2Test 起一个 httptest 平台，返回已配置好比赛上下文的客户端。
// 关键：显式写死 CompetitionID/StageID，避免 ensureContext 去猜比赛（会多发请求）。
func newCTF2Test(t *testing.T, h http.HandlerFunc) (*CTF2Platform, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	p := NewCTF2Platform(srv.URL, "test-token", zap.NewNop())
	p.CompetitionID = "comp-1"
	p.StageID = "stage-1"
	p.MaxRetries = 0          // 默认不重试，避免用例被退避拖慢
	p.RetryBackoff = time.Millisecond
	p.listCacheTTL = 0 // 关缓存：多数用例要断言"每次都真打"
	return p, srv
}

// TestCTF2ConfiguredRequiresBothEnv 门禁：两个环境变量缺一不可。
// app.go 用它决定"选 CTF² 还是回退 DasCTF"——只配一半却判 true，赛时会连不上平台。
func TestCTF2ConfiguredRequiresBothEnv(t *testing.T) {
	t.Setenv(envCTF2BaseURL, "")
	t.Setenv(envCTF2Token, "")
	if CTF2Configured() {
		t.Fatal("两者都未设置时 CTF2Configured() 必须为 false")
	}
	t.Setenv(envCTF2BaseURL, "https://ctf2.example")
	if CTF2Configured() {
		t.Fatal("只设置 BASE_URL 时 CTF2Configured() 必须为 false（否则会选中一个没 token 的平台）")
	}
	t.Setenv(envCTF2Token, "tok")
	if !CTF2Configured() {
		t.Fatal("两者都设置后 CTF2Configured() 必须为 true")
	}
}

// TestCTF2NewPlatformDefaults 默认值与 env 回填。
func TestCTF2NewPlatformDefaults(t *testing.T) {
	t.Setenv(envCTF2BaseURL, "https://env.example/")
	t.Setenv(envCTF2Token, "env-token")
	t.Setenv(envCTF2CompetitionID, "comp-env")
	t.Setenv(envCTF2StageID, "stage-env")

	p := NewCTF2Platform("", "", nil)
	if p.BaseURL != "https://env.example" {
		t.Fatalf("BaseURL 应取 env 并去掉尾斜杠，得到 %q", p.BaseURL)
	}
	if p.Token != "env-token" {
		t.Fatalf("Token 应取 env，得到 %q", p.Token)
	}
	if p.CompetitionID != "comp-env" || p.StageID != "stage-env" {
		t.Fatalf("比赛上下文应取 env，得到 comp=%q stage=%q", p.CompetitionID, p.StageID)
	}
	if p.MaxRetries <= 0 || p.RetryBackoff <= 0 || p.WAFTimeout <= 0 {
		t.Fatalf("抗打击默认值必须为正（零值等价于关治理）：%+v", p)
	}
	if p.Logger == nil || p.HTTPClient == nil {
		t.Fatal("Logger / HTTPClient 不得为 nil（nil 会在热路径 panic）")
	}
	// 空 env 时回落到官方地址
	t.Setenv(envCTF2BaseURL, "")
	if got := NewCTF2Platform("", "", nil).BaseURL; got != ctf2DefaultBaseURL {
		t.Fatalf("空配置应回落到 %q，得到 %q", ctf2DefaultBaseURL, got)
	}
}

// TestCTF2ListChallengesProtocol 断言列表请求的**路径 / 鉴权 / UA** 与解析结果。
func TestCTF2ListChallengesProtocol(t *testing.T) {
	var gotPath, gotAuth, gotUA string
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotUA = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		if r.URL.Query().Get("limit") != "100" {
			t.Errorf("列表必须带 limit=100，实际 query=%q", r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"data":{"total":2,"items":[
			{"id":"c1","name":"Web 签到","category":"web","difficulty":"EASY","points":100,
			 "has_attachments":true,"has_container":true,"is_solved":false,"solve_count":7,
			 "submission_type":"flag","score_multiplier":1.5,
			 "competition_id":"comp-1","stage_id":"stage-1"},
			{"id":"c2","name":"Crypto 一血","category":"crypto","points":300,"is_solved":true}
		]}}`)
	})

	list, err := p.ListChallenges(context.Background())
	if err != nil {
		t.Fatalf("ListChallenges 失败: %v", err)
	}
	wantPath := ctf2AgentBase + "/competitions/comp-1/stages/stage-1/challenges/"
	if gotPath != wantPath {
		t.Fatalf("路径不符（比赛模式前缀错了就全盘 404）\n got=%q\nwant=%q", gotPath, wantPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("鉴权头必须为 %q，得到 %q（CTF² 不是 X-Agent-AccessKey）", "Bearer test-token", gotAuth)
	}
	if !strings.Contains(gotUA, "Mozilla") {
		t.Fatalf("UA 应伪装为浏览器，得到 %q", gotUA)
	}
	if len(list) != 2 {
		t.Fatalf("应解析出 2 题，得到 %d", len(list))
	}
	c1 := list[0]
	if c1.ID != "c1" || c1.Title != "Web 签到" || c1.Category != "web" || c1.Score != 100 {
		t.Fatalf("字段映射错误: %+v", c1)
	}
	if !c1.HasInstance || !c1.HasAttachment || c1.Difficulty != "EASY" {
		t.Fatalf("has_container/has_attachments/difficulty 映射错误: %+v", c1)
	}
	// Extra 里的旁路字段是解题编排（是否已解/提交类型）的依据，不能丢
	if got, _ := c1.Extra["submission_type"].(string); got != "flag" {
		t.Fatalf("Extra[submission_type] 应为 flag，得到 %v", c1.Extra["submission_type"])
	}
	if got, _ := c1.Extra["is_solved"].(bool); got {
		t.Fatal("Extra[is_solved] 应为 false")
	}
	if !p.LastListOK() {
		t.Fatal("成功拉取后 LastListOK() 必须为 true")
	}
}

// TestCTF2GetChallengeDetail 详情解析（题干/个人附件状态/提交类型）。
func TestCTF2GetChallengeDetail(t *testing.T) {
	var gotPath string
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"data":{"id":"c1","name":"Web 签到","category":"web",
			"difficulty":"EASY","description":"flag 格式：DASCTF{xxx}，附件见 files",
			"points":100,"has_attachments":true,"has_container":true,
			"submission_type":"flag","personal_files_status":"ready",
			"files":[{"file_id":"f1","file_name":"a.zip","kind":"assigned"}]}}`)
	})

	ch, err := p.GetChallenge(context.Background(), "c1")
	if err != nil {
		t.Fatalf("GetChallenge 失败: %v", err)
	}
	if want := ctf2AgentBase + "/competitions/comp-1/stages/stage-1/challenges/c1/"; gotPath != want {
		t.Fatalf("详情路径不符\n got=%q\nwant=%q", gotPath, want)
	}
	if ch.ID != "c1" || !strings.Contains(ch.Description, "DASCTF{") {
		t.Fatalf("详情字段未解析: %+v", ch)
	}
	if got, _ := ch.Extra["personal_files_status"].(string); got != "ready" {
		t.Fatalf("personal_files_status 应透传到 Extra（决定要不要等附件生成），得到 %v", ch.Extra["personal_files_status"])
	}
}

// TestCTF2SubmitFlagConfirmation 提交必须带 confirmation=true，且响应字段解析正确。
// 这是**防误交的硬要求**：平台侧缺这个字段直接拒收，赛时等于白交。
func TestCTF2SubmitFlagConfirmation(t *testing.T) {
	var gotBody map[string]interface{}
	var gotPath, gotMethod string
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = io.WriteString(w, `{"data":{"accepted":true,"attempt":1,"attempts_left":9,
			"earned_points":100,"is_solved":true,"points":100,"submission_id":"sub-1"}}`)
	})

	res, err := p.SubmitFlag(context.Background(), "c1", "DASCTF{ok}")
	if err != nil {
		t.Fatalf("SubmitFlag 返回 error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("提交必须是 POST，得到 %s", gotMethod)
	}
	if want := ctf2AgentBase + "/competitions/comp-1/stages/stage-1/challenges/c1/submit/"; gotPath != want {
		t.Fatalf("提交路径不符\n got=%q\nwant=%q", gotPath, want)
	}
	if v, ok := gotBody["confirmation"].(bool); !ok || !v {
		t.Fatalf("请求体必须含 confirmation=true（防误交），实际 %v", gotBody)
	}
	if gotBody["flag"] != "DASCTF{ok}" {
		t.Fatalf("请求体 flag 不符: %v", gotBody["flag"])
	}
	if res == nil || !res.Accepted || !res.Correct {
		t.Fatalf("accepted=true 应映射为 Accepted/Correct=true，得到 %+v", res)
	}
	if res.RemainingAttempts != 9 {
		t.Fatalf("attempts_left 应映射到 RemainingAttempts，得到 %d", res.RemainingAttempts)
	}
	if got, _ := res.Extra["is_solved"].(bool); !got {
		t.Fatalf("is_solved 应透传到 Extra，得到 %v", res.Extra["is_solved"])
	}
}

// TestCTF2SubmitFlagRequestFailureIsNotWrongFlag 请求层失败必须 RequestFailed=true，
// 且**不能**被读成"flag 错了"——否则会把对的 flag 判错、白丢分。
func TestCTF2SubmitFlagRequestFailure(t *testing.T) {
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	p.SetAntiBlock(AntiBlockOptions{Enabled: false}) // 关治理=不重试，用例才快

	res, err := p.SubmitFlag(context.Background(), "c1", "DASCTF{ok}")
	if err != nil {
		t.Fatalf("SubmitFlag 不应把请求失败升级为 error（调用方按 RequestFailed 分支）: %v", err)
	}
	if res == nil || !res.RequestFailed {
		t.Fatalf("5xx 必须 RequestFailed=true，得到 %+v", res)
	}
	if res.Correct {
		t.Fatal("请求失败时不得声称 Correct（会把对的 flag 当错的丢掉）")
	}
}

// TestCTF2ParseHostPort 靶机地址解析（赛时开环境后拿到的地址形态很多）。
func TestCTF2ParseHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"http://1.2.3.4:8080/path", "1.2.3.4", 8080, false},
		{"1.2.3.4:8080", "1.2.3.4", 8080, false},
		{"https://h.example.com", "h.example.com", 0, false},
		{"  http://user:pass@10.0.0.1:22/x  ", "10.0.0.1", 22, false},
		{"http://[::1]:9000/", "[::1]", 9000, false},
		{"", "", 0, true},
	}
	for _, c := range cases {
		host, port, err := parseHostPort(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseHostPort(%q) err=%v，期望 err=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("parseHostPort(%q) = (%q,%d)，期望 (%q,%d)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

// TestCTF2ExtractFlagFormat 题干里的 flag 格式提取（决定提交前要不要套壳）。
func TestCTF2ExtractFlagFormat(t *testing.T) {
	cases := []struct{ in, wantSub string }{
		{"flag 格式：DASCTF{xxx}", "DASCTF{"},
		{"请提交 flag{...} 形式的答案", "flag{"},
		{"格式：N1CTF{abc}", "N1CTF{"},
		{"没有提到格式", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := extractFlagFormat(c.in)
		if c.wantSub == "" {
			if got != "" {
				t.Errorf("extractFlagFormat(%q) = %q，期望空", c.in, got)
			}
			continue
		}
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("extractFlagFormat(%q) = %q，期望含 %q", c.in, got, c.wantSub)
		}
	}
}

// TestCTF2Retry429ThenSuccess 429 → 重试 → 成功，且连续计数归零。
func TestCTF2Retry429ThenSuccess(t *testing.T) {
	var hits int32
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"rate limited"}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"items":[]}}`)
	})
	p.MaxRetries = 2
	p.RetryBackoff = time.Millisecond

	if _, err := p.ListChallenges(context.Background()); err != nil {
		t.Fatalf("429 后重试应成功，得到 error: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("应请求 2 次（1 次 429 + 1 次成功），实际 %d", got)
	}
	if p.Consec429() != 0 {
		t.Fatalf("成功后连续 429 计数必须归零，得到 %d", p.Consec429())
	}
	if !p.LastListOK() {
		t.Fatal("成功后 LastListOK 应为 true")
	}
}

// TestCTF2WAF403CooldownShortCircuits 403 → 进入冷却 → 后续请求直接短路（不再打平台）。
// 赛时被 WAF 盯上还硬打，等于把 IP 彻底封死。
func TestCTF2WAF403CooldownShortCircuits(t *testing.T) {
	var hits int32
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "blocked", http.StatusForbidden)
	})
	p.WAFTimeout = time.Minute

	if _, err := p.ListChallenges(context.Background()); err == nil {
		t.Fatal("403 必须返回 error")
	}
	if secs := p.WafBlockedSeconds(); secs <= 0 {
		t.Fatalf("403 后应进入 WAF 冷却，WafBlockedSeconds()=%v", secs)
	}
	// 冷却期内的第二次请求：必须在本地短路，不再产生真实请求
	if _, err := p.ListChallenges(context.Background()); err == nil {
		t.Fatal("冷却期内请求必须失败")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("冷却期不得再打平台（实际请求 %d 次，期望 1）", got)
	}
}

// TestCTF2ListCache 列表 TTL 缓存：TTL 内第二次不产生请求。
func TestCTF2ListCache(t *testing.T) {
	var hits int32
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"data":{"items":[{"id":"c1","name":"n"}]}}`)
	})
	ttl := 10 * time.Second
	p.listCacheTTL = ttl

	for i := 0; i < 2; i++ {
		if _, err := p.ListChallenges(context.Background()); err != nil {
			t.Fatalf("第 %d 次 ListChallenges 失败: %v", i+1, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("TTL 内应只请求 1 次（缓存未生效，实际 %d 次）", got)
	}
	// 关掉缓存后必须重新请求
	p.listCacheTTL = 0
	if _, err := p.ListChallenges(context.Background()); err != nil {
		t.Fatalf("关缓存后 ListChallenges 失败: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("关缓存后应重新请求（实际 %d 次，期望 2）", got)
	}
}

// TestCTF2EmptyBaseURLFails 未配置地址时必须给出可操作错误，而不是拼出 "?limit=100" 去撞。
func TestCTF2EmptyBaseURLFails(t *testing.T) {
	p := &CTF2Platform{Logger: zap.NewNop(), HTTPClient: &http.Client{Timeout: time.Second}}
	p.CompetitionID = "comp-1"
	p.StageID = "stage-1"
	_, _, err := p.doRequest(context.Background(), http.MethodGet, "/x", nil)
	if err == nil {
		t.Fatal("BaseURL 为空必须报错")
	}
	if !strings.Contains(err.Error(), envCTF2BaseURL) {
		t.Fatalf("错误信息应提示配置 %s，得到 %v", envCTF2BaseURL, err)
	}
}

// TestCTF2AntiBlockRollbackClearsState 一键回退必须把残留计数/冷却清零（半开状态最难查）。
func TestCTF2AntiBlockRollbackClearsState(t *testing.T) {
	p, _ := newCTF2Test(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	})
	p.WAFTimeout = time.Minute
	if _, err := p.ListChallenges(context.Background()); err == nil {
		t.Fatal("403 必须返回 error")
	}
	if p.WafBlockedSeconds() <= 0 {
		t.Fatal("前置条件：应已进入 WAF 冷却")
	}

	p.SetAntiBlock(AntiBlockOptions{Enabled: false})
	if secs := p.WafBlockedSeconds(); secs != 0 {
		t.Fatalf("回退后 WAF 冷却必须清零，得到 %v 秒", secs)
	}
	if p.Consec429() != 0 {
		t.Fatalf("回退后连续 429 计数必须清零，得到 %d", p.Consec429())
	}
}
