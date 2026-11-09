package ctfplatform

// 时间窗驱动回归（2026-11-10 第二轮）。
// fixture 直接用第一轮真机探针实值（docs/evidence/match_info双平台字段实探_时间窗第一轮_20261110.md），
// 不凭记忆编字段——那正是本功能第一轮要防的错误。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ── MatchWindowInfo.IsEnded：fail-safe 判停口径 ─────────────────────────────
func TestMatchWindowIsEndedFailSafe(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"ended", true},
		{"ENDED", true}, // 大小写宽容（值本身已实见）
		{" ended ", true},
		{"running", false},
		{"", false},          // 取不到 → 不误停
		{"paused_for_judge", false}, // 未知字面量 → 不误停（宁多跑）
	}
	for _, c := range cases {
		if got := (MatchWindowInfo{Status: c.status}).IsEnded(); got != c.want {
			t.Errorf("IsEnded(%q)=%v，期望 %v", c.status, got, c.want)
		}
	}
}

// ── deriveFirstBloodUntil：推导数学 ─────────────────────────────────────────
func TestDeriveFirstBloodUntil(t *testing.T) {
	start := time.Date(2026, 11, 10, 19, 0, 0, 0, time.FixedZone("CST", 8*3600))

	// 60 分钟赛程 → 窗口 = min(15, 12) = 12 分钟
	w := MatchWindowInfo{Start: start, HasStart: true, End: start.Add(60 * time.Minute), HasEnd: true}
	if until, ok := deriveFirstBloodUntil(w); !ok || !until.Equal(start.Add(12*time.Minute)) {
		t.Fatalf("60min 赛程应推到 start+12min，实际 %v ok=%v", until, ok)
	}
	// 2 小时赛程 → 15 分钟封顶
	w2 := MatchWindowInfo{Start: start, HasStart: true, End: start.Add(2 * time.Hour), HasEnd: true}
	if until, ok := deriveFirstBloodUntil(w2); !ok || !until.Equal(start.Add(15*time.Minute)) {
		t.Fatalf("2h 赛程应 15min 封顶，实际 %v ok=%v", until, ok)
	}
	// 无 end → 15 分钟
	w3 := MatchWindowInfo{Start: start, HasStart: true}
	if until, ok := deriveFirstBloodUntil(w3); !ok || !until.Equal(start.Add(15*time.Minute)) {
		t.Fatalf("缺 end 应按 15min，实际 %v ok=%v", until, ok)
	}
	// 无 start → inert
	if _, ok := deriveFirstBloodUntil(MatchWindowInfo{}); ok {
		t.Fatal("无 start_time 必须 inert（保持人工配置）")
	}
}

func TestPollWaitDerived(t *testing.T) {
	cfg := DefaultPollerConfig() // PollInterval=30s
	if got := pollWaitDerived(cfg, true); got != cfg.PollInterval {
		t.Fatalf("未配 interval 时不得启用短间隔，实际 %v", got)
	}
	cfg.FirstBloodInterval = 5 * time.Second
	if got := pollWaitDerived(cfg, true); got != 5*time.Second {
		t.Fatalf("首血内应用短间隔，实际 %v", got)
	}
	if got := pollWaitDerived(cfg, false); got != cfg.PollInterval {
		t.Fatalf("首血后应回落轮询间隔，实际 %v", got)
	}
	cfg.FirstBloodInterval = 40 * time.Second // 倒挂：>= PollInterval
	if got := pollWaitDerived(cfg, true); got != cfg.PollInterval {
		t.Fatalf("interval 倒挂不得用短间隔，实际 %v", got)
	}
}

// ── CTF2Platform.MatchWindow：真机 fixture 适配器测试 ───────────────────────
const probeFixture = `{
  "description": "1024 程序员节快闪赛：60 分钟、19 道题、1024 分。",
  "end_time": "2026-10-24T20:00:00+08:00",
  "entry": {"board_state": "published", "entered": true},
  "id": "e3c53c8c-2e44-4aee-8263-6495b334f606",
  "is_paused": false,
  "is_public": true,
  "max_agents_per_owner": 5,
  "name": "1024 程序员节快闪赛（AI Agent 赛道）",
  "requires_invite_code": false,
  "stages": [{"audience": "agent", "end_time": "2026-10-24T20:00:00+08:00", "max_targets": 4,
              "name": "AI Agent 赛道", "start_time": "2026-10-24T19:00:00+08:00", "status": "ended"}],
  "start_time": "2026-10-24T19:00:00+08:00",
  "status": "ended"
}`

func newProbePlatform(t *testing.T, body string) (*CTF2Platform, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/open/v1/user/agent/competitions/1/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": json.RawMessage(body)})
	}))
	t.Cleanup(ts.Close)
	p := NewCTF2Platform(ts.URL, "probe-token", zap.NewNop())
	p.CompetitionID = "1"
	return p, ts
}

func TestCTF2MatchWindowParsesRealFixture(t *testing.T) {
	p, _ := newProbePlatform(t, probeFixture)
	w, err := p.MatchWindow(context.Background())
	if err != nil {
		t.Fatalf("MatchWindow 解析真机 fixture 失败：%v", err)
	}
	if !w.HasStart || !w.HasEnd {
		t.Fatalf("start/end 应解析成功，实际 %+v", w)
	}
	wantStart := time.Date(2026, 10, 24, 19, 0, 0, 0, time.FixedZone("CST", 8*3600))
	if !w.Start.Equal(wantStart) {
		t.Fatalf("start_time 应按 RFC3339+08:00 解析，实际 %v", w.Start)
	}
	if !w.IsEnded() {
		t.Fatalf("fixture status=ended，IsEnded 必须为 true，实际 status=%q", w.Status)
	}
	// 推导链路：60 分钟赛程 → 首血截止 = 19:12
	until, ok := deriveFirstBloodUntil(w)
	wantUntil := time.Date(2026, 10, 24, 19, 12, 0, 0, until.Location())
	if !ok || !until.Equal(wantUntil) {
		t.Fatalf("推导应得 19:12(+08)，实际 %v ok=%v", until, ok)
	}
}

// ── RunForever 集成：status=ended 判停 / 非 provider inert ──────────────────

// windowFakePlatform 嵌入既有替身（第八条：新增接口方法缺失会立刻在此暴露）
type windowFakePlatform struct {
	*fakePlatform
	window MatchWindowInfo
	err    error
	calls  int
}

func (w *windowFakePlatform) MatchWindow(ctx context.Context) (MatchWindowInfo, error) {
	w.calls++
	return w.window, w.err
}

func TestRunForeverStopsOnPlatformEnded(t *testing.T) {
	fp := &windowFakePlatform{
		fakePlatform: &fakePlatform{}, // 空题目列表：每轮秒过
		window:       MatchWindowInfo{Status: "ended"},
	}
	cfg := DefaultPollerConfig()
	cfg.StopOnPlatformEnd = true
	p := NewPoller(fp, func(ctx context.Context, ch *Challenge) ([]string, error) { return nil, nil }, cfg, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := p.RunForever(ctx); err != nil {
		t.Fatalf("status=ended 应返回 nil 停轮，实际 err=%v", err)
	}
	if fp.calls == 0 {
		t.Fatal("StopOnPlatformEnd 开启且平台支持时必须真的查过 status")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("判停过慢（疑似没走判停路径）：%v", time.Since(start))
	}
}

func TestRunForeverUnknownStatusKeepsRunning(t *testing.T) {
	fp := &windowFakePlatform{
		fakePlatform: &fakePlatform{},
		window:       MatchWindowInfo{Status: "some_unexpected_value"}, // 未知值
	}
	cfg := DefaultPollerConfig()
	cfg.PollInterval = 20 * time.Millisecond
	cfg.StopOnPlatformEnd = true
	p := NewPoller(fp, func(ctx context.Context, ch *Challenge) ([]string, error) { return nil, nil }, cfg, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = p.RunForever(ctx)
	if fp.calls < 2 {
		t.Fatalf("未知 status 必须继续轮询（宁多跑不误停），实际只查了 %d 次", fp.calls)
	}
}

func TestRunForeverInertOnNonProviderPlatform(t *testing.T) {
	// DASCTF 形态：平台未实现 MatchWindowProvider → 特性 inert，不得 panic/不得改变行为
	fp := &fakePlatform{}
	cfg := DefaultPollerConfig()
	cfg.StopOnPlatformEnd = true
	cfg.DeriveWindowFromMatchInfo = true
	p := NewPoller(fp, func(ctx context.Context, ch *Challenge) ([]string, error) { return nil, nil }, cfg, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := p.RunForever(ctx); err != context.DeadlineExceeded {
		t.Fatalf("非 provider 应照常运行到 ctx 超时，实际 err=%v", err)
	}
}
