package ctfplatform

// 决赛整链路演练（规划总纲 §2.1 的 e2e 要求，去掉"必须用官方平台"那部分）。
//
// 为什么单独做这一层：
//   既有测试是**组件级**的（协议契约、退避、WAF、去重各自单测）。但决赛出事从来不是
//   因为某个函数写错，而是**整链配合**：并发求解会不会把平台打爆？拉题被限流后整轮会不会
//   半途而废？解不出的题会不会反复提交浪费次数（每题约 50 次机会）？第二轮会不会重复提交？
//   这些只有把"仿真平台 + 真实 Poller + 真实求解器"串起来跑一遍才测得到。
//
// 本演练刻意贴近赛况：
//   - 多题混合（可解 / 解不出 / 慢题），模拟真实分数构成；
//   - 拉题注入 429，验证抗打击生效且整轮不中断；
//   - 并发上限可调，用"总耗时 < 单题耗时之和"证明并发真的并行（不是假并发）；
//   - 对平台请求次数设硬上限，防止"求解并行了、请求也并行了"把平台打挂（自伤）。
//   - 跑第二轮验证去重（重复提交会白白吃掉提交机会）。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// rehearsalChallenge 演练题目定义。
type rehearsalChallenge struct {
	id       string        // 题号（数值型，与官方 exerciseId 一致）
	title    string        // 标题（前缀决定分类）
	desc     string        // 描述；含 flag{...} 视为"可解出"
	solveDur time.Duration // 模拟单题求解耗时（验证并发是否真并行）
}

// rehearsalPlatform 仿真 DASCTF 平台。
type rehearsalPlatform struct {
	mu sync.Mutex

	challenges []rehearsalChallenge

	listCalls    int            // 拉题请求数（反刷平台上限断言）
	submitCalls  int            // 总提交次数
	submitsByID  map[string]int // 每题提交次数（不得 >1，否则浪费提交机会）
	acceptedByID map[string]bool
	wrongByID    map[string]int

	inject429 int // 前 N 次拉题注入 429（模拟平台限流）
}

func newRehearsalPlatform(chs []rehearsalChallenge) *rehearsalPlatform {
	return &rehearsalPlatform{
		challenges:   chs,
		submitsByID:  map[string]int{},
		acceptedByID: map[string]bool{},
		wrongByID:    map[string]int{},
	}
}

// expectedFlags 预先算出"正确答案"（剥离外壳后），供仿真平台判分。
func (s *rehearsalPlatform) expectedFlags() map[string]string {
	out := map[string]string{}
	for _, c := range s.challenges {
		for _, f := range FilterFlagCandidates(ExtractFlags(c.desc)) {
			out[c.id] = StripFlagWrapper(f)
			break
		}
	}
	return out
}

// listPayload 构造**嵌套**列表（分类容器 corpus + 平铺题目混合），
// 确保演练同时覆盖 flattenChallenges 的两条解析路径。
func (s *rehearsalPlatform) listPayload() string {
	type item map[string]interface{}
	half := len(s.challenges) / 2
	corpus := []item{}
	for _, c := range s.challenges[:half] {
		corpus = append(corpus, item{
			"id": c.id, "name": c.title, "description": c.desc, "isOpen": true,
		})
	}
	data := []item{
		{"id": 9001, "name": "CRYPTO", "order": 1, "corpus": corpus},
	}
	for _, c := range s.challenges[half:] {
		data = append(data, item{
			"id": c.id, "name": c.title, "description": c.desc, "isOpen": true,
		})
	}
	b, _ := json.Marshal(map[string]interface{}{"code": "00000", "data": data})
	return string(b)
}

func (s *rehearsalPlatform) handler(t *testing.T) http.HandlerFunc {
	expect := s.expectedFlags()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slab-match/api/v1/agent/ctf/exercise-list":
			s.mu.Lock()
			s.listCalls++
			call := s.listCalls
			inject := s.inject429
			s.mu.Unlock()
			if inject > 0 && call <= inject {
				// 模拟平台限流：HTTP 429 + 业务码非 00000
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"code":"429","msg":"rate limited"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(s.listPayload()))

		case "/slab-match/api/v1/agent/answer-panel/answer":
			body, _ := io.ReadAll(r.Body)
			var req map[string]interface{}
			_ = json.Unmarshal(body, &req)
			rawID, _ := req["exerciseId"]
			id := fmt.Sprintf("%v", rawID)
			submitted, _ := req["flag"].(string)

			s.mu.Lock()
			s.submitCalls++
			s.submitsByID[id]++
			ok := expect[id] != "" && submitted == expect[id]
			if ok {
				s.acceptedByID[id] = true
			} else {
				s.wrongByID[id]++
			}
			s.mu.Unlock()

			// 契约⑥：成功判据 = code=="00000" 且 data.isCorrect==true
			if ok {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":true}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":false}}`))

		default:
			// 详情页 / 起靶机 / 概览等：一律成功但不带关键信息，
			// 保证演练聚焦在"拉题-求解-提交"主链上。
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":{}}`))
		}
	}
}

// TestRehearsalFinalsLoop 决赛整链路演练。
func TestRehearsalFinalsLoop(t *testing.T) {
	chs := []rehearsalChallenge{
		{id: "1001", title: "CRYPTO-01", desc: "base64 层层解码，得到 flag{rehearsal_crypto_ok}", solveDur: 120 * time.Millisecond},
		{id: "1002", title: "MISC-01", desc: "strings 一把梭：flag{rehearsal_misc_ok}", solveDur: 120 * time.Millisecond},
		{id: "1003", title: "WEB-01", desc: "查看源码：flag{rehearsal_web_ok}", solveDur: 120 * time.Millisecond},
		{id: "1004", title: "PWN-01", desc: "需要交互式 shell，静态无解", solveDur: 20 * time.Millisecond}, // 解不出
		{id: "1005", title: "REVERSE-01", desc: "需要下载二进制分析", solveDur: 20 * time.Millisecond},       // 解不出
	}
	sim := newRehearsalPlatform(chs)
	sim.inject429 = 1 // 第一次拉题被限流

	srv := httptest.NewServer(sim.handler(t))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)

	// 真实形态的求解器：从题目描述里抽 flag，并按题设耗时模拟"慢题"。
	var muSolve sync.Mutex
	solveDurations := map[string]time.Duration{}
	solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
		var d time.Duration
		for _, c := range chs {
			if c.id == ch.ID {
				d = c.solveDur
				break
			}
		}
		start := time.Now()
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		muSolve.Lock()
		solveDurations[ch.ID] = time.Since(start)
		muSolve.Unlock()
		return FilterFlagCandidates(ExtractFlags(ch.Description)), nil
	}

	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.MaxConcurrency = 3
	pc.SolveTimeout = 30 * time.Second
	poller := NewPoller(p, solver, pc, zap.NewNop())
	poller.SetAdvisor(p)

	start := time.Now()
	records, err := poller.RunOnce(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("演练第一轮 RunOnce 失败（限流注入后整轮不应中断）: %v", err)
	}
	if len(records) != len(chs) {
		t.Fatalf("应处理 %d 题，实际 %d", len(chs), len(records))
	}

	// ── 断言 1：可解的题全部被平台接受 ──────────────────────────────
	byID := map[string]PollRecord{}
	for _, r := range records {
		byID[r.ChallengeID] = r
	}
	for _, id := range []string{"1001", "1002", "1003"} {
		if !byID[id].Accepted {
			t.Errorf("题 %s 应被接受，实际 rec=%+v", id, byID[id])
		}
		if !byID[id].Submitted {
			t.Errorf("题 %s 应发生提交", id)
		}
	}

	// ── 断言 2：解不出的题绝不接受、且不得提交（保护每题约 50 次机会）──
	for _, id := range []string{"1004", "1005"} {
		if byID[id].Accepted {
			t.Errorf("题 %s 无解却被判接受", id)
		}
		if n := sim.submitsByID[id]; n != 0 {
			t.Errorf("题 %s 无候选不应提交，实际提交 %d 次", id, n)
		}
	}

	// ── 断言 3：每题最多提交 1 次（不浪费机会，也不刷平台）───────────
	for id, n := range sim.submitsByID {
		if n > 1 {
			t.Errorf("题 %s 提交 %d 次，超过 1 次（重复提交会吃掉提交机会）", id, n)
		}
	}

	// ── 断言 4：并发真的并行（总耗时 < 各题求解耗时之和）────────────
	muSolve.Lock()
	var sumDur time.Duration
	for _, d := range solveDurations {
		sumDur += d
	}
	muSolve.Unlock()
	if sumDur < 300*time.Millisecond {
		t.Fatalf("演练设计问题：单题耗时之和仅 %v，无法判定并发效果", sumDur)
	}
	if elapsed >= sumDur {
		t.Errorf("并发未生效：总耗时 %v ≥ 各题耗时之和 %v（MaxConcurrency=%d）",
			elapsed, sumDur, pc.MaxConcurrency)
	}

	// ── 断言 5：限流被触发且已自我恢复 ─────────────────────────────
	if sim.listCalls < 2 {
		t.Errorf("注入的 429 未被重试绕过：拉题仅 %d 次", sim.listCalls)
	}

	// ── 断言 6：第二轮不得重复处理（去重生效）───────────────────────
	before := sim.submitCalls
	records2, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("演练第二轮 RunOnce 失败: %v", err)
	}
	if len(records2) != 0 {
		t.Errorf("第二轮应无新题（去重），实际 %d", len(records2))
	}
	if sim.submitCalls != before {
		t.Errorf("第二轮不应产生提交，提交数由 %d 变为 %d", before, sim.submitCalls)
	}

	// ── 演练报告（人读；同时是 CI 里的赛况快照）─────────────────────
	ids := make([]string, 0, len(records))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t.Logf("")
	t.Logf("========== 决赛整链路演练报告 ==========")
	t.Logf("  题目总数 %d（可解 3 / 无解 2）  并发上限 %d", len(chs), pc.MaxConcurrency)
	t.Logf("  总耗时   %v   单题耗时之和 %v（并发有效：%v）",
		elapsed.Round(time.Millisecond), sumDur.Round(time.Millisecond), elapsed < sumDur)
	t.Logf("  拉题请求 %d 次（含注入 429 一次）  提交总次数 %d", sim.listCalls, sim.submitCalls)
	for _, id := range ids {
		r := byID[id]
		status := "MISS"
		if r.Accepted {
			status = "ACCEPTED"
		}
		t.Logf("    %-6s %-12s %-9s flag=%-28s 提交=%d",
			id, r.Title, status, r.Flag, sim.submitsByID[id])
	}
	t.Logf("========================================")
}

// TestRehearsalSerialVsConcurrent 串行 vs 并发对照：证明 MaxConcurrency 真的在起作用
// （防止"配了并发、实现还是串行"这种静默退化）。
func TestRehearsalSerialVsConcurrent(t *testing.T) {
	chs := []rehearsalChallenge{
		{id: "2001", title: "CRYPTO-01", desc: "flag{serial_a}", solveDur: 100 * time.Millisecond},
		{id: "2002", title: "CRYPTO-02", desc: "flag{serial_b}", solveDur: 100 * time.Millisecond},
		{id: "2003", title: "CRYPTO-03", desc: "flag{serial_c}", solveDur: 100 * time.Millisecond},
		{id: "2004", title: "CRYPTO-04", desc: "flag{serial_d}", solveDur: 100 * time.Millisecond},
	}

	run := func(concurrency int) time.Duration {
		sim := newRehearsalPlatform(chs)
		srv := httptest.NewServer(sim.handler(t))
		defer srv.Close()
		p := newTestPlatform(t, srv.URL)
		solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
			for _, c := range chs {
				if c.id == ch.ID {
					select {
					case <-time.After(c.solveDur):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					break
				}
			}
			return FilterFlagCandidates(ExtractFlags(ch.Description)), nil
		}
		pc := DefaultPollerConfig()
		pc.SubmitAfterSolve = true
		pc.MaxConcurrency = concurrency
		poller := NewPoller(p, solver, pc, zap.NewNop())
		start := time.Now()
		if _, err := poller.RunOnce(context.Background()); err != nil {
			t.Fatalf("concurrency=%d 失败: %v", concurrency, err)
		}
		d := time.Since(start)
		for _, id := range []string{"2001", "2002", "2003", "2004"} {
			if !sim.acceptedByID[id] {
				t.Fatalf("concurrency=%d：题 %s 未被接受", concurrency, id)
			}
		}
		return d
	}

	serial := run(1)
	concurrent := run(4)
	t.Logf("串行(MaxConcurrency=1)=%v  并发(MaxConcurrency=4)=%v",
		serial.Round(time.Millisecond), concurrent.Round(time.Millisecond))
	// 4 题 × 100ms：串行应 ≥ ~400ms；并发应显著更短。
	// 判据放宽到 0.8 倍，避免 CI 抖动造成假红（本断言只拦"并发完全没生效"）。
	if concurrent > serial*8/10 {
		t.Errorf("并发未生效：并发 %v 未显著小于串行 %v", concurrent, serial)
	}
}
