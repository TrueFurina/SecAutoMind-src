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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	hasInst  bool          // 是否需要靶机（演练 AutoBuildEnv 链路）
	// expectInner 显式指定判分答案（剥离外壳后的内容）。
	// 需要靶机的题 flag 在靶机上、描述里没有 → 必须显式给，否则仿真平台判分表为空。
	expectInner string
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
	buildCalls   int            // build-exercise-env（起靶机）调用数
	detailCalls  int            // challenge_detail（取靶机地址）调用数

	inject429       int    // 前 N 次拉题注入 429（模拟平台限流）
	injectSubmit429 int    // 前 N 次提交注入 429（模拟提交限流，验证客户端内部重试）
	webTargetURL    string // 模拟靶机地址（http://127.0.0.1:PORT）；非空时 detail 返回它
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
		if c.expectInner != "" {
			out[c.id] = c.expectInner
			continue
		}
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
		it := item{
			"id": c.id, "name": c.title, "description": c.desc, "isOpen": true,
		}
		if c.hasInst {
			it["has_instance"] = true
		}
		corpus = append(corpus, it)
	}
	data := []item{
		{"id": 9001, "name": "CRYPTO", "order": 1, "corpus": corpus},
	}
	for _, c := range s.challenges[half:] {
		it := item{
			"id": c.id, "name": c.title, "description": c.desc, "isOpen": true,
		}
		if c.hasInst {
			it["has_instance"] = true
		}
		data = append(data, it)
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
			if s.injectSubmit429 > 0 {
				// 模拟提交限流：客户端应内部重试（抗打击⑤⑦），最终仍能交上
				s.injectSubmit429--
				s.mu.Unlock()
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"code":"429","msg":"rate limited"}`))
				return
			}
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

		case "/slab-match/api/v1/agent/ctf/build-exercise-env":
			s.mu.Lock()
			s.buildCalls++
			s.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":{"instance_id":"inst-rehearsal-1","status":"running"}}`))

		case "/slab-match/api/v1/agent/ctf/exercise":
			// 官方契约：靶机地址在 challenge_detail.endpoints[].exposeIps[0]（"ip:port"）
			s.mu.Lock()
			s.detailCalls++
			target := s.webTargetURL
			s.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			if target == "" {
				_, _ = w.Write([]byte(`{"code":"00000","data":{}}`))
				return
			}
			hostport := strings.TrimPrefix(target, "http://")
			b, _ := json.Marshal(map[string]interface{}{
				"code": "00000",
				"data": map[string]interface{}{
					"endpoints": []map[string]interface{}{
						{"name": "web", "exposeIps": []string{hostport}, "ports": []string{"tcp/80"}},
					},
				},
			})
			_, _ = w.Write(b)

		default:
			// 概览 / 公告等：一律成功但不带关键信息，
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

// TestRehearsalInstanceChain 起靶机整链演练（09-17 补的生产缺口）。
//
// 背景：CreateInstance/GetAccess 此前**从未被生产代码调用**——需要靶机的题
//（真实决赛里的 web/pwn 主力）会因"没有可打的地址"整题 0 分，而所有组件级单测都是绿的。
// 本演练验证完整链条：起靶机 → 取地址（exposeIps）→ 地址并入描述 → 打靶 → flag 提交 → accepted。
// 并含反向对照：关掉 AutoBuildEnv 后同一道题必须拿不到 flag（证明断言不是恒真）。
func TestRehearsalInstanceChain(t *testing.T) {
	// 独立"靶机"：flag 只存在于靶机上，描述里没有 —— 模拟真实赛况
	webTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html>欢迎来到靶机</html><!-- flag{instance_chain_ok} -->`))
	}))
	defer webTarget.Close()

	chs := []rehearsalChallenge{
		{id: "3001", title: "WEB-01", desc: "启动靶机后访问目标读取 flag", hasInst: true, expectInner: "instance_chain_ok"},
		{id: "3002", title: "MISC-01", desc: "明文：flag{plain_ok}"},
	}
	sim := newRehearsalPlatform(chs)
	sim.webTargetURL = webTarget.URL

	srv := httptest.NewServer(sim.handler(t))
	defer srv.Close()
	p := newTestPlatform(t, srv.URL)

	// 贴近真实求解器形态：描述直接抽 flag + 描述里出现的 URL 自动渗透
	//（= presolve 的真实路径，见 presolve_registry.go 的 ExploitURLsInText 分支）。
	solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
		flags := ExtractFlags(ch.Description)
		flags = append(flags, ExploitURLsInText(ctx, ch.Description)...)
		return FilterFlagCandidates(flags), nil
	}

	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoBuildEnv = true
	pc.MaxConcurrency = 2
	poller := NewPoller(p, solver, pc, zap.NewNop())
	poller.SetAdvisor(p)

	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("起靶机整链演练失败: %v", err)
	}
	byID := map[string]PollRecord{}
	for _, r := range records {
		byID[r.ChallengeID] = r
	}

	if !byID["3001"].Accepted {
		t.Fatalf("需要靶机的题未被解决（起靶机链路断裂）rec=%+v", byID["3001"])
	}
	if byID["3001"].Flag != "flag{instance_chain_ok}" {
		t.Errorf("3001 的 flag 应来自靶机，实际 %q", byID["3001"].Flag)
	}
	if !byID["3002"].Accepted {
		t.Errorf("3002（明文 flag）应直接命中，rec=%+v", byID["3002"])
	}
	if sim.buildCalls != 1 {
		t.Errorf("build-env 应恰好调用 1 次（重复起环境浪费时间），实际 %d", sim.buildCalls)
	}
	if sim.detailCalls < 1 {
		t.Errorf("challenge_detail（取靶机地址）应至少调用 1 次，实际 %d", sim.detailCalls)
	}

	// ── 反向对照：AutoBuildEnv=false → 靶机链不启动 → 3001 必须拿不到 flag ──
	// （若这条失败，说明上面的"成功"与开关无关，断言形同虚设）
	sim2 := newRehearsalPlatform(chs)
	sim2.webTargetURL = webTarget.URL
	srv2 := httptest.NewServer(sim2.handler(t))
	defer srv2.Close()
	p2 := newTestPlatform(t, srv2.URL)
	pc2 := DefaultPollerConfig()
	pc2.SubmitAfterSolve = true // AutoBuildEnv 保持 false
	poller2 := NewPoller(p2, solver, pc2, zap.NewNop())
	if _, err := poller2.RunOnce(context.Background()); err != nil {
		t.Fatalf("对照组运行失败: %v", err)
	}
	if sim2.acceptedByID["3001"] {
		t.Errorf("对照失败：AutoBuildEnv=false 时 3001 不应被解出（靶机都没起）")
	}
	if !sim2.acceptedByID["3002"] {
		t.Errorf("对照组 3002（明文 flag）仍应命中")
	}
	if sim2.buildCalls != 0 {
		t.Errorf("对照组不应有任何起靶机调用，实际 %d", sim2.buildCalls)
	}
	t.Logf("起靶机整链演练：build-env×1 / detail×%d / 3001=%v 3002=%v；对照组 3001=%v",
		sim.detailCalls, sim.acceptedByID["3001"], sim.acceptedByID["3002"], sim2.acceptedByID["3001"])
}

// TestRehearsalAttachmentChain 附件链演练（09-18 补的生产缺口）。
//
// 背景：DownloadAttachment 是**存根**且生产代码零调用、app 层 Presolve 恒传 nil attachments
// → 附件题（取证/二进制/pcap，执行层 10/10 的那批求解器）在真实流程里**整个休眠**。
// 本演练用 PlatformAPI 测试替身（真实客户端的附件端点未确认）+ **真实 Presolver** 验证：
// 附件下载 → 落 chat_uploads 白名单 → [用户上传的文件] 标记块并入描述 →
// loadChatAttachmentFiles 读入 → 求解 → 提交 accepted。并含对照组。
func TestRehearsalAttachmentChain(t *testing.T) {
	// 附件内容放在 t.TempDir()（**不在** chat_uploads 白名单内），
	// 以便同时验证 poller 的"外部文件复制进白名单"兜底逻辑。
	attachment := filepath.Join(t.TempDir(), "flag_evidence.txt")
	if err := os.WriteFile(attachment,
		[]byte("=== 取证附件 ===\n敏感字符串: flag{attachment_chain_ok}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := &fakeRehearsalPlatform{
		attachmentPath: attachment,
		expectInner:    "attachment_chain_ok",
		ch: &Challenge{
			ID: "3001", Title: "MISC-ATTACH-01", Category: "misc",
			HasAttachment: true, Description: "分析附件文件得到 flag",
		},
	}

	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoFetchAttachment = true
	poller := NewPoller(fake, solverForAttachmentDrill(), pc, zap.NewNop())

	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("附件链演练失败: %v", err)
	}
	if len(records) != 1 || !records[0].Accepted {
		t.Fatalf("附件题未被解决（附件链断裂）records=%+v", records)
	}
	if records[0].Flag != "flag{attachment_chain_ok}" {
		t.Errorf("flag 应来自附件内容，实际 %q", records[0].Flag)
	}
	if fake.downloadCalls != 1 {
		t.Errorf("DownloadAttachment 应恰好调用 1 次，实际 %d", fake.downloadCalls)
	}
	// 注：不校验 fake.ch.Description —— Poller 求解用的是每题的**副本**（RunOnce 传值），
	// 替身里的原描述本来就不会变；标记块是否生效由"flag 来自附件内容"这条断言背书。
	// 附件应已复制进白名单目录（源文件在 t.TempDir()，白名单外）
	cwd, _ := os.Getwd()
	copied := filepath.Join(cwd, "chat_uploads", "ctf", "3001", "flag_evidence.txt")
	if _, err := os.Stat(copied); err != nil {
		t.Errorf("附件应已复制进 chat_uploads 白名单：%v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(cwd, "chat_uploads", "ctf")) })

	// ── 对照组：AutoFetchAttachment=false → 不下载、不解出、不提交 ──
	fake2 := &fakeRehearsalPlatform{
		attachmentPath: attachment,
		expectInner:    "attachment_chain_ok",
		ch: &Challenge{
			ID: "3001", Title: "MISC-ATTACH-01", Category: "misc",
			HasAttachment: true, Description: "分析附件文件得到 flag",
		},
	}
	pc2 := DefaultPollerConfig()
	pc2.SubmitAfterSolve = true // AutoFetchAttachment 保持 false
	poller2 := NewPoller(fake2, solverForAttachmentDrill(), pc2, zap.NewNop())
	if _, err := poller2.RunOnce(context.Background()); err != nil {
		t.Fatalf("对照组运行失败: %v", err)
	}
	if fake2.downloadCalls != 0 {
		t.Errorf("对照组不应有任何附件下载，实际 %d", fake2.downloadCalls)
	}
	if fake2.submitCalls != 0 {
		t.Errorf("对照组不应有提交（描述里没有 flag，附件没下载），实际 %d", fake2.submitCalls)
	}
	t.Logf("附件链演练：download×1 / accepted=%v；对照组 download=%d submit=%d",
		fake.accepted, fake2.downloadCalls, fake2.submitCalls)
}

// solverForAttachmentDrill 返回**真实 presolve 形态**的求解器：
// 与 app.go 生产闭包同构（Presolve(ctx, ch, nil)），附件内容靠
// loadChatAttachmentFiles 从描述标记块读入 —— 证明零求解器改动的注入方式真的生效。
func solverForAttachmentDrill() SolverFunc {
	pres := NewPresolver(zap.NewNop())
	return func(ctx context.Context, ch *Challenge) ([]string, error) {
		res := pres.Presolve(ctx, ch, nil)
		if !res.Solved {
			return nil, nil
		}
		return FilterFlagCandidates(res.Flags), nil
	}
}

// fakeRehearsalPlatform 演练用的 PlatformAPI 测试替身（通用）。
// 只覆盖 Poller 在具体配置下会触碰的方法；其余方法不会被调用（其余开关默认关），
// 嵌入接口即可 —— 一旦 Poller 新增调用，缺失方法会以 nil panic 立刻暴露，不会静默跳过。
type fakeRehearsalPlatform struct {
	PlatformAPI

	mu             sync.Mutex
	ch             *Challenge
	attachmentPath string
	expectInner    string

	// 详情补全相关
	detailDesc          string
	detailHasInstance   bool
	detailHasAttachment bool
	detailErr           error

	downloadCalls int
	submitCalls   int
	submitGot     string
	accepted      bool
	detailCalls   int
	destroyCalls  int
	createCalls   int
}

func (f *fakeRehearsalPlatform) ListChallenges(ctx context.Context) ([]Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []Challenge{*f.ch}, nil
}

func (f *fakeRehearsalPlatform) DownloadAttachment(ctx context.Context, challengeID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downloadCalls++
	return []string{f.attachmentPath}, nil
}

// GetChallenge 返回详情（题干可能比列表更完整）。detailErr 用于演练"详情取不到"的回退。
func (f *fakeRehearsalPlatform) GetChallenge(ctx context.Context, challengeID string) (*Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detailCalls++
	if f.detailErr != nil {
		return nil, f.detailErr
	}
	return &Challenge{
		ID:            challengeID,
		Title:         f.ch.Title,
		Category:      f.ch.Category,
		Description:   f.detailDesc,
		HasInstance:   f.detailHasInstance,
		HasAttachment: f.detailHasAttachment,
	}, nil
}

func (f *fakeRehearsalPlatform) CreateInstance(ctx context.Context, challengeID string) (*Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	return &Instance{InstanceID: "inst-fake-1", Status: "running"}, nil
}

func (f *fakeRehearsalPlatform) GetAccess(ctx context.Context, instanceID string) (*Access, error) {
	return &Access{Host: "127.0.0.1", Port: 8080, URL: "http://127.0.0.1:8080"}, nil
}

func (f *fakeRehearsalPlatform) DestroyInstance(ctx context.Context, challengeID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyCalls++
	return nil
}

func (f *fakeRehearsalPlatform) SubmitFlag(ctx context.Context, challengeID string, flag string) (*SubmitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitCalls++
	f.submitGot = flag
	// 真实客户端在 SubmitFlag 内剥壳（契约：只交 {} 内内容），替身必须同口径
	ok := StripFlagWrapper(flag) == f.expectInner
	if ok {
		f.accepted = true
	}
	return &SubmitResult{Correct: ok, Detail: "rehearsal"}, nil
}

// TestRehearsalDetailEnrichment 详情补全演练（09-24 补的第三处生产缺口）。
//
// 背景：平台列表的 description 可能是**摘要**，完整题干在详情里；且 has_instance /
// has_attachment 标记可能只在详情给出 —— 生产代码此前从未调 GetChallenge，
// 等于一直拿"半份题干"在解题。
// 本演练：列表给摘要、详情给全文（含 flag）→ 开启 AutoFetchDetail 后必须解出；
// 对照组关闭后必须解不出、且不该产生详情请求。
func TestRehearsalDetailEnrichment(t *testing.T) {
	newFake := func() *fakeRehearsalPlatform {
		return &fakeRehearsalPlatform{
			expectInner: "detail_enrich_ok",
			ch: &Challenge{
				ID: "4001", Title: "CRYPTO-01", Category: "crypto",
				Description: "题干摘要：多层编码（完整题干见详情）",
			},
			detailDesc: "完整题干：以下密文经 base64→hex 多层编码，flag{detail_enrich_ok}",
		}
	}

	// 实验组
	fake := newFake()
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoFetchDetail = true
	poller := NewPoller(fake, solverForAttachmentDrill(), pc, zap.NewNop())
	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("详情补全演练失败: %v", err)
	}
	if len(records) != 1 || !records[0].Accepted {
		t.Fatalf("开启详情补全后应解出（详情链断裂）records=%+v", records)
	}
	if records[0].Flag != "flag{detail_enrich_ok}" {
		t.Errorf("flag 应来自完整题干，实际 %q", records[0].Flag)
	}
	if fake.detailCalls != 1 {
		t.Errorf("GetChallenge 应恰好调用 1 次，实际 %d", fake.detailCalls)
	}

	// 对照组：关闭 → 只有摘要，解不出；且不应产生详情请求
	fake2 := newFake()
	pc2 := DefaultPollerConfig()
	pc2.SubmitAfterSolve = true // AutoFetchDetail 保持 false
	poller2 := NewPoller(fake2, solverForAttachmentDrill(), pc2, zap.NewNop())
	if _, err := poller2.RunOnce(context.Background()); err != nil {
		t.Fatalf("对照组运行失败: %v", err)
	}
	if fake2.detailCalls != 0 {
		t.Errorf("对照组不应有任何详情请求，实际 %d", fake2.detailCalls)
	}
	if fake2.submitCalls != 0 {
		t.Errorf("对照组只有摘要、不应提交，实际 %d", fake2.submitCalls)
	}
	t.Logf("详情补全演练：detail×1 accepted=true；对照组 detail=%d submit=%d",
		fake2.detailCalls, fake2.submitCalls)
}

// TestRehearsalEnvRelease 靶机回收演练（09-24 补的资源缺口）。
//
// 背景：CreateInstance 在 09-17 才被接进生产；但 DestroyInstance **始终无人调用** ——
// 起完不销毁会一直占平台配额，赛时可能"想开新环境却开不出来"。
// 本演练：解出并 accepted → 必须销毁一次；对照组（开关关 / 未解出）不得销毁。
func TestRehearsalEnvRelease(t *testing.T) {
	newFake := func(detailDesc string) *fakeRehearsalPlatform {
		return &fakeRehearsalPlatform{
			expectInner: "env_release_ok",
			ch: &Challenge{
				ID: "4101", Title: "WEB-01", Category: "web",
				Description: "访问靶机读取 flag", HasInstance: true,
			},
			detailDesc: detailDesc,
		}
	}

	// 实验组：起靶机 + 回收，题干含 flag → accepted → 应销毁 1 次
	// 注：flag 放在**列表描述**里（本用例验的是回收语义，与详情补全无关，故不开 AutoFetchDetail）
	fake := newFake("访问靶机读取 flag：flag{env_release_ok}")
	fake.ch.Description = "访问靶机读取 flag：flag{env_release_ok}"
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoBuildEnv = true
	pc.AutoReleaseEnv = true
	poller := NewPoller(fake, solverForAttachmentDrill(), pc, zap.NewNop())
	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("靶机回收演练失败: %v", err)
	}
	if len(records) != 1 || !records[0].Accepted {
		t.Fatalf("应解出并 accepted，records=%+v", records)
	}
	if fake.createCalls != 1 {
		t.Errorf("CreateInstance 应 1 次，实际 %d", fake.createCalls)
	}
	if fake.destroyCalls != 1 {
		t.Errorf("accepted 后应销毁靶机 1 次，实际 %d", fake.destroyCalls)
	}

	// 对照组 A：开关关 → 起了也不销毁（证明销毁来自开关，不是别的副作用）
	fake2 := newFake("访问靶机读取 flag：flag{env_release_ok}")
	fake2.ch.Description = "访问靶机读取 flag：flag{env_release_ok}"
	pc2 := DefaultPollerConfig()
	pc2.SubmitAfterSolve = true
	pc2.AutoBuildEnv = true // AutoReleaseEnv 保持 false
	poller2 := NewPoller(fake2, solverForAttachmentDrill(), pc2, zap.NewNop())
	if _, err := poller2.RunOnce(context.Background()); err != nil {
		t.Fatalf("对照组A失败: %v", err)
	}
	if fake2.destroyCalls != 0 {
		t.Errorf("对照组A不应销毁，实际 %d", fake2.destroyCalls)
	}

	// 对照组 B：未解出 → 保留靶机供人工接手，不得销毁
	fake3 := newFake("访问靶机读取 flag（详情也没给 flag）")
	pc3 := DefaultPollerConfig()
	pc3.SubmitAfterSolve = true
	pc3.AutoBuildEnv = true
	pc3.AutoReleaseEnv = true
	poller3 := NewPoller(fake3, solverForAttachmentDrill(), pc3, zap.NewNop())
	if _, err := poller3.RunOnce(context.Background()); err != nil {
		t.Fatalf("对照组B失败: %v", err)
	}
	if fake3.destroyCalls != 0 {
		t.Errorf("未解出的题应保留靶机、不得销毁，实际 %d", fake3.destroyCalls)
	}
	t.Logf("靶机回收演练：accepted→destroy×1；对照组A(关开关)=%d，对照组B(未解出)=%d",
		fake2.destroyCalls, fake3.destroyCalls)
}

// rehearsalEnvInt 读环境变量整数（带默认值）。
func rehearsalEnvInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// TestRehearsalStress 赛前压力演练（**手动触发**，默认跳过以免拖慢日常 CI）。
//
// 用法（决赛前按 runbook 执行，摸最优并发与吞吐）：
//
//	REHEARSAL_STRESS=1 \
//	REHEARSAL_PROBLEMS=30 REHEARSAL_CONCURRENCY=8 REHEARSAL_SOLVE_MS=80 \
//	REHEARSAL_LIST_429=3 REHEARSAL_SUBMIT_429=2 \
//	go test -count=1 -v -run TestRehearsalStress ./internal/ctfplatform/
//
// 断言随参数缩放：可解题全 accepted / 无解题零提交 / 每题 ≤1 次成功提交 /
// 提交限流被客户端内部重试吸收（提交 HTTP 次数 = 可解题数 + 注入数）/ 第二轮去重。
func TestRehearsalStress(t *testing.T) {
	if os.Getenv("REHEARSAL_STRESS") == "" {
		t.Skip("压力演练默认跳过：REHEARSAL_STRESS=1 启用；可配 REHEARSAL_PROBLEMS/CONCURRENCY/SOLVE_MS/LIST_429/SUBMIT_429")
	}
	n := rehearsalEnvInt("REHEARSAL_PROBLEMS", 20)
	conc := rehearsalEnvInt("REHEARSAL_CONCURRENCY", 4)
	solveMS := rehearsalEnvInt("REHEARSAL_SOLVE_MS", 60)
	list429 := rehearsalEnvInt("REHEARSAL_LIST_429", 2)
	submit429 := rehearsalEnvInt("REHEARSAL_SUBMIT_429", 0)
	solvable := n * 6 / 10

	chs := make([]rehearsalChallenge, 0, n)
	for i := 0; i < n; i++ {
		id := strconv.Itoa(5000 + i)
		if i < solvable {
			chs = append(chs, rehearsalChallenge{
				id: id, title: fmt.Sprintf("CRYPTO-%02d", i),
				desc:    fmt.Sprintf("flag{stress_%s_ok}", id),
				solveDur: time.Duration(solveMS) * time.Millisecond,
			})
		} else {
			chs = append(chs, rehearsalChallenge{
				id: id, title: fmt.Sprintf("PWN-%02d", i),
				desc: "需要交互式靶机，静态无解", solveDur: 5 * time.Millisecond,
			})
		}
	}

	sim := newRehearsalPlatform(chs)
	sim.inject429 = list429
	sim.injectSubmit429 = submit429
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
	pc.AutoBuildEnv = false // 压力演练聚焦并发/限流；起靶机链另有专门演练
	pc.MaxConcurrency = conc
	poller := NewPoller(p, solver, pc, zap.NewNop())
	poller.SetAdvisor(p)

	start := time.Now()
	records, err := poller.RunOnce(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("压力演练失败（限流下整轮不应中断）: %v", err)
	}
	if len(records) != n {
		t.Fatalf("应处理 %d 题，实际 %d", n, len(records))
	}

	accepted := 0
	for _, r := range records {
		if r.Accepted {
			accepted++
		}
	}
	if accepted != solvable {
		t.Errorf("可解题应全被接受：accepted=%d / solvable=%d", accepted, solvable)
	}

	// 无解题零提交 + 每题成功提交 ≤1 次
	for _, c := range chs {
		if c.solveDur == 5*time.Millisecond && sim.submitsByID[c.id] != 0 {
			t.Errorf("无解题 %s 不应提交（%d 次）", c.id, sim.submitsByID[c.id])
		}
		if sim.submitsByID[c.id] > 1 {
			t.Errorf("题 %s 成功提交 %d 次（重复提交浪费机会）", c.id, sim.submitsByID[c.id])
		}
	}
	// 提交限流应被客户端内部重试完全吸收：HTTP 提交次数 = 可解题数 + 注入数
	wantSubmitHTTP := solvable + submit429
	if sim.submitCalls != wantSubmitHTTP {
		t.Errorf("提交 HTTP 次数 %d ≠ 预期 %d（可解 %d + 注入 429 %d）；说明重试策略有泄漏",
			sim.submitCalls, wantSubmitHTTP, solvable, submit429)
	}

	// 并发有效性：总耗时 < 各题耗时之和（并发 >1 时）
	if conc > 1 {
		// ⚠️ 单位：solveMS 是毫秒数，必须显式乘 time.Millisecond
		//（曾漏乘 → 阈值变成 1.44µs，任何实现都会"失败"）。
		muSum := time.Duration(solvable*solveMS) * time.Millisecond
		if elapsed >= muSum {
			t.Errorf("并发未生效：总耗时 %v ≥ 可解题耗时之和 %v", elapsed, muSum)
		}
	}

	// 第二轮去重
	before := sim.submitCalls
	if _, err := poller.RunOnce(context.Background()); err != nil {
		t.Fatalf("第二轮失败: %v", err)
	}
	if sim.submitCalls != before {
		t.Errorf("第二轮不应产生提交：%d → %d", before, sim.submitCalls)
	}

	t.Logf("压力演练：题数=%d（可解 %d）并发=%d 求解耗时=%dms | 总耗时=%v 吞吐=%.1f 题/秒 | 拉题 %d 次（注入 429×%d）提交 HTTP %d 次（注入 429×%d）",
		n, solvable, conc, solveMS, elapsed.Round(time.Millisecond),
		float64(n)/elapsed.Seconds(), sim.listCalls, list429, sim.submitCalls, submit429)
}

// TestRehearsalConcurrencySweep 并发扫描（**手动触发**）：同一负载跑多档并发，
// 输出吞吐表，供赛前把 MaxConcurrency 定在拐点上（默认配置 2 明显偏保守）。
//
//	REHEARSAL_SWEEP=1 REHEARSAL_SWEEP_PROBLEMS=16 REHEARSAL_SWEEP_SOLVE_MS=80 \
//	go test -count=1 -v -run TestRehearsalConcurrencySweep ./internal/ctfplatform/
func TestRehearsalConcurrencySweep(t *testing.T) {
	if os.Getenv("REHEARSAL_SWEEP") == "" {
		t.Skip("并发扫描默认跳过：REHEARSAL_SWEEP=1 启用；可配 REHEARSAL_SWEEP_PROBLEMS/SOLVE_MS")
	}
	n := rehearsalEnvInt("REHEARSAL_SWEEP_PROBLEMS", 12)
	solveMS := rehearsalEnvInt("REHEARSAL_SWEEP_SOLVE_MS", 80)

	chs := make([]rehearsalChallenge, 0, n)
	for i := 0; i < n; i++ {
		chs = append(chs, rehearsalChallenge{
			id:    strconv.Itoa(7000 + i),
			title: fmt.Sprintf("CRYPTO-%02d", i),
			desc:  fmt.Sprintf("flag{sweep_%d_ok}", i),
			solveDur: time.Duration(solveMS) * time.Millisecond,
		})
	}

	elapsed := map[int]time.Duration{}
	t.Logf("并发扫描（%d 题 × %dms/题，理论上限串行 %v）：", n, solveMS, time.Duration(n*solveMS))
	for _, c := range []int{1, 2, 4, 8} {
		sim := newRehearsalPlatform(chs)
		srv := httptest.NewServer(sim.handler(t))
		p := newTestPlatform(t, srv.URL)
		solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
			select {
			case <-time.After(time.Duration(solveMS) * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return FilterFlagCandidates(ExtractFlags(ch.Description)), nil
		}
		pc := DefaultPollerConfig()
		pc.SubmitAfterSolve = true
		pc.MaxConcurrency = c
		poller := NewPoller(p, solver, pc, zap.NewNop())
		start := time.Now()
		if _, err := poller.RunOnce(context.Background()); err != nil {
			t.Fatalf("并发=%d 失败: %v", c, err)
		}
		d := time.Since(start)
		for _, ch := range chs {
			if !sim.acceptedByID[ch.id] {
				t.Fatalf("并发=%d：题 %s 未被接受", c, ch.id)
			}
		}
		elapsed[c] = d
		t.Logf("  并发=%-2d 总耗时=%-10v 吞吐=%.1f 题/秒 加速比=%.2fx",
			c, d.Round(time.Millisecond), float64(n)/d.Seconds(),
			float64(elapsed[1])/float64(d))
		srv.Close()
	}
	// 只拦"并发完全没生效"：4 并发必须显著快于串行（阈值放宽到 0.7，避免 CI 抖动假红）。
	if !(elapsed[4] < elapsed[1]*7/10) {
		t.Errorf("并发扫描异常：4 并发 %v 未显著快于串行 %v", elapsed[4], elapsed[1])
	}
}
