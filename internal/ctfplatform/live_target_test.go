package ctfplatform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ─────────────────────────────────────────────────────────────────────────────
// 真实靶机端到端演练（live target end-to-end）
//
// 为什么既有演练不够：TestRehearsalFinalsLoop 的 flag 写在**题面文本**里，
// solver 静态抽取即得。那测的是"平台契约 + 提交判据"，**测不到真实靶机**。
// 而真实赛场的 web/misc 题，flag 就在**靶机响应**里 —— 静态层永远拿不到，
// 必须真的发 HTTP 请求。这是 55 题真题库 36 道未命中里 21 道的真实形态。
//
// 本文件起真 HTTP 靶机（真漏洞，非 mock 响应），走完整链路：
//   平台投递 → 起靶机(build-env) → 取地址(detail) → 地址注入题面 → 探测真实响应
//   → 解出 flag → 提交(answer) → 平台判分
//
// 定位（防止把结论读大）：探测器是**写死的专用探测器**，代替 Agent 的"手"。
// 所以本文件验证的是**链路**（地址注入 / 真实 HTTP 交互 / 提交判分 / 判分一致性），
// **不测评 AI 自主解题能力** —— 后者需要 LLM 驱动的开放式评测，另行设计。
// ─────────────────────────────────────────────────────────────────────────────

var liveFlagRe = regexp.MustCompile(`flag\{[^}]+\}`)

var liveProbeClient = &http.Client{Timeout: 10 * time.Second}

type liveProbe func(ctx context.Context, baseURL string) ([]string, error)

// liveCase = 一道"真实靶机题"。
// desc 是**完整题面但不含 flag、不含靶机 URL** —— 与真实平台同构：
// 真实赛题的地址是平台分配后注入的，题面里本来就没有。
type liveCase struct {
	id      string
	title   string
	desc    string
	flag    string           // 完整 flag（含外壳），只出现在靶机响应里
	handler http.HandlerFunc // 真实靶机路由
	probe   liveProbe        // 专用探测器（代替 Agent 的手）
}

// hitCounter 统计各题靶机被真实访问的次数。
// 独立于 liveCase 是因为 liveCase 被 range 复制，内含锁会被 go vet 判 "copies lock"。
type hitCounter struct {
	mu sync.Mutex
	m  map[string]int
}

func newHitCounter() *hitCounter { return &hitCounter{m: map[string]int{}} }

func (h *hitCounter) inc(id string) {
	h.mu.Lock()
	h.m[id]++
	h.mu.Unlock()
}

func (h *hitCounter) get(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.m[id]
}

// ── 靶机 1：源码泄露（对应 pico2024_findme / pico2024_intro_to_web 同款）────────
func targetSourceLeak(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><head><title>Find me</title></head>
<body>
<h1>Congratulations! You reached the page.</h1>
<p>Some hints are hidden in this file.</p>
<!-- %s -->
</body></html>`, flag)
	}
}

func probeSourceLeak(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/", liveFlagRe)
}

// ── 靶机 2：Cookie 里的 Base64 flag（对应 pico2024_cookie / pico2024_webdecode）──
func targetCookieB64(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enc := base64.StdEncoding.EncodeToString([]byte(flag))
		http.SetCookie(w, &http.Cookie{Name: "session", Value: enc, Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><body>Login successful. Your session cookie is set.</body></html>")
	}
}

func probeCookieB64(ctx context.Context, base string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s/ → HTTP %d", base, resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		dec, err := base64.StdEncoding.DecodeString(c.Value)
		if err != nil {
			continue
		}
		if s := string(dec); liveFlagRe.MatchString(s) {
			return []string{s}, nil
		}
	}
	return nil, fmt.Errorf("cookie 中未解出 flag（cookie 数=%d）", len(resp.Cookies()))
}

// ── 靶机 3：SQL 注入登录绕过（对应 pico2024_irishname / buuctf_sqli_basic）──────
func targetSQLiAuth(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		user := r.FormValue("user")
		// 真实漏洞形态：字符串直接比对，未参数化 → 恒真条件即可绕过
		lowered := strings.ToLower(user)
		if strings.Contains(lowered, "or") && strings.Contains(lowered, "1") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><p>Welcome back, %s</p><!-- %s --></body></html>", user, flag)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "invalid credentials")
	}
}

func probeSQLiAuth(ctx context.Context, base string) ([]string, error) {
	form := strings.NewReader("user=%27+OR+%271%27%3D%271&pass=x")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/login", form)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s/login → HTTP %d（注入未绕过）", base, resp.StatusCode)
	}
	if m := liveFlagRe.FindAllString(string(b), -1); len(m) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("绕过登录后响应中仍无 flag")
}

// ── 靶机 4：本地文件包含（对应 buuctf_lfi_basic）──────────────────────────────
func targetLFI(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.php" {
			http.NotFound(w, r)
			return
		}
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(page, "..") {
			// 真实穿越成立时才吐内容
			fmt.Fprintf(w, "<html><body><div class=content><!-- %s --></div></body></html>", flag)
			return
		}
		io.WriteString(w, "<html><body><h1>Home</h1><a href=\"/index.php?page=about\">about</a></body></html>")
	}
}

func probeLFI(ctx context.Context, base string) ([]string, error) {
	u := base + "/index.php?page=" + "..%2f..%2f..%2f..%2fflag"
	return liveGetExtract(ctx, u, liveFlagRe)
}

func liveGetExtract(ctx context.Context, u string, re *regexp.Regexp) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s → HTTP %d", u, resp.StatusCode)
	}
	if m := re.FindAllString(string(b), -1); len(m) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("GET %s 响应中无 flag", u)
}

// ── 极简平台：按 exerciseId 分发**各自的**真实靶机 ───────────────────────────
// 为什么不复用 rehearsalPlatform：它的 webTargetURL 是单值（全体题共用一个靶机），
// 真实评测需要一题一靶机；为不侵入既有演练文件，这里独立实现四个端点。
type livePlatform struct {
	mu       sync.Mutex
	targets  map[string]string // exerciseId → 靶机 base URL
	inner    map[string]string // exerciseId → 剥壳后的正确答案
	builds   map[string]int
	details  map[string]int
	submits  map[string]int
	accepted map[string]bool
}

func newLivePlatform() *livePlatform {
	return &livePlatform{
		targets:  map[string]string{},
		inner:    map[string]string{},
		builds:   map[string]int{},
		details:  map[string]int{},
		submits:  map[string]int{},
		accepted: map[string]bool{},
	}
}

func (p *livePlatform) listPayload() string {
	type item struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		IsOpen      bool   `json:"isOpen"`
		HasInstance bool   `json:"has_instance"`
	}
	p.mu.Lock()
	ids := make([]int, 0, len(p.targets))
	for id := range p.targets {
		n, err := strconv.Atoi(id)
		if err != nil {
			continue
		}
		ids = append(ids, n)
	}
	sort.Ints(ids) // 固定顺序，避免 map 随机化导致并发断言抖动
	data := []map[string]interface{}{}
	for _, id := range ids {
		data = append(data, map[string]interface{}{
			"id": id, "name": strconv.Itoa(id),
			"description": "平台已分配靶机，请按题面要求访问",
			"isOpen":      true, "has_instance": true,
		})
	}
	p.mu.Unlock()
	b, _ := json.Marshal(data)
	return `{"code":"00000","data":` + string(b) + `}`
}

func (p *livePlatform) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slab-match/api/v1/agent/ctf/exercise-list":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(p.listPayload()))

		case "/slab-match/api/v1/agent/ctf/build-exercise-env":
			body, _ := io.ReadAll(r.Body)
			id := extractExerciseID(string(body))
			p.mu.Lock()
			p.builds[id]++
			p.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":{"instance_id":"inst-live-1","status":"running"}}`))

		case "/slab-match/api/v1/agent/ctf/exercise":
			id := r.URL.Query().Get("exerciseId")
			p.mu.Lock()
			p.details[id]++
			hostport := strings.TrimPrefix(p.targets[id], "http://")
			p.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			if hostport == "" {
				_, _ = w.Write([]byte(`{"code":"00000","data":{}}`))
				return
			}
			fmt.Fprintf(w, `{"code":"00000","data":{"endpoints":[{"exposeIps":["%s"]}]}}`, hostport)

		case "/slab-match/api/v1/agent/answer-panel/answer":
			body, _ := io.ReadAll(r.Body)
			id := extractExerciseID(string(body))
			submitted := extractJSONString(string(body), "flag")
			p.mu.Lock()
			p.submits[id]++
			want := p.inner[id]
			ok := want != "" && submitted == want
			if ok {
				p.accepted[id] = true
			}
			p.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			if ok {
				_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":true}}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":"00000","data":{"isCorrect":false}}`))

		default:
			http.NotFound(w, r)
		}
	}
}

func extractExerciseID(body string) string {
	m := regexp.MustCompile(`"exerciseId"\s*:\s*"?(\d+)"?`).FindStringSubmatch(body)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func extractJSONString(body, key string) string {
	m := regexp.MustCompile(`"` + key + `"\s*:\s*"([^"]*)"`).FindStringSubmatch(body)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// newLiveCases 组装 10 种真实题型。
// 题型与 55 道真题里 36 道未命中的 sub 分布一一对应（picoCTF 2024/2025、BUUCTF 同款原型）。
func newLiveCases() []liveCase {
	return []liveCase{
		{
			id: "2001", title: "WEB-01", flag: "flag{live_source_leak_ok}",
			desc:      "平台已分配靶机。访问靶机首页并查看页面源码，flag 藏在源码注释里。",
			handler:   targetSourceLeak("flag{live_source_leak_ok}"),
			probe:     probeSourceLeak,
		},
		{
			id: "2002", title: "WEB-02", flag: "flag{live_cookie_b64_ok}",
			desc:      "平台已分配靶机。登录成功后会话信息存在 Cookie 里，Base64 编码后取出 flag。",
			handler:   targetCookieB64("flag{live_cookie_b64_ok}"),
			probe:     probeCookieB64,
		},
		{
			id: "2003", title: "WEB-03", flag: "flag{live_sqli_auth_ok}",
			desc:      "平台已分配靶机。/login 存在 SQL 注入，构造恒真条件绕过登录后拿到 flag。",
			handler:   targetSQLiAuth("flag{live_sqli_auth_ok}"),
			probe:     probeSQLiAuth,
		},
		{
			id: "2004", title: "WEB-04", flag: "flag{live_lfi_ok}",
			desc:      "平台已分配靶机。/index.php?page= 参数存在本地文件包含，读取 flag 文件。",
			handler:   targetLFI("flag{live_lfi_ok}"),
			probe:     probeLFI,
		},
		{
			id: "2005", title: "WEB-05", flag: "flag{live_ssti_ok}",
			desc:      "平台已分配靶机。/search 参数被当作模板源码渲染，尝试构造模板表达式读取服务端配置。",
			handler:   targetSSTI("flag{live_ssti_ok}"),
			probe:     probeSSTI,
		},
		{
			id: "2006", title: "WEB-06", flag: "flag{live_jwt_weak_ok}",
			desc:      "平台已分配靶机。/verify 校验 JWT，签名密钥过弱，可离线爆破后伪造管理员身份。",
			handler:   targetJWTWeak("flag{live_jwt_weak_ok}"),
			probe:     probeJWTWeak,
		},
		{
			id: "2007", title: "WEB-07", flag: "flag{live_ssrf_ok}",
			desc:      "平台已分配靶机。/fetch 可传入任意 URL，未做内网地址限制，尝试访问内网管理服务。",
			handler:   targetSSRF("flag{live_ssrf_ok}"),
			probe:     probeSSRF,
		},
		{
			id: "2008", title: "WEB-08", flag: "flag{live_cmdinject_ok}",
			desc:      "平台已分配靶机。/ping 会对主机名执行系统命令，尝试用分隔符注入第二条命令。",
			handler:   targetCmdInject("flag{live_cmdinject_ok}"),
			probe:     probeCmdInject,
		},
		{
			id: "2009", title: "WEB-09", flag: "flag{live_upload_bypass_ok}",
			desc:      "平台已分配靶机。/upload 只按扩展名校验，尝试上传 .php 文件绕过限制。",
			handler:   targetUploadBypass("flag{live_upload_bypass_ok}"),
			probe:     probeUploadBypass,
		},
		{
			id: "2010", title: "WEB-10", flag: "flag{live_xxe_ok}",
			desc:      "平台已分配靶机。/xml 会解析提交的 XML，尝试利用外部实体读取本地文件。",
			handler:   targetXXE("flag{live_xxe_ok}"),
			probe:     probeXXE,
		},
		{
			id: "2011", title: "WEB-11", flag: "flag{live_xss_ok}",
			desc:      "平台已分配靶机。/search 的 q 参数未转义直接回显，构造脚本注入并观察注入点上下文。",
			handler:   targetXSS("flag{live_xss_ok}"),
			probe:     probeXSS,
		},
		{
			id: "2012", title: "WEB-12", flag: "flag{live_nosql_ok}",
			desc:      "平台已分配靶机。/login 直接把提交的 JSON 当查询条件，用 MongoDB 操作符绕过认证。",
			handler:   targetNoSQLBypass("flag{live_nosql_ok}"),
			probe:     probeNoSQLBypass,
		},
		{
			id: "2013", title: "WEB-13", flag: "flag{live_api_authz_ok}",
			desc:      "平台已分配靶机。/api/v1/admin/keys 未做真正鉴权，尝试直接访问管理端点。",
			handler:   targetAPIAuthz("flag{live_api_authz_ok}"),
			probe:     probeAPIAuthz,
		},
	}
}

// runLiveOnce 起靶机 + 起平台 + 跑一轮 Poller，返回平台、记录与靶机访问计数。
func runLiveOnce(t *testing.T, cases []liveCase, injectTarget bool) (*livePlatform, []PollRecord, *hitCounter) {
	t.Helper()
	plat := newLivePlatform()
	hits := newHitCounter()
	srv := httptest.NewServer(plat.handler(t))
	defer srv.Close()

	probeByID := map[string]liveProbe{}
	for _, c := range cases {
		id, handler := c.id, c.handler
		tgt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.inc(id)
			handler(w, r)
		}))
		defer tgt.Close()
		plat.mu.Lock()
		plat.targets[c.id] = tgt.URL
		plat.inner[c.id] = StripFlagWrapper(c.flag)
		plat.mu.Unlock()
		probeByID[c.id] = c.probe
	}

	solver := func(ctx context.Context, ch *Challenge) ([]string, error) {
		probe, ok := probeByID[ch.ID]
		if !ok {
			return nil, fmt.Errorf("题 %s 无探测器", ch.ID)
		}
		base, _ := ch.Extra["target_url"].(string)
		if base == "" {
			return nil, fmt.Errorf("题面未注入靶机地址（Extra[target_url] 为空）")
		}
		if !strings.Contains(ch.Description, base) {
			return nil, fmt.Errorf("题面文本未出现靶机地址（注入缺失）")
		}
		return probe(ctx, base)
	}

	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.MaxConcurrency = 4
	pc.SolveTimeout = 20 * time.Second
	pc.AutoBuildEnv = injectTarget
	pc.AutoFetchDetail = injectTarget

	p := newTestPlatform(t, srv.URL)
	poller := NewPoller(p, solver, pc, zap.NewNop())
	poller.SetAdvisor(p)

	records, err := poller.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("真实靶机端到端 RunOnce 失败: %v", err)
	}
	return plat, records, hits
}

func TestLiveTargetEndToEnd(t *testing.T) {
	cases := newLiveCases()
	plat, records, hits := runLiveOnce(t, cases, true)

	byID := map[string]PollRecord{}
	for _, r := range records {
		byID[r.ChallengeID] = r
	}

	for _, c := range cases {
		rec, ok := byID[c.id]
		if !ok {
			t.Errorf("题 %s 未被处理，records=%d", c.id, len(records))
			continue
		}
		if !rec.Submitted {
			t.Errorf("题 %s 应发生提交，实际 rec=%+v", c.id, rec)
		}
		if !rec.Accepted {
			t.Errorf("题 %s 应被平台判为 accepted，实际 rec=%+v", c.id, rec)
		}
		// 关键：flag 必须来自真实靶机响应，不是凭空来的
		if n := hits.get(c.id); n == 0 {
			t.Errorf("题 %s 的靶机从未被访问（hits=0）—— 说明没走真实 HTTP 探测", c.id)
		}
	}

	// 起靶机链与地址注入链各被调用（证明 AutoBuildEnv / AutoFetchDetail 真的生效）
	plat.mu.Lock()
	builds, details := len(plat.builds), len(plat.details)
	for id, n := range plat.builds {
		if n == 0 {
			t.Errorf("题 %s 未调用 build-exercise-env", id)
		}
	}
	for id, n := range plat.details {
		if n == 0 {
			t.Errorf("题 %s 未调用 challenge_detail（取不到靶机地址）", id)
		}
	}
	plat.mu.Unlock()
	if builds != len(cases) || details != len(cases) {
		t.Errorf("build/detail 覆盖题数不对：builds=%d details=%d 期望各 %d", builds, details, len(cases))
	}

	// 每题最多提交一次（不得浪费提交机会）
	plat.mu.Lock()
	for id, n := range plat.submits {
		if n > 1 {
			t.Errorf("题 %s 提交 %d 次，超过 1 次", id, n)
		}
	}
	plat.mu.Unlock()
}

// TestLiveTargetFailsWithoutEnvInjection 是**反向自检**：
// 关闭起靶机/地址注入后，题目必须**全部失败**——
// 这证明上一条测试的 accepted 确实来自"平台注入地址 → 真实 HTTP 探测"这条链，
// 而不是"flag 恰好出现在别处"或"断言写松了"。
// 若本题意外全过，说明上一条的通过原因不是我们以为的那条（测试失去证明力）。
func TestLiveTargetFailsWithoutEnvInjection(t *testing.T) {
	cases := newLiveCases()
	plat, records, hits := runLiveOnce(t, cases, false)

	byID := map[string]PollRecord{}
	for _, r := range records {
		byID[r.ChallengeID] = r
	}
	for _, c := range cases {
		rec := byID[c.id]
		if rec.Accepted {
			t.Errorf("未注入靶机地址却判 accepted（%s）—— 链路判据失效", c.id)
		}
		plat.mu.Lock()
		n := plat.submits[c.id]
		plat.mu.Unlock()
		if n != 0 {
			t.Errorf("未注入地址却提交 %d 次（%s）—— 应在求解阶段就失败", n, c.id)
		}
		if h := hits.get(c.id); h != 0 {
			t.Errorf("未注入地址却仍访问了靶机 %d 次（%s）—— 探测器不应被触发", h, c.id)
		}
	}
}
