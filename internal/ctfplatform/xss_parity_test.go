package ctfplatform

// XSS 集的 Go 侧机验（对齐 data/ctf_benchmark/judge_xss.py 与 live_target/xss_range.py）。
//
// 靶机用 httptest 在进程内原生复刻（含"管理员 bot"与最小 JS 子集执行器），
// 逐题跑真实利用链，再拿 flag 的 sha256 与基准集比对。
//
// 反注水三条：
//   1. **safe 变异**：靶机把回显/留言做 HTML 转义后，三个场景必须**全部打不通**
//      （证明判题器不是"怎么都能过"）；
//   2. **无 payload 不触发**：bot 访问干净页面时监听器收不到任何数据；
//   3. **会话是硬门槛**：不带正确 session 打 /admin/panel 必须 403（组合链的第二段
//      不能白拿）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

// XSS 三场景 flag（与 live_target/xss_range.py 的 SCENES 逐字一致）。
const (
	xssFlagReflected = "flag{xss_r3fl3ct3d_c00k13}"
	xssFlagStored    = "flag{xss_st0r3d_p3rs1st}"
	xssFlagToSQLi    = "flag{xss_t0_sql1_ch41n}"
)

// xssAdminSession 管理端会话（与 Python 侧同算法：sess- + sha256("xss-range-admin")[:16]）。
var xssAdminSession = func() string {
	sum := sha256.Sum256([]byte("xss-range-admin"))
	return "sess-" + hex.EncodeToString(sum[:])[:16]
}()

var (
	xssScriptRe  = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	xssHandlerRe = regexp.MustCompile(`(?is)on\w+\s*=\s*["']([^"']*)["']`)
	// 三类外带写法（最小 JS 子集）：URL 前缀 + 拼接 document.cookie
	xssExfilPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)fetch\(\s*['"]([^'"]+)['"]\s*\+\s*(?:encodeURIComponent\()?\s*document\.cookie`),
		regexp.MustCompile(`(?i)new\s+Image\(\s*\)\s*\.src\s*=\s*['"]([^'"]+)['"]\s*\+\s*(?:encodeURIComponent\()?\s*document\.cookie`),
		regexp.MustCompile(`(?i)(?:document\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]\s*\+\s*(?:encodeURIComponent\()?\s*document\.cookie`),
	}
)

// xssRange 是 Go 原生靶机（含 bot 与最小 JS 子集执行器）。
type xssRange struct {
	srv     *httptest.Server
	safe    bool // true = 回显/留言 HTML 转义（变异开关，XSS 不成立）

	mu        sync.Mutex
	collected []string
	guestbook [][2]string
}

// xssRunJSSubset 最小 JS 子集执行：抽出 script 体与事件处理器，匹配外带写法并真实发请求。
// 返回成功发出的请求数。
func (r *xssRange) xssRunJSSubset(page, cookie string) int {
	chunks := xssScriptRe.FindAllStringSubmatch(page, -1)
	bodies := make([]string, 0, len(chunks))
	for _, m := range chunks {
		bodies = append(bodies, m[1])
	}
	for _, m := range xssHandlerRe.FindAllStringSubmatch(page, -1) {
		bodies = append(bodies, m[1])
	}

	executed := 0
	for _, code := range bodies {
		for _, rx := range xssExfilPatterns {
			for _, m := range rx.FindAllStringSubmatch(code, -1) {
				u := m[1] + url.QueryEscape(cookie)
				if strings.HasPrefix(u, "/") {
					u = r.srv.URL + u
				}
				if _, err := xssHTTPGet(context.Background(), u); err == nil {
					executed++
				}
			}
		}
	}
	return executed
}

func newXSSRange(t *testing.T, safe bool) *xssRange {
	t.Helper()
	r := &xssRange{safe: safe}
	mux := http.NewServeMux()

	page := func(title, body string) string {
		return fmt.Sprintf("<!DOCTYPE html><html><head><meta charset='utf-8'><title>%s</title></head>"+
			"<body><h1>%s</h1>%s</body></html>", title, title, body)
	}
	sendHTML := func(w http.ResponseWriter, code int, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
	sendJSON := func(w http.ResponseWriter, code int, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	esc := func(s string) string {
		if r.safe {
			return html.EscapeString(s)
		}
		return s
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			sendHTML(w, 404, page("404", "<p>not found</p>"))
			return
		}
		sendHTML(w, 200, page("XSS Range", "<ul><li>/search</li><li>/guestbook</li></ul>"))
	})

	// 反射型：q 原样回显
	mux.HandleFunc("/search", func(w http.ResponseWriter, req *http.Request) {
		q := esc(req.URL.Query().Get("q"))
		sendHTML(w, 200, page("Search", "<p>Results for: "+q+"</p>"))
	})

	// 存储型：留言原样渲染
	mux.HandleFunc("/guestbook", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			_ = req.ParseForm()
			r.mu.Lock()
			r.guestbook = append(r.guestbook, [2]string{req.PostFormValue("name"), req.PostFormValue("msg")})
			r.mu.Unlock()
			w.Header().Set("Location", "/guestbook")
			w.WriteHeader(http.StatusFound)
			return
		}
		r.mu.Lock()
		var sb strings.Builder
		for _, e := range r.guestbook {
			sb.WriteString(fmt.Sprintf("<div class='entry'><b>%s</b>: %s</div>", esc(e[0]), esc(e[1])))
		}
		r.mu.Unlock()
		form := "<form method='post' action='/guestbook'><input name='name'><textarea name='msg'></textarea></form>"
		sendHTML(w, 200, page("Guestbook", sb.String()+form))
	})

	// 管理员 bot：带 Cookie 访问目标并执行页面里的外带
	mux.HandleFunc("/admin/visit", func(w http.ResponseWriter, req *http.Request) {
		target := req.URL.Query().Get("url")
		scene := req.URL.Query().Get("scene")
		if strings.HasPrefix(target, "/") {
			target = r.srv.URL + target
		}
		cookie := "admin_session=" + xssAdminSession
		switch scene {
		case "xss_reflected":
			cookie += "; flag=" + xssFlagReflected
		case "xss_stored":
			cookie += "; flag=" + xssFlagStored
		}
		hreq, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			sendJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		hreq.Header.Set("Cookie", cookie)
		hreq.Header.Set("User-Agent", "AdminBot/1.0")
		resp, err := (&http.Client{}).Do(hreq)
		if err != nil {
			sendJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		var body strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				body.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		resp.Body.Close()
		executed := r.xssRunJSSubset(body.String(), cookie)
		sendJSON(w, 200, map[string]interface{}{"ok": true, "visited": target, "executed": executed})
	})

	// 攻击者监听器
	mux.HandleFunc("/collect", func(w http.ResponseWriter, req *http.Request) {
		if c := req.URL.Query().Get("c"); c != "" {
			r.mu.Lock()
			r.collected = append(r.collected, c)
			r.mu.Unlock()
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/collect/latest", func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		last := ""
		if n := len(r.collected); n > 0 {
			last = r.collected[n-1]
		}
		count := len(r.collected)
		r.mu.Unlock()
		sendJSON(w, 200, map[string]interface{}{"data": last, "count": count})
	})

	// 管理面板：必须持会话；id 参数存在 SQLi
	mux.HandleFunc("/admin/panel", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("session") != xssAdminSession {
			sendHTML(w, 403, page("Forbidden", "<p>admin session required</p>"))
			return
		}
		idv := req.URL.Query().Get("id")
		if strings.ContainsAny(idv, `'"#`) || strings.Contains(idv, " OR ") || strings.Contains(idv, " or ") {
			sendHTML(w, 200, page("Admin Panel", "<pre>"+xssFlagToSQLi+"</pre>"))
			return
		}
		sendHTML(w, 200, page("Admin Panel", "<p>row id="+idv+"</p>"))
	})

	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

// TestXSSThreeScenes 三场景全通（正常靶机）。
func TestXSSThreeScenes(t *testing.T) {
	r := newXSSRange(t, false)
	ctx := context.Background()

	cases := []struct {
		pid  string
		run  func(context.Context, string) (string, error)
		want string
	}{
		{"xss_reflected", xssAttackReflected, xssFlagReflected},
		{"xss_stored", xssAttackStored, xssFlagStored},
		{"xss_to_sqli", xssAttackToSQLi, xssFlagToSQLi},
	}
	for _, c := range cases {
		got, err := c.run(ctx, r.srv.URL)
		if err != nil {
			t.Fatalf("[%s] 利用链未打通: %v", c.pid, err)
		}
		if got != c.want {
			t.Fatalf("[%s] flag 不符: got=%q want=%q", c.pid, got, c.want)
		}
	}
}

// TestXSSSafeModeBlocksAll 变异：靶机转义后三场景必须全部打不通（判题器非空洞绿）。
func TestXSSSafeModeBlocksAll(t *testing.T) {
	r := newXSSRange(t, true) // --safe 等价：回显/留言都 HTML 转义
	ctx := context.Background()

	for _, c := range []struct {
		pid string
		run func(context.Context, string) (string, error)
	}{
		{"xss_reflected", xssAttackReflected},
		{"xss_stored", xssAttackStored},
		{"xss_to_sqli", xssAttackToSQLi},
	} {
		if flag, err := c.run(ctx, r.srv.URL); err == nil {
			t.Fatalf("[%s] 转义靶机仍打通（flag=%q）—— 判题器在瞎猜，基准集失去意义", c.pid, flag)
		}
	}
}

// TestXSSNoPayloadNoExfil 干净页面不得产生外带（排除"只要 bot 访问就外带"的退化）。
func TestXSSNoPayloadNoExfil(t *testing.T) {
	r := newXSSRange(t, false)
	ctx := context.Background()
	if err := xssVisit(ctx, r.srv.URL, "/search?q=hello", "xss_reflected"); err != nil {
		t.Fatalf("bot 访问失败: %v", err)
	}
	data, err := xssLatestCollect(ctx, r.srv.URL)
	if err != nil {
		t.Fatalf("读监听器失败: %v", err)
	}
	if data != "" {
		t.Fatalf("干净页面却外带了数据（%q）—— 靶机/执行器退化了", data)
	}
}

// TestXSSAdminPanelRequiresSession 组合链第二段是硬门槛：无会话必须 403。
func TestXSSAdminPanelRequiresSession(t *testing.T) {
	r := newXSSRange(t, false)
	body, err := xssHTTPGet(context.Background(),
		r.srv.URL+"/admin/panel?id="+url.QueryEscape("1' OR '1'='1"))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if strings.Contains(body, xssFlagToSQLi) {
		t.Fatal("不带会话却拿到了 flag —— 会话校验形同虚设")
	}
}

// TestXSSSuiteParityAgainstBenchmark 逐题机验：三场景必须全中且 sha256 与基准集一致。
func TestXSSSuiteParityAgainstBenchmark(t *testing.T) {
	bench := loadSuiteBench(t, "xss_benchmark.json")
	if len(bench) == 0 {
		t.Fatal("[xss] 基准集 problems 为空 —— 空洞绿，禁止判过")
	}

	runners := map[string]func(context.Context, string) (string, error){
		"xss_reflected": xssAttackReflected,
		"xss_stored":    xssAttackStored,
		"xss_to_sqli":   xssAttackToSQLi,
	}

	for pid := range bench {
		if _, ok := runners[pid]; !ok {
			t.Errorf("[xss] json 含未实现分派的题 %q —— 覆盖度缺失（空洞绿风险）", pid)
		}
	}

	pids := make([]string, 0, len(bench))
	for pid := range bench {
		pids = append(pids, pid)
	}
	sort.Strings(pids)

	r := newXSSRange(t, false)
	hits := 0
	for _, pid := range pids {
		run, ok := runners[pid]
		if !ok {
			continue
		}
		flag, err := run(context.Background(), r.srv.URL)
		if err != nil {
			t.Logf("❌ MISS %s（%v）", pid, err)
			continue
		}
		if flagMatchesSHA([]string{flag}, bench[pid].FlagSHA256) {
			hits++
			t.Logf("✅ HIT  %s", pid)
		} else {
			t.Logf("❌ MISS %s（flag sha256 不匹配：%q）", pid, flag)
		}
	}
	t.Logf("=== [xss] Go 侧逐题: %d/%d ===", hits, len(bench))
	if hits < len(bench) {
		t.Errorf("[xss] Go 逐题命中 %d/%d 低于全中门禁（Python judge 侧全中，双语言应当一致）",
			hits, len(bench))
	}
}
