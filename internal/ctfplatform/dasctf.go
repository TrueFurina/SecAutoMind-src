package ctfplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DasCTFPlatform 实现挑战杯决赛官方 AI Agent API 客户端。
//
// 端点映射对齐西湖论剑 ctfplatform/dasctf.py 的 DEFAULT_ENDPOINTS，
// 以 /slab-match/api/v1/agent/ 为前缀。
//
// 鉴权：X-Agent-AccessKey 请求头（环境变量 DASCTF_TOKEN 或 CTF_AGENT_PLATFORM_TOKEN）。
// 所有方法返回类型安全——失败返回零值/默认对象 + error，不 panic。
type DasCTFPlatform struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	Logger     *zap.Logger
	Endpoints  map[string]string

	// ── 抗打击治理（移植自西湖论剑 ctfplatform/dasctf.py，决赛抗限流/抗 WAF）──
	// 7 项：① 指数退避重试 ② Retry-After 尊重 ③ 连续 429 计数(_consec_429)
	//     ④ 429 阶梯退避建议(BackoffSuggestion) ⑤ 403 WAF 冷却(_waf_blocked_until)
	//     ⑥ 列表 TTL 缓存(listCache) ⑦ HTTP 连接复用(HTTPClient 复用，Go 原生)
	MaxRetries      int           // 最大重试次数（默认 5）
	RetryBackoff    time.Duration // 退避基准（默认 2s，单次上限 15s）
	WAFTimeout      time.Duration // 403 触发后的冷却时长（默认 300s）
	listCacheTTL    time.Duration // 列表缓存 TTL（默认 10s，可用 CTF_AGENT_LIST_TTL 覆盖）
	mu              sync.Mutex    // 保护并发计数与缓存
	consec429       int           // 连续 429 次数（成功后重置）
	wafBlockedUntil time.Time     // WAF 冷却截止时刻（绝对时间，等价 monotonic）
	lastListOK      bool          // 最近一次 ListChallenges 是否真实成功（HTTP 200，含空列表）
	listCache       []Challenge   // 列表缓存
	listCacheAt     time.Time     // 列表缓存写入时刻
	lastError       string        // 最近一次请求层失败详情（供 SubmitFlag 暴露真实错误）
}

// defaultUserAgent 与真源（Python 客户端）保持逐字一致。
//
// 这不是"伪装技巧"而是协议一致性要求：平台侧的 WAF 会按 UA 判流，
// Go 默认 UA 会被判为脚本攻击。改动此值必须同步 scripts/gen_request_golden.py
// 并重新生成 request_golden.json。
const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"

// 默认端点映射（对齐官方 AI Agent API）
var defaultEndpoints = map[string]string{
	"match_info":       "/slab-match/api/v1/agent/match/notice/match-info",
	"overview":         "/slab-match/api/v1/agent/answer-panel/overview",
	"challenges":       "/slab-match/api/v1/agent/ctf/exercise-list",
	"challenge_detail": "/slab-match/api/v1/agent/ctf/exercise",
	"build_env":        "/slab-match/api/v1/agent/ctf/build-exercise-env",
	"recover_env":      "/slab-match/api/v1/agent/ctf/recover-exercise-env",
	"submit":           "/slab-match/api/v1/agent/answer-panel/answer",
	"notice_list":      "/slab-match/api/v1/agent/match/notice/now-list",
	"notice_detail":    "/slab-match/api/v1/agent/match/notice/detail",
}

// NewDasCTFPlatform 创建平台客户端。
// base_url 和 token 支持从环境变量 DASCTF_BASE_URL / DASCTF_TOKEN 读取。
func NewDasCTFPlatform(baseURL, token string, logger *zap.Logger) *DasCTFPlatform {
	if baseURL == "" {
		baseURL = os.Getenv("DASCTF_BASE_URL")
	}
	if token == "" {
		token = os.Getenv("DASCTF_TOKEN")
		if token == "" {
			token = os.Getenv("CTF_AGENT_PLATFORM_TOKEN")
		}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	eps := make(map[string]string, len(defaultEndpoints))
	for k, v := range defaultEndpoints {
		eps[k] = v
	}
	return &DasCTFPlatform{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Logger:       logger,
		Endpoints:    eps,
		MaxRetries:   5,
		RetryBackoff: 2 * time.Second,
		WAFTimeout:   300 * time.Second,
		listCacheTTL: listCacheTTLFromEnv(),
	}
}

// ── 底层请求 ──────────────────────────────────────────

func (p *DasCTFPlatform) doRequest(ctx context.Context, method, endpointKey string, body interface{}) ([]byte, int, error) {
	path, ok := p.Endpoints[endpointKey]
	if !ok {
		return nil, 0, fmt.Errorf("未知端点: %s", endpointKey)
	}
	return p.doRequestURL(ctx, method, path, body)
}

// doRequestURL 与 doRequest 同一条治理通道，但接受原始路径（用于带查询参数的端点，
// 如 challenge_detail?exerciseId=xx）——确保重试/429 计数/WAF 冷却对详情请求同样生效。
func (p *DasCTFPlatform) doRequestURL(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	if p.BaseURL == "" {
		return nil, 0, fmt.Errorf("平台 BaseURL 未配置（设置 DASCTF_BASE_URL 环境变量）")
	}
	url := p.BaseURL + path

	// ⑤ WAF 冷却冻结检查（403 命中后冷却期内所有平台请求直接跳过，避免雪崩）
	if secs := p.WafBlockedSeconds(); secs > 0 {
		return nil, 0, fmt.Errorf("WAF 风控冷却中(剩余 %.0fs)，跳过平台请求", secs)
	}

	maxRetries := p.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}
	backoff := p.RetryBackoff
	if backoff <= 0 {
		backoff = 2 * time.Second
	}

	var lastErr error
	var lastStatus int
	var retryAfter string // 上一次可重试响应携带的 Retry-After
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := p.sleepCtx(ctx, computeBackoff(backoff, attempt, retryAfter)); err != nil {
				return nil, lastStatus, err
			}
		}
		var reqBody io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, 0, fmt.Errorf("序列化请求体失败: %w", err)
			}
			reqBody = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return nil, 0, fmt.Errorf("创建请求失败: %w", err)
		}
		if p.Token != "" {
			req.Header.Set("X-Agent-AccessKey", p.Token)
		}
		// 与真源完全一致：所有请求（含 GET）都带 Content-Type 与浏览器 UA。
		//
		// UA 尤其关键：Go 默认的 "Go-http-client/1.1" 是典型 WAF 拦截特征，
		// 真源（Python）初赛中正是因请求特征被平台判「疑似攻击行为」403 封禁，
		// 才加了浏览器 UA。这种差异不会在功能测试里暴露，只会在赛时静默触发——
		// 由 request_golden_test.go 的双语言比对兜住。
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", defaultUserAgent)
		resp, err := p.HTTPClient.Do(req)
		if err != nil {
			// 网络异常：退避后重试（fail-open，不抛 panic）
			lastErr = err
			lastStatus = 0
			p.setLastError(fmt.Sprintf("%v", err))
			continue
		}
		data, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			lastStatus = resp.StatusCode
			p.setLastError(fmt.Sprintf("读取响应失败: %v", rerr))
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated:
			// 请求成功 → 重置连续 429 计数（退避阶梯在成功后自然回落）
			p.resetConsec429()
			return data, resp.StatusCode, nil
		case http.StatusForbidden:
			// ⑤ 403 WAF 风控（初赛高频轮询触发「疑似攻击行为」封禁的根因）：冻结请求
			cooldown := p.wafTimeout()
			p.mu.Lock()
			p.wafBlockedUntil = time.Now().Add(cooldown)
			p.mu.Unlock()
			msg := fmt.Sprintf("平台 403 WAF 风控（冷却 %s）", cooldown)
			p.setLastError(msg)
			return nil, resp.StatusCode, fmt.Errorf("%s", msg)
		case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			// ② 可重试状态码：指数退避 + 尊重 Retry-After；429 时累加连续计数
			if resp.StatusCode == http.StatusTooManyRequests {
				p.incConsec429()
			}
			retryAfter = resp.Header.Get("Retry-After")
			lastStatus = resp.StatusCode
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			p.setLastError(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 200)))
			continue
		default:
			p.setLastError(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 200)))
			return nil, resp.StatusCode, fmt.Errorf("平台返回 HTTP %d, body=%s", resp.StatusCode, string(data))
		}
	}
	return nil, lastStatus, fmt.Errorf("平台请求重试耗尽(%d次): %v", maxRetries, lastErr)
}

// computeBackoff 计算单次重试等待（对齐西湖论剑 dasctf.py：Retry-After 优先；
// 否则 retryBackoff * 2^attempt；单次上限 15s，快速失败交还轮询层统一控速）。
func computeBackoff(retryBackoff time.Duration, attempt int, retryAfter string) time.Duration {
	if retryBackoff <= 0 {
		retryBackoff = 2 * time.Second
	}
	if retryAfter != "" {
		if secs, err := strconv.ParseFloat(strings.TrimSpace(retryAfter), 64); err == nil && secs > 0 {
			return time.Duration(secs * float64(time.Second))
		}
	}
	wait := retryBackoff * time.Duration(1<<uint(attempt))
	if wait > 15*time.Second {
		return 15 * time.Second
	}
	return wait
}

// truncate 截断字符串到 n 字节（安全，不 panic）。
func truncate(s string, n int) string {
	b := []byte(s)
	if len(b) > n {
		return string(b[:n])
	}
	return s
}

// ── 官方协议适配（对齐西湖论剑 dasctf.py，决赛提交契约）─────────
//
// 三条官方手册契约（错一条即 0 分）：
//  1. 提交 body 键为 flag（非 answer）：{"exerciseId":1001,"flag":"example"}
//  2. 「提交时仅需提交 {} 内内容」→ 必须剥离 flag{}/DASCTF{} 外壳
//  3. 成功判据 = code=="00000"（字符串）且 data.isCorrect==true

// flagWrapperRe 与真源**逐字对齐**（dasctf.py `_FLAG_WRAPPER_RE`）：
//
//	真源 = ^(?:flag|FLAG|ctf|CTF|DASCTF|dasctf)\{(.+)\}$   （枚举大小写 + DOTALL）
//
// 这里刻意**不用** `(?i)`：混合大小写外壳（`Flag{}` / `Ctf{}` / `Dasctf{}`）真源不剥壳，
// Go 侧若忽略大小写就会单边"更宽容"，与真源分叉（2026-09-13 深度复检实测 7/25 用例分叉）。
// 铁律：目标侧偏离真源一律按缺陷处理。
var flagWrapperRe = regexp.MustCompile(`(?s)^(?:flag|FLAG|ctf|CTF|DASCTF|dasctf)\{(.+)\}$`)

// 预编译正则（避免每次解析题目重复编译）。
var (
	// bareCategoryRe 匹配 "CRYPTO-32" 这类纯题型-编号标识符标题（对解题无用）。
	// ⚠️ 必须与 Python 真源 _parse_challenge 的
	// `^(web|crypto|misc|reverse|pwn)[-_ ]?\d+$` 完全一致：
	// 早期版本自行扩展了 rev/re 分支，导致 "re-01" 被误判为裸标识符 →
	// description 不兜底（真源会兜底），双语言 golden 已固化该差异。
	bareCategoryRe = regexp.MustCompile(`(?i)^(web|crypto|misc|reverse|pwn)[-_ ]?\d+$`)
	// urlRe 用于从描述中提取附件 URL。
	urlRe = regexp.MustCompile(`https?://\S+`)
)

// defaultFlagFormat 与真源 ChallengeInfo.flag_format 默认值一致；
// 题面未给格式提示时使用（下游据此生成/校验 flag 外壳）。
const defaultFlagFormat = `flag\{[^}]+\}`

// realWebKeywords REAL-xx 系列附件名里的 CMS/中间件/数据库关键字。
// 与真源 _parse_challenge 的 _web_keywords 逐项一致——这类题实为 web 源码审计，
// 但标题只写 "REAL-16"（不含 web 字样），只能靠附件名判型。
var realWebKeywords = []string{
	"joomla", "wordpress", "drupal", "ghost", "cmsms", "nginx",
	"httpd", "apache", "openlitespeed", "caddy", "openresty",
	"mysql", "postgresql", "redis", "mongodb", "clickhouse",
	"mariadb", "sqlite", "mssql", "oracle", "elasticsearch",
	"01_", "02_", "03_", "04_", "05_", "06_", "07_", "08_", "09_", "10_",
}

// StripFlagWrapper 按官方手册剥离 flag{}/DASCTF{} 外壳，仅提交花括号内内容。
//
//	"flag{synthetic_case}"   → "synthetic_case"
//	"DASCTF{abc-123}"        → "abc-123"
//	"raw_value_no_braces"    → "raw_value_no_braces"（无外壳原样返回）
//
// 内部为空时回退原值（异常情况，宁可提交原样也不要提交空串）。
func StripFlagWrapper(flag string) string {
	f := strings.TrimSpace(flag)
	if m := flagWrapperRe.FindStringSubmatch(f); m != nil {
		if inner := strings.TrimSpace(m[1]); inner != "" {
			return inner
		}
	}
	return f
}

// exerciseIDValue 官方 API 的 exerciseId 为数值型；纯数字 ID 转 int 提交，
// 非数字（个别平台题号）原样透传，避免像 Python 版那样抛错中断提交。
func exerciseIDValue(challengeID string) interface{} {
	if n, err := strconv.Atoi(strings.TrimSpace(challengeID)); err == nil {
		return n
	}
	return challengeID
}

// codeIsSuccess 判定平台业务码是否成功。
// 严格对齐真源（dasctf.py:562 `ok_code = str(data.get("code", "")) == "00000"`）：
// **只认字符串 "00000"**。曾对 int/string 双兼容（`0`、`"0"` 也判成功），属目标侧单边放宽，
// 于 2026-09-13 深度复检按「目标侧偏离真源一律按缺陷处理」回退。
func codeIsSuccess(raw json.RawMessage) bool {
	s := strings.TrimSpace(strings.Trim(string(raw), `"`))
	return s == "00000"
}

// parseChallenge 把平台返回的题目对象解析为 Challenge（字段名多版本兼容）。
// 真源：列表项字段为 id/name/title/description/desc/category/type，
// 题型常缺失，需从 "CRYPTO-01" 这类标题前缀归一化。
func parseChallenge(raw json.RawMessage) Challenge {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		// 兼容直接是标量的异常结构
		var ch Challenge
		_ = json.Unmarshal(raw, &ch)
		return ch
	}

	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				var s string
				if json.Unmarshal(v, &s) == nil && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
				var num json.Number
				if json.Unmarshal(v, &num) == nil {
					return num.String()
				}
			}
		}
		return ""
	}

	ch := Challenge{}
	// ID 取第一个「真值」候选（0/""/null/false 会被跳过，对齐真源的 `or` 取值链）。
	// str 已兼容字符串/数字两种 id 表示（json.Number 分支）。
	ch.ID = str("id", "code", "challenge_id", "exerciseId")

	// rawTitle 是**兜底前**的原始标题。判 description 是否兜底时必须用它——
	// 真源用的是 item["title"] 原值；若误用兜底后的 ch.Title（可能是 id），
	// 会把 "1014" 这类纯 id 当成题面写进 description，污染下游解题输入。
	rawTitle := str("title", "name")
	ch.Title = rawTitle
	if ch.Title == "" {
		ch.Title = ch.ID
	}
	ch.Description = str("description", "desc")
	// 纯标识符标题（如 "CRYPTO-32"）对解题无用且会破坏 no-data 快速止损，
	// 故仅对"描述性标题"兜底；与真源 _parse_challenge 一致。
	if ch.Description == "" && rawTitle != "" && !bareCategoryRe.MatchString(rawTitle) {
		ch.Description = rawTitle
	}

	// 题型归一化（严格对齐真源：先 category/title 关键字，再 REAL-xx 附件名判型）。
	// 早期版本在此额外加过 pwn/exploit/re- 同义词分支，会把 "re-01" 判成 reverse
	// 而真源判 misc——偏离真源即偏离实战验证过的行为，已移除。
	catRaw := strings.ToLower(str("category", "type"))
	titleRaw := strings.ToLower(rawTitle)

	// 附件名辅助判型（REAL-xx 系列：附件名含 CMS/中间件/数据库名 → web 源码审计）
	attName := ""
	if v, ok := m["attachment"]; ok {
		var att struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(v, &att) == nil {
			attName = strings.ToLower(att.Name)
		}
	}
	if attName == "" {
		// P0 数据链路：大文件题的附件 URL 直接放在 description 里
		if u := urlRe.FindString(ch.Description); u != "" {
			if i := strings.LastIndex(u, "/"); i >= 0 && i+1 < len(u) {
				attName = strings.ToLower(u[i+1:])
			}
		}
	}
	ch.Category = "misc"
	for _, c := range []string{"web", "crypto", "misc", "reverse", "pwn"} {
		if strings.Contains(catRaw, c) || strings.Contains(titleRaw, c) {
			ch.Category = c
			break
		}
	}
	if ch.Category == "misc" && strings.HasPrefix(titleRaw, "real-") {
		for _, kw := range realWebKeywords {
			if strings.Contains(attName, kw) {
				ch.Category = "web"
				break
			}
		}
	}

	// 附件判定（真源条件全集；漏掉 attachments/file 会让附件题判成无附件 → 不下载 → 无输入）
	ch.HasAttachment = jsonTruthy(m["has_attachment"]) || jsonTruthy(m["has_file"]) ||
		jsonTruthy(m["file"]) || attachmentHasPayload(m["attachment"]) ||
		isNonEmptyList(m["attachments"]) || urlRe.MatchString(ch.Description)

	// 提取附件下载 URL（供 DownloadAttachment 使用；DASCTF 把 URL 嵌在详情 JSON 里，无独立下载 API）
	ch.AttachmentURLs = extractAttachmentURLs(m, ch.Description)

	// 分值：score 优先，其次 points（真源 `_safe_int(score or points or 0)`）。
	// 官方可能返回 "50.0"/"200" 这类字符串，故走 safeInt 而非直接 Unmarshal 到 int。
	ch.Score = safeInt(rawTruthy(m, "score", "points"))

	// 实例类题目（endpoints 非空，或平台显式标记需起靶机）。
	// 漏判 → 不起靶机 → 实例题完全无输入，必然解不出。
	ch.HasInstance = jsonTruthy(m["has_instance"]) || jsonTruthy(m["need_instance"]) ||
		jsonTruthy(m["isNeedInit"]) || isNonEmptyList(m["endpoints"])

	// flag 格式提示；题面未给时用真源默认值（下游据此校验/生成外壳）
	ch.FlagFormat = str("flag_format", "flag_pattern")
	if ch.FlagFormat == "" {
		ch.FlagFormat = defaultFlagFormat
	}
	// 原始字段留存（供上层审计/扩展，不丢信息）
	ch.Extra = make(map[string]interface{}, len(m))
	for k, v := range m {
		var any interface{}
		if json.Unmarshal(v, &any) == nil {
			ch.Extra[k] = any
		}
	}
	return ch
}

// jsonTruthy 判定 JSON 值在 Python 语义下是否为真（None/False/0/""/[]/{} 为假）。
// 真源大量使用 `a or b or c` 取值链，Go 侧必须复刻该语义，否则 0/"" 会被误当有效值。
func jsonTruthy(v json.RawMessage) bool {
	if len(v) == 0 {
		return false
	}
	var any interface{}
	if err := json.Unmarshal(v, &any); err != nil || any == nil {
		return false
	}
	switch x := any.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return strings.TrimSpace(x) != ""
	case []interface{}:
		return len(x) > 0
	case map[string]interface{}:
		return len(x) > 0
	}
	return true
}

// rawTruthy 按候选键顺序返回第一个「真值」的原始 JSON（Python `a or b or c` 语义）。
func rawTruthy(m map[string]json.RawMessage, keys ...string) json.RawMessage {
	for _, k := range keys {
		if v, ok := m[k]; ok && jsonTruthy(v) {
			return v
		}
	}
	return nil
}

// safeInt 复刻真源 _safe_int：int(float(value))，失败返回 0。
// 官方 score 可能返回 "50.0" 这类字符串，直接 Unmarshal 到 int 会失败归零。
func safeInt(v json.RawMessage) int {
	if len(v) == 0 {
		return 0
	}
	var f float64
	if err := json.Unmarshal(v, &f); err == nil {
		return int(f)
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		if f2, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
			return int(f2)
		}
	}
	return 0
}

// attachmentHasPayload 判定 attachment 字段是否携带实际附件（真源形态全集：
// 字符串 URL、含 url/downloadUrl/src/path/files 的对象、非空列表）。
func attachmentHasPayload(v json.RawMessage) bool {
	if len(v) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return strings.TrimSpace(s) != ""
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(v, &obj) == nil {
		for _, k := range []string{"url", "downloadUrl", "src", "path", "file_url", "download_url", "files"} {
			if jsonTruthy(obj[k]) {
				return true
			}
		}
		return false
	}
	return isNonEmptyList(v)
}

// isNonEmptyList 判定 JSON 值是否为非空数组。
func isNonEmptyList(v json.RawMessage) bool {
	if len(v) == 0 {
		return false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(v, &arr); err != nil {
		return false
	}
	return len(arr) > 0
}

// flattenChallenges 展平官方列表结构。
// 真源结构：data = [{id,name,order,corpus:[{id,name,order,isOpen,hasSolved}]}]
// ——分类容器内嵌 corpus，若直接按扁平数组解析会静默得到"有题但无题面"的假列表。
//
// 返回值 ok 区分「不是数组/解析失败」(false) 与「合法空列表」(true, len=0)：
// 后者是赛前放题窗口的正常状态，必须标记 lastListOK=true 而非当故障。
func flattenChallenges(data json.RawMessage) (list []Challenge, ok bool) {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, false
	}
	out := make([]Challenge, 0, len(entries))
	for _, e := range entries {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(e, &probe); err != nil {
			continue
		}
		if corpus, hasCorpus := probe["corpus"]; hasCorpus {
			// 分类容器：只取 corpus 内题目（空 corpus = 该批次未放题）
			var items []json.RawMessage
			if json.Unmarshal(corpus, &items) == nil {
				for _, it := range items {
					out = append(out, parseChallenge(it))
				}
			}
			continue
		}
		out = append(out, parseChallenge(e))
	}
	return out, true
}

// ── 平台 API 实现 ─────────────────────────────────────

// ListChallenges 拉取题目列表。
func (p *DasCTFPlatform) ListChallenges(ctx context.Context) ([]Challenge, error) {
	// ⑥ 列表 TTL 缓存：轮询循环每轮都调 exercise-list，赛时 429 风暴根因之一。
	// TTL 内直接复用，拉取到 0 道题时也不重复请求。
	p.mu.Lock()
	if p.listCache != nil && time.Since(p.listCacheAt) < p.listCacheTTL {
		cached := p.listCache
		p.mu.Unlock()
		return cached, nil
	}
	p.mu.Unlock()

	data, status, err := p.doRequest(ctx, "GET", "challenges", nil)
	if err != nil {
		p.setLastListOK(false)
		return nil, err
	}
	if status != http.StatusOK {
		p.setLastListOK(false)
		return nil, fmt.Errorf("拉取题目列表失败: HTTP %d, body=%s", status, string(data))
	}
	// 解析响应（平台返回格式：{"code":"00000","data":[{...,"corpus":[...]}]}）
	var resp struct {
		Code json.RawMessage `json:"code"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		p.setLastListOK(false)
		return nil, fmt.Errorf("解析题目列表失败: %w", err)
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		// data 缺失时容忍 msg 报错（部分平台 200 包业务错误码）
		if !codeIsSuccess(resp.Code) && resp.Msg != "" {
			p.setLastListOK(false)
			return nil, fmt.Errorf("平台返回错误: code=%s, msg=%s", string(resp.Code), resp.Msg)
		}
	}

	// 展平 corpus 嵌套结构；失败时兼容 {"list":[...]} 包裹格式
	challenges, ok := flattenChallenges(resp.Data)
	if !ok {
		var wrapped struct {
			List []json.RawMessage `json:"list"`
		}
		if json.Unmarshal(resp.Data, &wrapped) == nil {
			challenges = make([]Challenge, 0, len(wrapped.List))
			for _, it := range wrapped.List {
				challenges = append(challenges, parseChallenge(it))
			}
			ok = true
		}
	}
	if !ok {
		p.setLastListOK(false)
		return nil, fmt.Errorf("解析题目数据失败（原始: %s）", truncate(string(resp.Data), 200))
	}
	p.setLastListOK(true)
	p.mu.Lock()
	p.listCache = challenges
	p.listCacheAt = time.Now()
	p.mu.Unlock()
	p.Logger.Info("拉取题目列表成功", zap.Int("count", len(challenges)))
	return challenges, nil
}

// GetChallenge 获取单题详情。
//
// 走 doRequest（而非裸 HTTP）：否则 ②重试 ③429 计数 ⑤WAF 冷却对详情请求不生效，
// 「WAF 期间冻结所有平台请求」的治理承诺即为假。
func (p *DasCTFPlatform) GetChallenge(ctx context.Context, challengeID string) (*Challenge, error) {
	// 详情端点需 exerciseId 查询参数，故独立拼 URL 后借用同一治理通道
	data, status, err := p.doRequestURL(ctx, "GET",
		p.Endpoints["challenge_detail"]+"?exerciseId="+challengeID, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("获取题目详情失败: HTTP %d", status)
	}
	var resp struct {
		Code json.RawMessage `json:"code"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("解析题目详情失败: %w", err)
	}
	if !codeIsSuccess(resp.Code) && resp.Msg != "" {
		return nil, fmt.Errorf("平台返回错误: code=%s, msg=%s", string(resp.Code), resp.Msg)
	}
	// data 为空时容忍（返回仅带 ID 的骨架，避免上层 nil 解引用）
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return &Challenge{ID: challengeID, Category: "misc"}, nil
	}
	ch := parseChallenge(resp.Data)
	if ch.ID == "" {
		ch.ID = challengeID
	}
	return &ch, nil
}

// CreateInstance 启动题目环境/容器。
func (p *DasCTFPlatform) CreateInstance(ctx context.Context, challengeID string) (*Instance, error) {
	// 官方文档：body={"exerciseId":1001}（数值型）
	body := map[string]interface{}{"exerciseId": exerciseIDValue(challengeID)}
	data, status, err := p.doRequest(ctx, "POST", "build_env", body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, fmt.Errorf("启动环境失败: HTTP %d, body=%s", status, string(data))
	}
	var resp struct {
		Code json.RawMessage `json:"code"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("解析实例信息失败: %w", err)
	}
	if !codeIsSuccess(resp.Code) && resp.Msg != "" {
		return nil, fmt.Errorf("平台返回错误: code=%s, msg=%s", string(resp.Code), resp.Msg)
	}
	inst := &Instance{}
	// instance_id 可能在 data.instance_id / data.id，或 data 直接是字符串
	var m map[string]json.RawMessage
	if json.Unmarshal(resp.Data, &m) == nil {
		for _, k := range []string{"instance_id", "instanceId", "id"} {
			if v, ok := m[k]; ok {
				var s string
				if json.Unmarshal(v, &s) == nil && s != "" {
					inst.InstanceID = s
					break
				}
				var n json.Number
				if json.Unmarshal(v, &n) == nil {
					inst.InstanceID = n.String()
					break
				}
			}
		}
		if v, ok := m["status"]; ok {
			_ = json.Unmarshal(v, &inst.Status)
		}
	} else {
		var s string
		if json.Unmarshal(resp.Data, &s) == nil {
			inst.InstanceID = s
		}
	}
	if inst.InstanceID == "" {
		inst.InstanceID = challengeID // 兜底：部分平台用题号当实例号
	}
	p.Logger.Info("环境启动成功", zap.String("instance_id", inst.InstanceID))
	return inst, nil
}

// GetAccess 获取实例访问信息。
//
// 注意（真源踩坑记录）：DasCTF 的靶机地址不在 build_env 返回里，而在
// challenge_detail 的 endpoints[].exposeIps[0]（"ip:port"）中。原 Python 实现
// 曾把 instanceID 传给需要 exerciseId 的端点，导致"访问地址永远取空"。
// 本实现要求传入 exerciseId（题号），并从详情提取 endpoints。
func (p *DasCTFPlatform) GetAccess(ctx context.Context, instanceID string) (*Access, error) {
	data, status, err := p.doRequestURL(ctx, "GET",
		p.Endpoints["challenge_detail"]+"?exerciseId="+instanceID, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("获取靶机地址失败: HTTP %d", status)
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("解析靶机地址失败: %w", err)
	}
	acc := extractAccess(resp.Data)
	if acc == nil {
		return &Access{}, fmt.Errorf("题目 %s 详情中未找到 endpoints（该题可能无需靶机）", instanceID)
	}
	return acc, nil
}

// extractAccess 从题目详情中提取靶机访问信息（对齐真源 exposeIps/proxyIps 优先级）。
func extractAccess(detail json.RawMessage) *Access {
	var d struct {
		Endpoints []struct {
			Name      string   `json:"name"`
			ExposeIPs []string `json:"exposeIps"`
			ProxyIPs  []string `json:"proxyIps"`
			Ports     []string `json:"ports"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(detail, &d); err != nil || len(d.Endpoints) == 0 {
		return nil
	}
	for _, ep := range d.Endpoints {
		if len(ep.ExposeIPs) > 0 && ep.ExposeIPs[0] != "" {
			host, portStr, _ := strings.Cut(ep.ExposeIPs[0], ":")
			port := 80
			if portStr != "" {
				if n, err := strconv.Atoi(portStr); err == nil {
					port = n
				}
			}
			return &Access{
				Host: host, Port: port,
				URL: "http://" + ep.ExposeIPs[0],
				EntryPoints: []EntryPoint{
					{Name: ep.Name, Host: host, Port: port, Type: "web"},
				},
			}
		}
		if len(ep.ProxyIPs) > 0 && ep.ProxyIPs[0] != "" {
			host := ep.ProxyIPs[0]
			port := 80
			// ports 形如 ["tcp/8080"]，取最后一段
			for _, ps := range ep.Ports {
				if i := strings.LastIndex(ps, "/"); i >= 0 {
					if n, err := strconv.Atoi(ps[i+1:]); err == nil {
						port = n
					}
					break
				}
			}
			url := "http://" + host
			if port != 80 {
				url = fmt.Sprintf("http://%s:%d", host, port)
			}
			return &Access{
				Host: host, Port: port, URL: url,
				EntryPoints: []EntryPoint{
					{Name: ep.Name, Host: host, Port: port, Type: "web"},
				},
			}
		}
	}
	return nil
}

// DownloadAttachment 下载题目附件，返回本地路径列表。
//
// 实现（2026-10-08 解存根）：DASCTF 平台把附件 URL 嵌在题目详情 JSON 里（attachment/attachments/file
// 字段），无独立下载 API。故本函数先经 GetChallenge 取回详情（parseChallenge 已把 URL 抽到
// Challenge.AttachmentURLs），再逐个 HTTP GET 落到 `<cwd>/chat_uploads/ctf/<题号>/` 白名单之下，
// 返回本地绝对路径。
//
// 契约（与 poller.fetchAttachments 下游一致）：
//   - 文件落在 chat_uploads/ 之下 —— Presolve 的 loadChatAttachmentFiles 只读该目录（防任意文件读）；
//   - 返回本地绝对路径列表。
//
// 🔴 **诚实标注**：本机无官方凭证、无法真机联调，URL 字段名基于既有 HasAttachment 判定
//    （attachment/attachments/file + url/downloadUrl/src/file_url/download_url/files）推断。
//    若决赛真机字段命名不同，需在此微调 extractAttachmentURLs（单测覆盖提取逻辑，整链真机验证留决赛前）。
//    任何失败一律返回 (nil, nil) —— 保持「无附件」语义，不阻断求解。
func (p *DasCTFPlatform) DownloadAttachment(ctx context.Context, challengeID string) ([]string, error) {
	ch, err := p.GetChallenge(ctx, challengeID)
	if err != nil || ch == nil {
		p.Logger.Debug("取题目详情失败，无法下载附件", zap.String("challenge_id", challengeID), zap.Error(err))
		return nil, nil
	}
	if len(ch.AttachmentURLs) == 0 {
		p.Logger.Debug("题目无附件 URL", zap.String("challenge_id", challengeID))
		return nil, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		p.Logger.Warn("获取工作目录失败，附件下载跳过", zap.Error(err))
		return nil, nil
	}
	root := filepath.Join(cwd, "chat_uploads", "ctf", challengeID)
	if err := os.MkdirAll(root, 0o755); err != nil {
		p.Logger.Warn("创建附件目录失败", zap.String("dir", root), zap.Error(err))
		return nil, nil
	}

	paths, err := downloadURLsToDir(ctx, p.HTTPClient, ch.AttachmentURLs, root)
	if err != nil {
		p.Logger.Warn("附件下载未完成", zap.String("challenge_id", challengeID), zap.Error(err))
	}
	return paths, nil
}

// downloadURLsToDir 把一组 http/https URL 下载到 dir 下，返回成功落盘的本地绝对路径。
// 安全约束：仅接受 http/https 绝对 URL；文件名只取 URL 的 base name 防路径穿越；
// 单文件上限 256MB 防失控。任一 URL 失败仅记日志跳过，不影响其余。
func downloadURLsToDir(ctx context.Context, client *http.Client, urls []string, dir string) ([]string, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	var out []string
	for _, u := range urls {
		parsed, perr := url.Parse(u)
		if perr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		base := filepath.Base(parsed.Path)
		if base == "" || base == "." || base == "/" {
			base = "attachment.bin"
		}
		// 防穿越：只用 base name，且最终路径必须仍在 dir 内
		local := filepath.Join(dir, base)
		if !strings.HasPrefix(filepath.Clean(local), filepath.Clean(dir)) {
			continue
		}

		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if rerr != nil {
			continue
		}
		resp, derr := client.Do(req)
		if derr != nil {
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return
			}
			f, ferr := os.Create(local)
			if ferr != nil {
				return
			}
			defer f.Close()
			if _, cerr := io.CopyN(f, resp.Body, 256<<20); cerr != nil && cerr != io.EOF {
				return
			}
		}()
		if fi, serr := os.Stat(local); serr == nil && fi.Size() > 0 {
			out = append(out, local)
		}
	}
	return out, nil
}

// appendAttachmentURLs 把单个详情字段值（字符串 / 对象 / 列表）里的附件 URL 追加到 urls。
// 字符串直接取；对象取 url/downloadUrl/src/path/file_url/download_url/files 之一；列表递归展开。
func appendAttachmentURLs(urls *[]string, v json.RawMessage) {
	if len(v) == 0 {
		return
	}
	var s string
	if json.Unmarshal(v, &s) == nil && strings.TrimSpace(s) != "" {
		*urls = append(*urls, strings.TrimSpace(s))
		return
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(v, &obj) == nil {
		for _, k := range []string{"url", "downloadUrl", "src", "path", "file_url", "download_url", "files"} {
			if sv, ok := obj[k]; ok {
				var ss string
				if json.Unmarshal(sv, &ss) == nil && strings.TrimSpace(ss) != "" {
					*urls = append(*urls, strings.TrimSpace(ss))
				}
			}
		}
		return
	}
	var arr []json.RawMessage
	if json.Unmarshal(v, &arr) == nil {
		for _, item := range arr {
			appendAttachmentURLs(urls, item)
		}
	}
}

// extractAttachmentURLs 从题目详情字段提取附件下载 URL（DASCTF 形态全集）。
// 覆盖：attachment（对象含 url/downloadUrl/src/file_url/download_url/files 或字符串）、
// attachments（列表，每项对象/字符串）、file（字符串 URL）、description 里的 URL。
func extractAttachmentURLs(m map[string]json.RawMessage, description string) []string {
	var urls []string
	appendAttachmentURLs(&urls, m["attachment"])
	appendAttachmentURLs(&urls, m["attachments"])
	appendAttachmentURLs(&urls, m["file"])
	if description != "" {
		for _, u := range urlRe.FindAllString(description, -1) {
			u = strings.TrimSpace(u)
			if u != "" {
				urls = append(urls, u)
			}
		}
	}
	return urls
}

// SubmitFlag 提交 flag。
//
// 官方手册契约（错一条即丢分）：
//   - body 键名为 flag（非 answer）：{"exerciseId":1001,"flag":"example"}
//   - 「提交时仅需提交 {} 内内容」→ 剥离 flag{}/DASCTF{} 外壳（每题仅 ~50 次提交机会，
//     带外壳提交等于浪费机会）
//   - exerciseId 为数值型
func (p *DasCTFPlatform) SubmitFlag(ctx context.Context, challengeID string, flag string) (*SubmitResult, error) {
	body := map[string]interface{}{
		"exerciseId": exerciseIDValue(challengeID),
		"flag":       StripFlagWrapper(flag),
	}
	data, status, err := p.doRequest(ctx, "POST", "submit", body)
	if err != nil {
		// 提交请求层失败（HTTP 4xx/5xx/网络/鉴权）真实暴露，不再笼统吞掉——
		// 区分「请求故障」与「flag 错误」，避免正确 flag 因平台抖动被静默丢弃。
		detail := p.LastError()
		if strings.TrimSpace(detail) == "" {
			detail = err.Error()
		}
		return &SubmitResult{RequestFailed: true, Detail: "提交请求失败（真实错误）: " + detail}, err
	}
	result := &SubmitResult{}
	if status != http.StatusOK && status != http.StatusCreated {
		result.RequestFailed = true
		result.Detail = fmt.Sprintf("HTTP %d: %s", status, truncate(string(data), 200))
		return result, fmt.Errorf("提交失败: HTTP %d", status)
	}
	var resp struct {
		Code    json.RawMessage `json:"code"`
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message"`
		Msg     string          `json:"msg"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		// 用 truncate 而非 string(data)[:200]——后者在响应 <200 字节时直接 panic
		result.Detail = fmt.Sprintf("解析失败: %s", truncate(string(data), 200))
		return result, nil
	}
	// 响应 data 段（与请求体 body 区分命名，避免同作用域重名）
	var subData struct {
		IsCorrect         bool   `json:"isCorrect"`
		Correct           bool   `json:"correct"` // 兼容老字段
		Message           string `json:"message"`
		Detail            string `json:"detail"`
		RemainingAttempts *int   `json:"remainingAttempts"`
	}
	if len(resp.Data) > 0 && string(resp.Data) != "null" {
		// 宽容解析：data 非对象（数组/字符串）时忽略即可，不判失败
		_ = json.Unmarshal(resp.Data, &subData)
	}
	okCode := codeIsSuccess(resp.Code)
	isCorrect := subData.IsCorrect || subData.Correct
	// 官方语义：accepted = 业务码成功 且 isCorrect（真源 accepted = ok_code and is_correct）
	result.Accepted = okCode && isCorrect
	result.Correct = isCorrect
	if subData.RemainingAttempts != nil {
		result.RemainingAttempts = *subData.RemainingAttempts
	}
	for _, d := range []string{subData.Detail, subData.Message, resp.Message, resp.Msg} {
		if strings.TrimSpace(d) != "" {
			result.Detail = d
			break
		}
	}
	if !okCode {
		p.Logger.Warn("平台业务码非成功",
			zap.String("code", string(resp.Code)), zap.String("challenge_id", challengeID))
	}
	return result, nil
}

// ResetInstance 重置/回收题目环境。
//
// 官方按 exerciseId（题号）操作，不是 instanceId —— 真源踩坑记录：
// 传 instanceId 到需要 exerciseId 的端点会永远无效。故此处参数语义为题号。
func (p *DasCTFPlatform) ResetInstance(ctx context.Context, challengeID string) error {
	body := map[string]interface{}{"exerciseId": exerciseIDValue(challengeID)}
	_, status, err := p.doRequest(ctx, "POST", "recover_env", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("重置环境失败: HTTP %d", status)
	}
	return nil
}

// DestroyInstance 销毁实例。
func (p *DasCTFPlatform) DestroyInstance(ctx context.Context, challengeID string) error {
	return p.ResetInstance(ctx, challengeID) // 平台复用 recover 端点
}

// GetMatchInfo 获取竞赛规则/状态。
func (p *DasCTFPlatform) GetMatchInfo(ctx context.Context) (map[string]interface{}, error) {
	data, status, err := p.doRequest(ctx, "GET", "match_info", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("获取比赛信息失败: HTTP %d", status)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetOverview 获取得分排名。
func (p *DasCTFPlatform) GetOverview(ctx context.Context) (map[string]interface{}, error) {
	data, status, err := p.doRequest(ctx, "GET", "overview", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("获取排名失败: HTTP %d", status)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ── 抗打击治理访问器（供 Poller / 外部观测）────────────────

// wafTimeout 返回 403 冷却时长（默认 300s）。
func (p *DasCTFPlatform) wafTimeout() time.Duration {
	if p.WAFTimeout > 0 {
		return p.WAFTimeout
	}
	return 300 * time.Second
}

// setLastError 记录最近一次请求层失败详情。
func (p *DasCTFPlatform) setLastError(s string) {
	p.mu.Lock()
	p.lastError = s
	p.mu.Unlock()
}

// LastError 返回最近一次请求层失败详情。
func (p *DasCTFPlatform) LastError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastError
}

// setLastListOK 标记最近一次 ListChallenges 是否真实成功（HTTP 200，含空列表）。
func (p *DasCTFPlatform) setLastListOK(v bool) {
	p.mu.Lock()
	p.lastListOK = v
	p.mu.Unlock()
}

// LastListOK 返回最近一次 ListChallenges 是否真实成功（区分「0 道题」与「请求失败」）。
func (p *DasCTFPlatform) LastListOK() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastListOK
}

// incConsec429 累加并返回连续 429 次数。
func (p *DasCTFPlatform) incConsec429() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consec429++
	return p.consec429
}

// resetConsec429 成功后重置连续 429 计数（退避阶梯回落）。
func (p *DasCTFPlatform) resetConsec429() {
	p.mu.Lock()
	p.consec429 = 0
	p.mu.Unlock()
}

// Consec429 返回连续 429 次数。
func (p *DasCTFPlatform) Consec429() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.consec429
}

// BackoffSuggestion ④ 根据连续 429 次数给出建议轮询间隔（秒）；无 429 返回 0（不干预）。
// 阶梯：≥12→300s；≥8→120s；≥5→60s；≥3→30s；其余→0（由轮询层覆盖当前间隔）。
func (p *DasCTFPlatform) BackoffSuggestion(base float64) float64 {
	n := p.Consec429()
	switch {
	case n >= 12:
		return 300
	case n >= 8:
		return 120
	case n >= 5:
		return 60
	case n >= 3:
		return 30
	default:
		return 0
	}
}

// WafBlockedSeconds ⑤ 返回 WAF 冷却剩余秒数（>0 = 封禁中）；到期自动清零。
func (p *DasCTFPlatform) WafBlockedSeconds() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wafBlockedUntil.IsZero() {
		return 0
	}
	d := time.Until(p.wafBlockedUntil)
	if d <= 0 {
		p.wafBlockedUntil = time.Time{}
		return 0
	}
	return d.Seconds()
}

// sleepCtx 在 ctx 取消前休眠 d，用于退避等待。
func (p *DasCTFPlatform) sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// listCacheTTLFromEnv 读取列表缓存 TTL（默认 10s，可用 CTF_AGENT_LIST_TTL 覆盖）。
func listCacheTTLFromEnv() time.Duration {
	if v := strings.TrimSpace(os.Getenv("CTF_AGENT_LIST_TTL")); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 10 * time.Second
}

// Ensure DasCTFPlatform implements PlatformAPI
var _ PlatformAPI = (*DasCTFPlatform)(nil)
