package ctfplatform

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestWebExploitNoFalsePositive 反误报护栏：对一个「看起来像靶机、但根本没有 flag」的
// 正常站点，Web 渗透引擎必须返回 0 命中——绝不能因为端点名/参数名对上了就编造 flag。
//
// 站点刻意提供 /login.php /cmd.php /index.php?page= 等「像漏洞」的端点，并返回
// 看似正常的错误页（"invalid credentials" / "command output"），但任何响应都不含
// flag 形状串。引擎即便被题目线索「定向引导」到这些端点，也应零命中。
func TestWebExploitNoFalsePositive(t *testing.T) {
	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch {
		case strings.Contains(r.URL.Path, "login"):
			// 像 SQLi 登录绕过，但不泄漏任何 flag
			_, _ = w.Write([]byte("<html><body><h1>Login</h1><p>invalid credentials, try again.</p></body></html>"))
		case strings.Contains(r.URL.Path, "cmd"):
			// 像命令注入，但只回显普通文本
			_, _ = w.Write([]byte("<html><body><pre>usage: cmd [options]\nno input provided</pre></body></html>"))
		case strings.Contains(r.URL.Path, "page"), strings.Contains(r.URL.Path, "profile"):
			_, _ = w.Write([]byte("<html><body><h2>Page</h2><p>welcome, guest.</p></body></html>"))
		default:
			_, _ = w.Write([]byte("<html><body><h1>Home</h1><nav><a href=\"/login.php\">login</a><a href=\"/cmd.php\">cmd</a></nav></body></html>"))
		}
	}))
	defer benign.Close()

	// 故意给出「误导性线索」：端点与靶场一模一样、类型全覆盖，逼引擎去打。
	hints := WebHints{
		Endpoints: []string{"/login.php", "/cmd.php", "/index.php?page=", "/profile?name="},
		Params:    []string{"user", "pass", "ip", "page", "name", "url"},
		Payloads:  []string{"admin' OR 1=1--", "{{7*7}}", "127.0.0.1;cat /flag", "../../etc/passwd"},
		Types:     []string{"sqli", "ssti", "lfi", "cmdi", "ssrf", "nosql"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	findings := ExploitWebTargetWithHints(ctx, benign.URL, hints)

	real := 0
	for _, f := range findings {
		if f.Flag != "" {
			real++
			t.Errorf("误报命中: %q (scene=%s)", f.Flag, f.Scene)
		}
	}
	if real != 0 {
		t.Fatalf("对无 flag 的正常靶机产生了 %d 个假命中——必须为零", real)
	}
	t.Logf("反误报通过：正常无 flag 靶机 → 0 命中（探测端点 %d 个）", len(hints.Endpoints))
}

// TestForensicsNoFalsePositiveOnRandom 反误报护栏：把 256KiB 真随机字节（非任何已知
// 格式）喂给取证扫描全变体，必须不产生任何 flag 形状命中。证明引擎不会把噪声当成 flag。
func TestForensicsNoFalsePositiveOnRandom(t *testing.T) {
	buf := make([]byte, 256*1024)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("生成随机字节失败: %v", err)
	}

	// 全变体扫描：原始 + UTF-16 + base64 + hex + 逆序 + 百分号解码
	hits := bfxScanVariants(buf)

	// bfxScanVariants 出口已被 flag 形状正则过滤，随机噪声命中必为 0。
	if len(hits) != 0 {
		t.Fatalf("随机字节竟产生 %d 个 flag 形状命中（应恒为 0）：%v", len(hits), hits[:min(5, len(hits))])
	}
	t.Logf("反误报通过：256KiB 随机字节 → 取证扫描 0 命中")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
