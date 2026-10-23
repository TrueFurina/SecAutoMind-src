package ctfplatform

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveSensitiveFileRead 对真实靶场跑"非 flag 型打穿证据"探测。
//
// 默认 SKIP：只有显式设置 CTF4_LAB_URL 才执行，因此 CI 与日常全量测试不受影响。
//
// 用法（靶机由 scripts/ctf4_lab.sh start 拉起）：
//
//	CTF4_LAB_URL=http://127.0.0.1:8080/ go test -run TestLiveSensitiveFileRead -v ./internal/ctfplatform/
func TestLiveSensitiveFileRead(t *testing.T) {
	base := os.Getenv("CTF4_LAB_URL")
	if base == "" {
		t.Skip("未设 CTF4_LAB_URL，跳过真实靶场用例")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	eps, params := DiscoverWebParams(ctx, base)
	t.Logf("[discover] endpoints=%v params=%v", eps, params)

	start := time.Now()
	ev := ProbeSensitiveFileRead(ctx, base, WebHints{})
	t.Logf("[probe] elapsed=%v evidence=%d", time.Since(start).Round(time.Millisecond), len(ev))
	for i, e := range ev {
		t.Logf("  #%d kind=%s signal=%s param=%s payload=%s detail=%s",
			i+1, e.Kind, e.Signal, e.Param, e.Payload, e.Detail)
	}

	if len(ev) == 0 {
		t.Fatalf("真实靶场应至少检出 1 条敏感文件读取证据（0 条说明探测链没打通）")
	}
}

// TestLiveSQLError 对真实靶场跑"报错型 SQL 注入"探测。
// 同样默认 SKIP：只有设置 CTF4_LAB_URL 才执行。
func TestLiveSQLError(t *testing.T) {
	base := os.Getenv("CTF4_LAB_URL")
	if base == "" {
		t.Skip("未设 CTF4_LAB_URL，跳过真实靶场用例")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	start := time.Now()
	ev := ProbeSQLError(ctx, base, WebHints{})
	t.Logf("[sqli] elapsed=%v evidence=%d", time.Since(start).Round(time.Millisecond), len(ev))
	for i, e := range ev {
		t.Logf("  #%d kind=%s signal=%s url=%s param=%s payload=%s detail=%s",
			i+1, e.Kind, e.Signal, e.URL, e.Param, e.Payload, e.Detail)
	}

	if len(ev) == 0 {
		t.Fatalf("真实靶场应至少检出 1 条报错型 SQL 注入证据")
	}
}
