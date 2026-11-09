package gatewaycompliance

import "testing"

func TestOriginOf(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"https://gw.example.com/v1", "https://gw.example.com", false},
		{"https://gw.example.com/", "https://gw.example.com", false},
		{"http://127.0.0.1:18899/v1", "http://127.0.0.1:18899", false},
		{"gw.example.com/v1", "", true}, // 相对 URL：无 scheme
		{"", "", true},
	}
	for _, c := range cases {
		got, err := OriginOf(c.in)
		if c.wantErr != (err != nil) {
			t.Fatalf("OriginOf(%q) err=%v，期望 err=%v", c.in, err, c.wantErr)
		}
		if !c.wantErr && got != c.want {
			t.Fatalf("OriginOf(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestIsLoopbackOrigin(t *testing.T) {
	// 拍板口径（2026-11-09）：只认回环，不认任何公网 host。
	yes := []string{"http://127.0.0.1:18899", "http://localhost:11434", "http://[::1]:8080", "http://127.9.9.9"}
	no := []string{"https://api.deepseek.com", "https://kilo.example.com", "http://10.0.0.5:8080", "https://evil.example.com/127.0.0.1"}
	for _, o := range yes {
		if !IsLoopbackOrigin(o) {
			t.Errorf("IsLoopbackOrigin(%q) 应为 true", o)
		}
	}
	for _, o := range no {
		if IsLoopbackOrigin(o) {
			t.Errorf("IsLoopbackOrigin(%q) 应为 false（公网/内网非回环不豁免）", o)
		}
	}
}

func TestViolation(t *testing.T) {
	gw := "https://gw.example.com"
	// 同源放行
	if v := Violation(gw, "qwen", "https://gw.example.com/v1"); v != "" {
		t.Fatalf("同源通道必须放行，实际违规文本：%q", v)
	}
	// 回环豁免放行（ofm/ollama 拍板口径）
	if v := Violation(gw, "ofm", "http://127.0.0.1:18899/v1"); v != "" {
		t.Fatalf("回环本地网关必须豁免，实际：%q", v)
	}
	// 公网直连拦截且点名
	v := Violation(gw, "deep", "https://api.deepseek.com/v1")
	if v == "" {
		t.Fatal("公网直连必须拦截")
	}
	if !contains(v, "deep") || !contains(v, "api.deepseek.com") {
		t.Fatalf("违规文本必须可定位（通道名+origin）：%q", v)
	}
	// 不可解析也判违规（fail-closed 取向：宁可拦不可放）
	if v := Violation(gw, "broken", "not-a-url"); v == "" {
		t.Fatal("不可解析的通道 base_url 必须判违规")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
