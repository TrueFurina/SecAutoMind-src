package ilink

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBuildClientVersion(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"1.2.3", 0x010203},
		{"0.0.1", 0x000001},
		{"1", 0x010000},
		{"1.2", 0x010200},
		{"10.20.30", (10 << 16) | (20 << 8) | 30},
		{"999.999.999", (231 << 16) | (231 << 8) | 231}, // 999 & 0xff == 231 (0xe7)
		{"-5.2.3", (0 << 16) | (2 << 8) | 3},            // negative parsed as 0
	}
	for _, c := range cases {
		if got := BuildClientVersion(c.in); got != c.want {
			t.Errorf("BuildClientVersion(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

func TestNewClientDefaults(t *testing.T) {
	c := NewClient("", "tok", "", 0)
	if c.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, DefaultBaseURL)
	}
	if c.BotAgent != DefaultBotAgent {
		t.Errorf("BotAgent = %q, want %q", c.BotAgent, DefaultBotAgent)
	}
	if c.BotToken != "tok" {
		t.Errorf("BotToken = %q", c.BotToken)
	}
	// trailing slash trimmed
	c2 := NewClient("https://example.com/", "tok", "Agent/9", 5)
	if c2.BaseURL != "https://example.com" {
		t.Errorf("BaseURL trailing slash not trimmed: %q", c2.BaseURL)
	}
	if c2.BotAgent != "Agent/9" {
		t.Errorf("BotAgent = %q", c2.BotAgent)
	}
}

func TestSanitizeBotAgent(t *testing.T) {
	if got := sanitizeBotAgent(""); got != DefaultBotAgent {
		t.Errorf("empty agent -> %q, want %q", got, DefaultBotAgent)
	}
	long := strings.Repeat("x", 300)
	if got := sanitizeBotAgent(long); len(got) != 256 {
		t.Errorf("long agent should be truncated to 256, got %d", len(got))
	}
	if got := sanitizeBotAgent("  spaced  "); got != "spaced" {
		t.Errorf("agent should be trimmed: %q", got)
	}
}

func TestCommonAndAuthHeaders(t *testing.T) {
	c := NewClient("https://example.com", "secret-token", "Agent/1", 0x010203)
	h := c.commonHeaders()
	if h.Get("iLink-App-Id") != ILinkAppID {
		t.Errorf("missing iLink-App-Id, got %q", h.Get("iLink-App-Id"))
	}
	if h.Get("iLink-App-ClientVersion") != "66051" {
		t.Errorf("ClientVersion header = %q, want 66051", h.Get("iLink-App-ClientVersion"))
	}
	ah := c.authHeaders()
	if ah.Get("Authorization") != "Bearer secret-token" {
		t.Errorf("auth header = %q, want Bearer secret-token", ah.Get("Authorization"))
	}
	if ah.Get("X-WECHAT-UIN") == "" {
		t.Error("X-WECHAT-UIN must be set (random)")
	}
	// empty token -> no Authorization header
	ce := NewClient("https://example.com", "", "Agent/1", 1)
	if ce.authHeaders().Get("Authorization") != "" {
		t.Error("empty token must not produce Authorization header")
	}
}

func TestEndpointURL(t *testing.T) {
	c := NewClient("https://example.com", "tok", "", 0)
	got, err := c.endpointURL("ilink/bot/sendmessage")
	if err != nil {
		t.Fatalf("endpointURL err: %v", err)
	}
	if got != "https://example.com/ilink/bot/sendmessage" {
		t.Errorf("endpointURL = %q", got)
	}
}

func TestGetQRCodeStatusCancelledCtx(t *testing.T) {
	c := NewClient("https://example.com", "tok", "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// cancelled ctx -> doRequest fails immediately, handler returns wait status
	out, err := c.GetQRCodeStatus(ctx, "qr123", "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.Status != "wait" {
		t.Errorf("status = %q, want wait", out.Status)
	}
}

func TestGetUpdatesCancelledCtx(t *testing.T) {
	c := NewClient("https://example.com", "tok", "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := c.GetUpdates(ctx, "buf")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.Ret != 0 {
		t.Errorf("Ret = %d, want 0", out.Ret)
	}
}

func TestQRCodeDataURL(t *testing.T) {
	if _, err := QRCodeDataURL("", 256); err == nil {
		t.Error("empty content should error")
	}
	url, err := QRCodeDataURL("https://liteapp.example.com/x", 0)
	if err != nil {
		t.Fatalf("QRCodeDataURL err: %v", err)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(url, prefix) {
		t.Errorf("data URL missing prefix: %q", url)
	}
	// decodeable base64
	b64 := strings.TrimPrefix(url, prefix)
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
		t.Errorf("payload not valid base64: %v", err)
	}
}

func TestExtractText(t *testing.T) {
	msg := WeixinMessage{ItemList: []MessageItem{
		{Type: 1, TextItem: &struct {
			Text string `json:"text"`
		}{Text: "  hello  "}},
	}}
	if got := ExtractText(msg); got != "hello" {
		t.Errorf("ExtractText = %q, want hello", got)
	}
	empty := WeixinMessage{ItemList: []MessageItem{{Type: 99}}}
	if got := ExtractText(empty); got != "" {
		t.Errorf("ExtractText should be empty for non-text item, got %q", got)
	}
}

func TestRandomIdentifiers(t *testing.T) {
	id := randomClientID()
	if len(id) != 16 {
		t.Errorf("randomClientID len = %d, want 16", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("randomClientID not hex: %v", err)
	}
	uin := randomWechatUIN()
	if _, err := base64.StdEncoding.DecodeString(uin); err != nil {
		t.Errorf("randomWechatUIN not base64: %v", err)
	}
}
