package audit

import (
	"testing"
	"time"

	"secautomind-ai/internal/database"
)

// ---------- SanitizeDetail (PII / secret redaction) ----------

func TestSanitizeDetailRedactsSensitive(t *testing.T) {
	in := map[string]interface{}{
		"username":      "alice",
		"password":      "s3cret",
		"api_key":       "AKIA123",
		"secret":        "top",
		"token":         "abc.def",
		"authorization": "Bearer xyz",
		"note":          "public info",
	}
	out := SanitizeDetail(in, 0)
	if out["password"] != "***" {
		t.Errorf("password not redacted: %v", out["password"])
	}
	if out["api_key"] != "***" {
		t.Errorf("api_key not redacted: %v", out["api_key"])
	}
	if out["secret"] != "***" {
		t.Errorf("secret not redacted: %v", out["secret"])
	}
	if out["token"] != "***" {
		t.Errorf("token not redacted: %v", out["token"])
	}
	if out["authorization"] != "***" {
		t.Errorf("authorization not redacted: %v", out["authorization"])
	}
	// non-sensitive keys preserved
	if out["username"] != "alice" {
		t.Errorf("username should be preserved: %v", out["username"])
	}
	if out["note"] != "public info" {
		t.Errorf("note should be preserved: %v", out["note"])
	}
}

func TestSanitizeDetailNested(t *testing.T) {
	in := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "bob",
			"token": "x",
		},
		"items": []interface{}{
			map[string]interface{}{"apikey": "y"},
			map[string]interface{}{"ok": "z"},
		},
	}
	out := SanitizeDetail(in, 0)
	user, ok := out["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("user not a map: %T", out["user"])
	}
	if user["token"] != "***" {
		t.Errorf("nested token not redacted: %v", user["token"])
	}
	if user["name"] != "bob" {
		t.Errorf("nested name preserved: %v", user["name"])
	}
	items, _ := out["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("items len = %d", len(items))
	}
	first, _ := items[0].(map[string]interface{})
	if first["apikey"] != "***" {
		t.Errorf("array element apikey not redacted: %v", first["apikey"])
	}
}

func TestSanitizeDetailNilAndTruncation(t *testing.T) {
	if SanitizeDetail(nil, 10) != nil {
		t.Error("nil input should return nil")
	}
	// small maxBytes forces truncation
	big := map[string]interface{}{"note": "hello world this is a long public message"}
	out := SanitizeDetail(big, 10)
	if trunc, ok := out["_truncated"].(bool); !ok || !trunc {
		t.Errorf("expected _truncated true, got %v", out)
	}
	if _, ok := out["_preview"].(string); !ok {
		t.Error("_preview missing on truncation")
	}
	// maxBytes<=0 uses default 8192, no truncation for small payload
	small := map[string]interface{}{"note": "short"}
	if out := SanitizeDetail(small, 0); out["_truncated"] != nil {
		t.Errorf("small payload should not truncate, got %v", out)
	}
}

// ---------- failureThrottle ----------

func TestFailureThrottleAllow(t *testing.T) {
	tr := newFailureThrottle()
	if !tr.allow("k", 0) {
		t.Error("cooldown<=0 should always allow")
	}
	if !tr.allow("k", time.Hour) {
		t.Error("first attempt within cooldown should allow")
	}
	if tr.allow("k", time.Hour) {
		t.Error("immediate second attempt within cooldown should be denied")
	}
	// different key not affected
	if !tr.allow("other", time.Hour) {
		t.Error("different key should allow")
	}
	// empty key always allows (nil-guard path)
	if !tr.allow("", time.Hour) {
		t.Error("empty key should allow")
	}
	// nil throttle never blocks
	var ntr *failureThrottle
	if !ntr.allow("k", time.Hour) {
		t.Error("nil throttle should allow")
	}
}

// ---------- auth failure throttling classification ----------

func TestIsAuthFailureThrottled(t *testing.T) {
	cases := []struct {
		cat, act string
		want     bool
	}{
		{"auth", "login", true},
		{"auth", "change_password", true},
		{"auth", "logout", false},
		{"auth", "reset", false},
		{"session", "login", false},
		{"", "login", false},
	}
	for _, c := range cases {
		if got := isAuthFailureThrottled(c.cat, c.act); got != c.want {
			t.Errorf("isAuthFailureThrottled(%q,%q)=%v want %v", c.cat, c.act, got, c.want)
		}
	}
}

func TestAuthFailureThrottleKey(t *testing.T) {
	if got := authFailureThrottleKey("auth", "login", "1.2.3.4"); got != "auth:login:1.2.3.4" {
		t.Errorf("key = %q", got)
	}
}

// ---------- session hint (token hash) ----------

func TestHintFromToken(t *testing.T) {
	if HintFromToken("") != "" {
		t.Error("empty token -> empty hint")
	}
	a := HintFromToken("token-abc")
	b := HintFromToken("token-abc")
	if a != b {
		t.Error("hint must be deterministic")
	}
	if len(a) != 8 {
		t.Errorf("hint should be 8 hex chars (4 bytes), got %q len %d", a, len(a))
	}
	if HintFromToken("different") == a {
		t.Error("different tokens should produce different hints")
	}
}

// ---------- ApplyResourceAvailability (DB-free branches) ----------

func TestApplyResourceAvailabilityNilAndDelete(t *testing.T) {
	// nil log -> no panic
	ApplyResourceAvailability(nil, nil)
	// empty resource id -> no-op
	ApplyResourceAvailability(nil, &database.AuditLog{})
	// delete action sets ResourceAvailable=false without DB
	log := &database.AuditLog{Action: "delete", ResourceID: "vuln-1"}
	ApplyResourceAvailability(nil, log)
	if log.ResourceAvailable == nil || *log.ResourceAvailable != false {
		t.Errorf("delete action should mark resource unavailable, got %v", log.ResourceAvailable)
	}
	// non-delete action with nil db -> no-op (no DB call)
	log2 := &database.AuditLog{Action: "create", ResourceID: "conv-1"}
	ApplyResourceAvailability(nil, log2)
	if log2.ResourceAvailable != nil {
		t.Error("nil db + non-delete action should not set ResourceAvailable")
	}
}

// ---------- Service nil guards ----------

func TestServiceNilGuards(t *testing.T) {
	var s *Service
	if s.RetentionDays() != 0 {
		t.Error("nil service RetentionDays should be 0")
	}
	if s.Enabled() {
		t.Error("nil service Enabled should be false")
	}
	// these must not panic
	s.Record(nil, Entry{Category: "x", Action: "y"})
	s.RecordSystem(Entry{Category: "x", Action: "y"})
	s.PurgeExpired()
}

func TestNewServiceWithNilCfg(t *testing.T) {
	s := NewService(nil, nil, nil)
	if s == nil {
		t.Fatal("NewService returned nil")
	}
	if s.Enabled() {
		t.Error("service with nil cfg must be disabled")
	}
	if s.RetentionDays() != 0 {
		t.Error("service with nil cfg retention must be 0")
	}
	// Record with disabled service is a no-op (no db access)
	s.Record(nil, Entry{Category: "auth", Action: "login", Result: "failure"})
}
