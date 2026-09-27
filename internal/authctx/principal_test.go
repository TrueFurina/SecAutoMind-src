package authctx

import (
	"context"
	"testing"
)

func TestNewPrincipalTrimsAndFilters(t *testing.T) {
	p := NewPrincipal("  u1  ", "  alice  ", "  s1  ", map[string]bool{
		"read":  true,
		"write": false, // disabled -> dropped
	})
	if p.UserID != "u1" || p.Username != "alice" || p.Scope != "s1" {
		t.Errorf("trim failed: %+v", p)
	}
	if !p.HasPermission("read") {
		t.Error("read should be granted")
	}
	if p.HasPermission("write") {
		t.Error("write (false) must be dropped")
	}
	if p.HasPermission("missing") {
		t.Error("missing permission must be false")
	}
}

func TestNewPrincipalWithScopes(t *testing.T) {
	p := NewPrincipalWithScopes("u1", "alice", "global",
		map[string]bool{"read": true, "write": true},
		map[string]string{"read": "proj-1", "write": ""}, // write scope empty -> not recorded
	)
	if got := p.ScopeFor("read"); got != "proj-1" {
		t.Errorf("ScopeFor(read) = %q, want proj-1", got)
	}
	// write has no per-permission scope -> falls back to principal Scope
	if got := p.ScopeFor("write"); got != "global" {
		t.Errorf("ScopeFor(write) = %q, want global fallback", got)
	}
	// unknown permission -> principal Scope fallback
	if got := p.ScopeFor("delete"); got != "global" {
		t.Errorf("ScopeFor(delete) = %q, want global", got)
	}
}

func TestPrincipalContextRoundTrip(t *testing.T) {
	p := NewPrincipal("u1", "alice", "s", map[string]bool{"read": true})
	ctx := WithPrincipal(context.Background(), p)
	got, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("expected principal in context")
	}
	if got.UserID != "u1" {
		t.Errorf("round-trip UserID = %q", got.UserID)
	}
}

func TestWithPrincipalNilCtxAndEmptyUser(t *testing.T) {
	// nil context is safe
	ctx := WithPrincipal(nil, NewPrincipal("u1", "a", "s", nil))
	if _, ok := PrincipalFromContext(ctx); !ok {
		t.Error("non-empty principal should be stored even from nil ctx")
	}
	// empty UserID -> context returned unchanged (no principal stored)
	emptyCtx := context.Background()
	out := WithPrincipal(emptyCtx, NewPrincipal("", "anon", "s", nil))
	if _, ok := PrincipalFromContext(out); ok {
		t.Error("empty UserID must not be stored")
	}
	// nil ctx with empty userID must not panic
	if _, ok := PrincipalFromContext(WithPrincipal(nil, NewPrincipal("", "", "", nil))); ok {
		t.Error("empty UserID from nil ctx must not yield a principal")
	}
}

func TestPrincipalFromContextNil(t *testing.T) {
	if _, ok := PrincipalFromContext(nil); ok {
		t.Error("nil ctx should yield ok=false")
	}
}
