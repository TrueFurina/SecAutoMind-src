package ctfplatform

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestSqliAsk_DistinguishesFalseFromFailure 是盲注健壮性的核心回归：
// 「响应为假」必须返回 (false,true)；「请求失败」必须返回 ok=false，
// 绝不能被当成一个合法的 false —— 否则二分搜索会收敛到相邻字符
// （线上实测：sqli→sgli、b1n4ry→b1n+ry）。
func TestSqliAsk_DistinguishesFalseFromFailure(t *testing.T) {
	cl := webClient(2 * time.Second)
	ctx := context.Background()

	t.Run("true", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "row exists here")
		}))
		defer srv.Close()
		v, ok := sqliAsk(ctx, cl, srv.URL, "/", "id", "1=1")
		if !ok || !v {
			t.Fatalf("应返回 (true,true)，实际 (%v,%v)", v, ok)
		}
	})

	t.Run("false", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "no rows")
		}))
		defer srv.Close()
		v, ok := sqliAsk(ctx, cl, srv.URL, "/", "id", "1=2")
		if !ok || v {
			t.Fatalf("应返回 (false,true)，实际 (%v,%v)", v, ok)
		}
	})

	t.Run("transient_failure_then_success", func(t *testing.T) {
		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&n, 1) <= 2 {
				// 前两次直接断连，模拟网络抖动
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, err := hj.Hijack()
					if err == nil {
						conn.Close()
						return
					}
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			io.WriteString(w, "exists")
		}))
		defer srv.Close()
		v, ok := sqliAsk(ctx, cl, srv.URL, "/", "id", "1=1")
		if !ok || !v {
			t.Fatalf("重试后应成功 (true,true)，实际 (%v,%v)", v, ok)
		}
		if got := atomic.LoadInt32(&n); got < 3 {
			t.Errorf("应至少请求 3 次，实际 %d", got)
		}
	})

	t.Run("always_failing", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					conn.Close()
					return
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		v, ok := sqliAsk(ctx, cl, srv.URL, "/", "id", "1=1")
		if ok {
			t.Fatalf("始终失败时 ok 必须为 false，实际 (%v,%v)", v, ok)
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "exists")
		}))
		defer srv.Close()
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, ok := sqliAsk(cctx, cl, srv.URL, "/", "id", "1=1"); ok {
			t.Fatal("ctx 已取消时 ok 必须为 false")
		}
	})
}
