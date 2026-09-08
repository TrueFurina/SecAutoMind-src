package ctfplatform

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

const (
	blindTimeSecret = "t1m3b1"             // 时间盲注还原目标（6 字符）
	blindOOBSecret  = "flag{o0b_3xfil_7k}" // OOB 外带还原目标（flag）
	blindCharset    = "abcdefghijklmnopqrstuvwxyz0123456789_"
)

// newTimeTarget 返回一个时间盲注 mock 靶机：/time?pos=i&c=ch，secret[i]==ch 时延迟 300ms。
func newTimeTarget(secret string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		i, _ := strconv.Atoi(q.Get("pos"))
		c := q.Get("c")
		if i >= 0 && i < len(secret) && len(c) == 1 && secret[i] == c[0] {
			time.Sleep(300 * time.Millisecond) // 条件成立：显著延迟
		} else {
			time.Sleep(20 * time.Millisecond) // 条件不成立：快速返回
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
}

// newOOBTarget 返回一个 OOB mock 靶机：/oob?cb=<listenerURL>，收到后把密钥回连到该 URL。
func newOOBTarget(secret string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cb := r.URL.Query().Get("cb")
		if cb != "" {
			// 靶机被注入后，把密钥外泄到攻击方监听器
			go func() {
				resp, err := http.Get(cb + secret)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
}

// TestBlindOOBTimeBased 时间盲注真实还原：仅依靶机响应耗时差异逐字符还原密钥。
func TestBlindOOBTimeBased(t *testing.T) {
	target := newTimeTarget(blindTimeSecret)
	defer target.Close()

	oracle := func(ctx context.Context, cond string) (time.Duration, error) {
		q, err := url.ParseQuery(cond)
		if err != nil {
			return 0, err
		}
		u := target.URL + "/time?pos=" + q.Get("pos") + "&c=" + q.Get("c")
		t0 := time.Now()
		resp, err := http.Get(u)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return time.Since(t0), nil
	}

	got := TimeBlindRecover(context.Background(), oracle, len(blindTimeSecret), blindCharset, 120*time.Millisecond)
	if got != blindTimeSecret {
		t.Fatalf("时间盲注还原不符: want=%q got=%q", blindTimeSecret, got)
	}
	t.Logf("✅ 时间盲注逐字符还原密钥=%s", got)
}

// TestBlindOOBOOB OOB 外带真实还原：靶机把密钥回连到内置监听器，从中捕获。
func TestBlindOOBOOB(t *testing.T) {
	target := newOOBTarget(blindOOBSecret)
	defer target.Close()
	oob := StartOOBListener()
	defer oob.Close()

	trigger := func(oobBase string) error {
		u := target.URL + "/oob?cb=" + url.QueryEscape(oobBase+"/?d=")
		resp, err := http.Get(u)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil
	}
	got, ok := OOBExtract(oob, trigger, func(raw string) string {
		if f := scanFlags(raw); len(f) > 0 {
			return f[0]
		}
		return ""
	})
	if !ok || got != blindOOBSecret {
		t.Fatalf("OOB 外带还原失败: ok=%v got=%q (期望 %q)", ok, got, blindOOBSecret)
	}
	t.Logf("✅ OOB 外带还原密钥=%s", got)
}

// TestBlindOOBSolverRegistered 反注水门禁：web_blind_oob 必须真实注册且启用。
func TestBlindOOBSolverRegistered(t *testing.T) {
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "web_blind_oob" {
			found = true
			if !s.Enabled {
				t.Errorf("web_blind_oob 已注册但被禁用")
			}
		}
	}
	if !found {
		t.Errorf("web_blind_oob 未注册（反注水门禁）")
	}
}

// TestBlindOOBNoFalsePositiveOnRandom 反误报：无信号/无 URL 时不得产出任何命中。
func TestBlindOOBNoFalsePositiveOnRandom(t *testing.T) {
	random := "Please analyze this packet capture and recover the admin password from the pcap."
	if got := tryBlindOOB(context.Background(), random, nil); len(got) != 0 {
		t.Fatalf("无盲打信号应返回空，实际 %v", got)
	}
	withURL := "Visit https://example.com/login for details about the secret."
	if got := tryBlindOOB(context.Background(), withURL, nil); len(got) != 0 {
		t.Fatalf("有 URL 但无盲打信号应返回空，实际 %v", got)
	}
}
