package ctfplatform

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestWebExploitApplies URL 渗透链门控真值表：仅 web 类或未声明类别启用。
// 未声明（空）必须放行——生产 handler 构造的 Challenge 常不带类别
// （见 web_exploit_test.go TestPresolveAutoExploitsWebTarget 的空类别用例），
// 收得太紧会直接把 Web 题的利用链打断。
func TestWebExploitApplies(t *testing.T) {
	cases := []struct {
		category string
		want     bool
	}{
		{"", true},
		{"web", true},
		{"crypto", false},
		{"misc", false},
		{"reverse", false},
		{"pwn", false},
	}
	for _, c := range cases {
		if got := webExploitApplies(c.category); got != c.want {
			t.Errorf("webExploitApplies(%q) = %v, want %v", c.category, got, c.want)
		}
	}
}

// TestPresolveWebExploitGate_NonWebSkipsChain 非 web 题的文本 URL 不得触发
// 真实渗透链。回归防护（2026-10-15 立尺实锤）：crypto 题 specialcurve2 附件
// 注释里的 writeup 链接（cn-sec.com）会让九件套对该无关主机发起真实请求并
// 干等满超时——逐 solver 计时 jwt 40s / upload 29.8s / web_exploit 25s，
// 生产路径单题 60.002s，跨-bench 子集测试 4 遍扫描 267s；且从第三方页面
// 刮回的 body{...} 外形串污染 solved 判定。
// 方法：挂起监听器（接受连接但不写响应）+ crypto 类别 → 必须快速返回且零连接。
func TestPresolveWebExploitGate_NonWebSkipsChain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&conns, 1)
			_ = c // 故意不写响应：未门控时利用链将在此干等满超时
		}
	}()

	url := "http://" + ln.Addr().String() + "/writeup.html"
	pr := NewPresolver(zap.NewNop())
	ch := &Challenge{
		ID:          "synthetic_nonweb_url",
		Category:    "crypto",
		Description: "已知 phi(n) 与 n，求 d 并解密密文。参考 " + url + " （某 writeup）。",
	}
	t0 := time.Now()
	_ = pr.Presolve(context.Background(), ch, nil)
	elapsed := time.Since(t0)
	if elapsed > 10*time.Second {
		t.Errorf("非 web 题触发了 URL 渗透链：Presolve 耗时 %v（门控失效，九件套在干等超时）", elapsed)
	}
	if n := atomic.LoadInt64(&conns); n != 0 {
		t.Errorf("非 web 题建立了 %d 条到文本 URL 的连接，应为 0（门控失效）", n)
	}
}

// TestPresolveWebExploitGate_WebStillFires web 题必须仍然走利用链——
// 门控不得过度收紧。用本地快速响应服务器验证连接确实建立。
func TestPresolveWebExploitGate_WebStillFires(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&conns, 1)
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	url := "http://" + ln.Addr().String() + "/index.php?id=1"
	pr := NewPresolver(zap.NewNop())
	ch := &Challenge{
		ID:          "synthetic_web_url",
		Category:    "web",
		Description: "Web 题：目标站点 " + url + " ，存在注入，读取 flag。",
	}
	done := make(chan *PresolveResult, 1)
	go func() { done <- pr.Presolve(context.Background(), ch, nil) }()
	deadline := time.After(20 * time.Second)
	for atomic.LoadInt64(&conns) == 0 {
		select {
		case <-done:
			t.Fatalf("web 类别下 Presolve 已返回但未建立任何连接——利用链被过度门控")
		case <-deadline:
			t.Fatalf("web 类别下 20s 内未建立到靶机的连接——利用链未触发")
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Logf("web 类别已建立 %d 条连接（利用链正常触发）", atomic.LoadInt64(&conns))
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatal("web 类别下利用链 45s 未返回（异常缓慢）")
	}
}

// TestRegistrySweepSkipsWebChainForNonWeb 注册表路径同样受门控约束：
// PresolveWithRegistry 对 crypto 题不得调度 WebExploitChain 求解器。
// （生产路径 Presolve 的 fanout 门控由上面的挂起监听器测试覆盖。）
func TestRegistrySweepSkipsWebChainForNonWeb(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&conns, 1)
			_ = c
		}
	}()

	url := "http://" + ln.Addr().String() + "/"
	pr := NewPresolver(zap.NewNop())
	ch := &Challenge{
		ID:          "synthetic_nonweb_url_reg",
		Category:    "misc",
		Description: "杂项题：分析流量。参考 " + url + " 。",
	}
	t0 := time.Now()
	_ = pr.PresolveWithRegistry(context.Background(), ch, nil)
	if elapsed := time.Since(t0); elapsed > 10*time.Second {
		t.Errorf("注册表路径对非 web 题调度了 URL 渗透链：耗时 %v", elapsed)
	}
	if n := atomic.LoadInt64(&conns); n != 0 {
		t.Errorf("注册表路径对非 web 题建立了 %d 条连接，应为 0", n)
	}
}
