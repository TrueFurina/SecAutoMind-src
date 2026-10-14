package ctfplatform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ── 抗打击治理配置面（总纲 §2.4：config 开关化、默认开、一键回退）──────────
//
// 本文件是「一键回退」的**行为级**回归：不只断言开关位被写对，而是断言 7 项机制
// 在回退后**真的不再生效**（不重试 / 不计数 / 不冷却 / 不缓存 / 不复用），
// 且回退前后既有行为不受影响。只测开关位的测试是空洞绿——开关写对了但没接线，
// 一样会通过。

// 契约⓪：默认开。零值平台与 NewDasCTFPlatform 都必须等价于「7 项全开」。
//
// 这条是防回归的**关键钉子**：若有人把开关改成正向零值（Enabled bool 直接存进
// 结构体），既有大量「直接构造结构体再逐字段赋值」的路径会静默退化为朴素直连，
// 而所有功能测试照常全绿 —— 正是初赛被 429 打爆的成因。
func TestAntiBlockDefaultsOnForZeroValuePlatform(t *testing.T) {
	var raw DasCTFPlatform // 零值：不走构造函数
	if raw.AntiBlockDisabled() {
		t.Error("零值 DasCTFPlatform 必须等于「7 项全开」（默认开由零值保证）")
	}
	p := NewDasCTFPlatform("http://example.invalid", "", zap.NewNop())
	if p.AntiBlockDisabled() {
		t.Error("NewDasCTFPlatform 必须默认启用抗打击治理")
	}
}

// 契约①：一键回退。单个布尔位把 7 项一次性停用。
func TestAntiBlockOneClickRollback(t *testing.T) {
	ctx := context.Background()

	// 变体 A：永远 429 —— 用于验证「不重试」「不计数」「不给阶梯建议」
	var mu sync.Mutex
	var calls429 int
	srv429 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls429++
		mu.Unlock()
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv429.Close()

	p := newTestPlatform(t, srv429.URL)
	p.SetAntiBlock(AntiBlockOptions{Enabled: false})

	if !p.AntiBlockDisabled() {
		t.Fatal("SetAntiBlock(Enabled:false) 后 AntiBlockDisabled() 应为 true")
	}
	if _, _, err := p.doRequest(ctx, "GET", "challenges", nil); err == nil {
		t.Fatal("429 应返回错误（回退不回退都必须如实报错）")
	}
	mu.Lock()
	n := calls429
	mu.Unlock()
	if n != 1 {
		t.Errorf("回退后不重试，应共 1 次请求，实际 %d", n)
	}
	if p.Consec429() != 0 {
		t.Errorf("回退后不累计连续 429，实际 %d", p.Consec429())
	}

	// ④ 阶梯建议：直接把计数塞进去，仍须恒为 0 —— 证明拦截在建议层，
	//    而不是「刚好没累计上所以是 0」。
	p.mu.Lock()
	p.consec429 = 12
	p.mu.Unlock()
	if got := p.BackoffSuggestion(0); got != 0 {
		t.Errorf("回退后阶梯建议应恒为 0，实际 %v", got)
	}
	p.mu.Lock()
	p.consec429 = 0
	p.mu.Unlock()

	// ⑤ WAF 冷却：直接把冷却窗口塞进去，仍须为 0；且 403 不设冷却、不冻结后续请求
	p.mu.Lock()
	p.wafBlockedUntil = time.Now().Add(time.Hour)
	p.mu.Unlock()
	if got := p.WafBlockedSeconds(); got != 0 {
		t.Errorf("回退后 WAF 冷却应恒为 0，实际 %v", got)
	}

	var callsForbidden int
	srv403 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callsForbidden++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv403.Close()

	p403 := newTestPlatform(t, srv403.URL)
	p403.SetAntiBlock(AntiBlockOptions{Enabled: false})
	if _, err := p403.ListChallenges(ctx); err == nil {
		t.Fatal("403 应返回错误")
	}
	if p403.WafBlockedSeconds() != 0 {
		t.Error("回退后 403 不应设置 WAF 冷却")
	}
	// 不冻结 = 第二次请求仍会打到平台（对比：开启时第二次会被本地拦掉）
	if _, err := p403.ListChallenges(ctx); err == nil {
		t.Fatal("403 应返回错误")
	}
	mu.Lock()
	c403 := callsForbidden
	mu.Unlock()
	if c403 != 2 {
		t.Errorf("回退后不应冻结请求，应命中平台 2 次，实际 %d", c403)
	}

	// ⑥ 列表缓存：连续两次 ListChallenges 必须各发一次真实请求
	var callsList int
	srvList := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callsList++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":[]}`))
	}))
	defer srvList.Close()

	pList := newTestPlatform(t, srvList.URL) // listCacheTTL = 200ms
	pList.SetAntiBlock(AntiBlockOptions{Enabled: false})
	for i := 0; i < 2; i++ {
		if _, err := pList.ListChallenges(ctx); err != nil {
			t.Fatalf("第 %d 次 ListChallenges 失败: %v", i+1, err)
		}
	}
	mu.Lock()
	cList := callsList
	mu.Unlock()
	if cList != 2 {
		t.Errorf("回退后列表缓存应停用（每轮真实请求），应 2 次，实际 %d", cList)
	}
}

// 契约②：回退必须清零残留状态，不能留「开关已关但状态还在」的半开状态。
func TestAntiBlockRollbackClearsResidualState(t *testing.T) {
	p := newTestPlatform(t, "http://example.invalid")

	// 制造残留：连续 429 + WAF 冷却 + 列表缓存
	p.incConsec429()
	p.incConsec429()
	p.mu.Lock()
	p.wafBlockedUntil = time.Now().Add(time.Hour)
	p.listCache = []Challenge{{}}
	p.listCacheAt = time.Now()
	p.mu.Unlock()

	if p.WafBlockedSeconds() <= 0 {
		t.Fatal("前置条件不成立：应处于 WAF 冷却中")
	}

	p.SetAntiBlock(AntiBlockOptions{Enabled: false})

	if n := p.Consec429(); n != 0 {
		t.Errorf("回退应清零连续 429 计数，实际 %d", n)
	}
	if p.WafBlockedSeconds() != 0 {
		t.Error("回退应清零 WAF 冷却")
	}
	p.mu.Lock()
	cacheNil := p.listCache == nil && p.listCacheAt.IsZero()
	p.mu.Unlock()
	if !cacheNil {
		t.Error("回退应丢弃列表缓存")
	}
}

// 契约③：默认开的高位不变——回退后可再恢复，且数值旋钮生效。
func TestAntiBlockOverridesAndReversibility(t *testing.T) {
	var mu sync.Mutex
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	p.MaxRetries = 5

	ttl := 250 * time.Millisecond
	p.SetAntiBlock(AntiBlockOptions{
		Enabled:      true,
		MaxRetries:   1,
		RetryBackoff: time.Millisecond,
		WAFTimeout:   1234 * time.Millisecond,
		ListCacheTTL: &ttl,
	})

	if p.AntiBlockDisabled() {
		t.Fatal("Enabled:true 后不应处于回退态")
	}
	if _, _, err := p.doRequest(context.Background(), "GET", "challenges", nil); err == nil {
		t.Fatal("429 重试耗尽应返回错误")
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 2 { // 首次 + 1 次重试
		t.Errorf("MaxRetries=1 应共 2 次请求，实际 %d", n)
	}
	if got := p.wafTimeout(); got != 1234*time.Millisecond {
		t.Errorf("WAFTimeout 覆盖未生效，实际 %v", got)
	}
	p.mu.Lock()
	gotTTL := p.listCacheTTL
	p.mu.Unlock()
	if gotTTL != ttl {
		t.Errorf("ListCacheTTL 覆盖未生效，实际 %v", gotTTL)
	}

	// 反向：回退 → 再开启，重试能力必须回来（证明回退不是单向不可逆的破坏）
	p.SetAntiBlock(AntiBlockOptions{Enabled: false})
	mu.Lock()
	calls = 0
	mu.Unlock()
	if _, _, err := p.doRequest(context.Background(), "GET", "challenges", nil); err == nil {
		t.Fatal("429 应返回错误")
	}
	mu.Lock()
	n2 := calls
	mu.Unlock()
	if n2 != 1 {
		t.Errorf("回退后应只请求 1 次，实际 %d", n2)
	}

	p.SetAntiBlock(AntiBlockOptions{Enabled: true, MaxRetries: 1, RetryBackoff: time.Millisecond})
	mu.Lock()
	calls = 0
	mu.Unlock()
	if _, _, err := p.doRequest(context.Background(), "GET", "challenges", nil); err == nil {
		t.Fatal("429 应返回错误")
	}
	mu.Lock()
	n3 := calls
	mu.Unlock()
	if n3 != 2 {
		t.Errorf("恢复后应重新具备重试能力（2 次），实际 %d", n3)
	}
}

// 契约④：⑦ 连接复用的回退**不得**污染全局 http.DefaultTransport。
//
// 若直接改 DefaultTransport，本想只回退这一个 CTF 客户端，实际会把整个进程的
// HTTP 连接复用一起关掉——回退动作自身成为事故源。且该污染在功能测试里不可见。
func TestAntiBlockRollbackDoesNotPolluteDefaultTransport(t *testing.T) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("默认 Transport 非 *http.Transport，本断言不适用")
	}
	before := base.DisableKeepAlives
	beforeIdle := base.MaxIdleConnsPerHost

	p := NewDasCTFPlatform("http://example.invalid", "", zap.NewNop())
	sharedBefore := p.HTTPClient.Transport // nil = 走 DefaultTransport

	p.SetAntiBlock(AntiBlockOptions{Enabled: false})

	if base.DisableKeepAlives != before || base.MaxIdleConnsPerHost != beforeIdle {
		t.Fatal("回退连接复用时污染了全局 http.DefaultTransport")
	}
	if p.HTTPClient.Transport == sharedBefore {
		t.Fatal("回退连接复用时应克隆出私有 Transport，而不是继续共用默认实现")
	}
	priv, ok := p.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("私有 Transport 类型异常: %T", p.HTTPClient.Transport)
	}
	if !priv.DisableKeepAlives {
		t.Error("回退后私有 Transport 应关闭连接复用")
	}

	// 恢复：私有 Transport 上重新开启复用（仍不碰全局）
	p.SetAntiBlock(AntiBlockOptions{Enabled: true})
	if priv.DisableKeepAlives {
		t.Error("恢复后应重新开启连接复用")
	}
	if base.DisableKeepAlives != before {
		t.Fatal("恢复动作同样不得改动全局 http.DefaultTransport")
	}
}
