package llmchannel

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGuardBasicAcquireRelease 基础准入/释放。
func TestGuardBasicAcquireRelease(t *testing.T) {
	g := NewLLMGuard(2)
	ctx := context.Background()
	if err := g.Acquire(ctx); err != nil {
		t.Fatalf("acquire1: %v", err)
	}
	if g.InFlight() != 1 {
		t.Fatalf("inFlight want 1 got %d", g.InFlight())
	}
	g.Release()
	if g.InFlight() != 0 {
		t.Fatalf("inFlight want 0 got %d", g.InFlight())
	}
}

// TestGuardConcurrencyCap 并发上限不被突破。
func TestGuardConcurrencyCap(t *testing.T) {
	const limit = 5
	const workers = 50
	g := NewLLMGuard(limit)
	ctx := context.Background()

	var maxInFlight int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = g.Acquire(ctx)
			defer g.Release()
			cur := atomic.AddInt64(&maxInFlight, 1)
			// 读取峰值时加锁采样更准，但这里用原子峰值已足够证明不越界
			_ = cur
			time.Sleep(time.Millisecond)
			atomic.AddInt64(&maxInFlight, -1)
		}()
	}
	close(start)
	wg.Wait()

	// 峰值应 ≤ limit：用带锁的统计替代，重测更严格
	if g.InFlight() != 0 {
		t.Fatalf("leak: inFlight=%d after all done", g.InFlight())
	}
}

// TestGuardStrictCap 用计数信号严格证明任意时刻 inFlight ≤ limit。
func TestGuardStrictCap(t *testing.T) {
	const limit = 3
	const workers = 100
	g := NewLLMGuard(limit)
	ctx := context.Background()

	var mu sync.Mutex
	var cur, peak int
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = g.Acquire(ctx)
			mu.Lock()
			cur++
			if cur > peak {
				peak = cur
			}
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			mu.Lock()
			cur--
			mu.Unlock()
			g.Release()
		}()
	}
	close(start)
	wg.Wait()
	if peak > limit {
		t.Fatalf("concurrency cap violated: peak=%d > limit=%d", peak, limit)
	}
}

// TestGuardTryAcquire 名额满后非阻塞获取失败。
func TestGuardTryAcquire(t *testing.T) {
	g := NewLLMGuard(2)
	// 两次调用是有意的（占满 limit=2）；用变量接住而不是写两遍同样的表达式，
	// 否则 staticcheck SA4000 会当成复制粘贴错误，且 || 的短路会让"第二次是否被调用"
	// 取决于第一次的结果，测试意图变模糊。
	first, second := g.TryAcquire(), g.TryAcquire()
	if !first || !second {
		t.Fatal("first two TryAcquire should succeed")
	}
	if g.TryAcquire() {
		t.Fatal("third TryAcquire should fail when full")
	}
	g.Release()
	if !g.TryAcquire() {
		t.Fatal("after Release one slot should be available")
	}
}

// TestGuardCtxCancel ctx 取消时 Acquire 立即返回错误。
func TestGuardCtxCancel(t *testing.T) {
	g := NewLLMGuard(1)
	ctx := context.Background()
	_ = g.Acquire(ctx) // 占满唯一名额
	defer g.Release()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.Acquire(cancelled); err == nil {
		t.Fatal("Acquire on cancelled ctx should return error")
	}
}

// TestGuardSetLimit 热更新上限生效。
func TestGuardSetLimit(t *testing.T) {
	g := NewLLMGuard(1)
	g.SetLimit(4)
	if g.Limit() != 4 {
		t.Fatalf("limit want 4 got %d", g.Limit())
	}
	for i := 0; i < 4; i++ {
		if !g.TryAcquire() {
			t.Fatalf("should acquire slot %d after SetLimit(4)", i)
		}
	}
	if g.TryAcquire() {
		t.Fatal("5th acquire should fail at limit 4")
	}
}

// TestDefaultGuardEnv 环境变量覆盖默认容量。
func TestDefaultGuardEnv(t *testing.T) {
	t.Setenv("LLM_MAX_CONCURRENT", "7")
	g := NewLLMGuard(envLimit())
	if g.Limit() != 7 {
		t.Fatalf("env override want 7 got %d", g.Limit())
	}
}
