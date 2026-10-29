// Package llmchannel —— 免费 LLM 通道注册表 + 瞬时错误分类 + LLM 调用并发护栏。
//
// LLMGuard（本文件）是「多会话 / 多代理并发」的安全底座：
//
//	StepFun 等账号级并发上限是硬约束（所有模型共享同一池），多会话并行时任何时刻
//	的 LLM 调用数必须 ≤ 上限，否则触发 429 风暴 —— 见 registry.go 顶部 2026-10-25
//	实测事故（单通道 429 抖动 37 次重试、杀掉 3 道题）。
//
// 所有 LLM 调用路径（单代理 / 多代理 / 批量 harness）应统一在发起 provider 调用前
//
//	g.Acquire(ctx)，调用结束后 g.Release()（或用 g.Do 包裹）。
//
// 容量默认 5，可由环境变量 LLM_MAX_CONCURRENT 覆盖（与 config.yaml multi_agent.llm_max_concurrent 同源）。
package llmchannel

import (
	"context"
	"os"
	"strconv"
	"sync"
)

// LLMGuard 是 LLM 调用全局并发护栏（计数信号量）。
// 不依赖外部库；支持运行时热更新上限，调用前 Acquire 阻塞至有名额或 ctx 取消。
type LLMGuard struct {
	mu       sync.Mutex
	cond     *sync.Cond
	limit    int
	inFlight int
}

// envLimit 从 LLM_MAX_CONCURRENT 读取上限，缺省/非法时回退 5。
func envLimit() int {
	if v := os.Getenv("LLM_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 5
}

// NewLLMGuard 构造容量为 limit（<1 视为 1）的护栏。
func NewLLMGuard(limit int) *LLMGuard {
	if limit < 1 {
		limit = 1
	}
	g := &LLMGuard{limit: limit}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// DefaultGuard 进程级单例，容量取 LLM_MAX_CONCURRENT（默认 5）。
var DefaultGuard = NewLLMGuard(envLimit())

// SetLimit 运行时热更新并发上限（>0 才生效）。已在途的调用不受影响，
// 仅影响后续 Acquire 的准入门槛。
func (g *LLMGuard) SetLimit(n int) {
	if n < 1 {
		return
	}
	g.mu.Lock()
	g.limit = n
	g.cond.Broadcast()
	g.mu.Unlock()
}

// Acquire 阻塞至拿到一个并发名额，或 ctx 取消（返回 ctx.Err()）。
func (g *LLMGuard) Acquire(ctx context.Context) error {
	g.mu.Lock()
	for g.inFlight >= g.limit {
		if ctx.Err() != nil {
			g.mu.Unlock()
			return ctx.Err()
		}
		g.cond.Wait()
	}
	g.inFlight++
	g.mu.Unlock()
	return nil
}

// Release 归还一个并发名额并唤醒一个等待者。
func (g *LLMGuard) Release() {
	g.mu.Lock()
	if g.inFlight > 0 {
		g.inFlight--
	}
	g.cond.Signal()
	g.mu.Unlock()
}

// TryAcquire 非阻塞获取；成功返回 true，名额已满返回 false。
func (g *LLMGuard) TryAcquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight >= g.limit {
		return false
	}
	g.inFlight++
	return true
}

// Do 在持有一个并发名额期间执行 fn，结束后自动 Release。
func (g *LLMGuard) Do(ctx context.Context, fn func() error) error {
	if err := g.Acquire(ctx); err != nil {
		return err
	}
	defer g.Release()
	return fn()
}

// InFlight 返回当前在途调用数（诊断用）。
func (g *LLMGuard) InFlight() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight
}

// Limit 返回当前并发上限。
func (g *LLMGuard) Limit() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limit
}
