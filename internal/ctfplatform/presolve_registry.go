package ctfplatform

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// presolveCacheEntry 缓存条目。
type presolveCacheEntry struct {
	result    *PresolveResult
	createdAt time.Time
}

// presolveCache 结果缓存（相同输入+相同求解器 → 直接返回缓存结果）。
type presolveCache struct {
	mu    sync.RWMutex
	store map[string]*presolveCacheEntry
	ttl   time.Duration
}

func newPresolveCache(ttl time.Duration) *presolveCache {
	return &presolveCache{
		store: make(map[string]*presolveCacheEntry),
		ttl:   ttl,
	}
}

// cacheKey 生成缓存键：hash(输入文本 + 求解器名)。
func cacheKey(solverName, text string) string {
	h := sha256.Sum256([]byte(solverName + "|" + text))
	return fmt.Sprintf("%x", h[:16])
}

// Get 获取缓存结果（存在且未过期时返回）。
func (c *presolveCache) Get(key string) (*PresolveResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.store[key]
	if !ok {
		return nil, false
	}
	if time.Since(entry.createdAt) > c.ttl {
		return nil, false
	}
	return entry.result, true
}

// Set 存入缓存。
func (c *presolveCache) Set(key string, result *PresolveResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = &presolveCacheEntry{result: result, createdAt: time.Now()}
	if len(c.store) > 1000 {
		c.store = make(map[string]*presolveCacheEntry)
	}
}

// PresolveWithRegistry 使用注册表驱动的 presolve（优先级排序 + 并发扇出 + 缓存 + 热插拔）。
// 相比原版 Presolve（硬编码 60+ goroutine），此版本：
//   - 按注册表 Priority 排序执行（高优先级先跑）
//   - 并发扇出（同优先级的求解器并行，命中即返回）
//   - 结果缓存（相同输入+相同求解器 → 命中缓存）
//   - 热插拔（跳过 Enabled=false 的求解器）
//   - 上下文取消支持（ctx 取消时立即返回）
func (p *Presolver) PresolveWithRegistry(ctx context.Context, ch *Challenge, attachments map[string]string) *PresolveResult {
	text := ch.Description
	for _, v := range attachments {
		text += "\n" + v
	}
	if strings.TrimSpace(text) == "" {
		return &PresolveResult{}
	}

	solvers := GetSolvers()
	if len(solvers) == 0 {
		p.logger.Warn("注册表为空，回退到原始 Presolve")
		return p.Presolve(ctx, ch, attachments)
	}

	// 按优先级分组（同优先级的并行执行）
	groups := groupByPriority(solvers)

	type hitResult struct {
		engine string
		flags  []string
	}

	// 缓存实例（生命周期与调用方一致）
	if p.cache == nil {
		p.cache = newPresolveCache(5 * time.Minute)
	}

	// 按优先级组从高到低执行
	for _, group := range groups {
		select {
		case <-ctx.Done():
			return &PresolveResult{Detail: "上下文取消"}
		default:
		}

		ch := make(chan hitResult, len(group))
		var wg sync.WaitGroup

		for _, entry := range group {
			if !entry.Enabled {
				continue
			}
			wg.Add(1)
			go func(s SolverEntry) {
				defer wg.Done()
				// 缓存检查
				key := cacheKey(s.Name, text)
				if cached, ok := p.cache.Get(key); ok && cached.Solved {
					ch <- hitResult{s.Name, cached.Flags}
					return
				}
				// 执行求解器
				flags := s.Solver(ctx, text, attachments)
				// 写入缓存
				p.cache.Set(key, &PresolveResult{Solved: len(flags) > 0, Engine: s.Name, Flags: flags})
				if len(flags) > 0 {
					ch <- hitResult{s.Name, flags}
				}
			}(entry)
		}

		// 等待当前优先级组完成
		go func() {
			wg.Wait()
			close(ch)
		}()

		// 取第一个命中
		for h := range ch {
			if len(h.flags) > 0 {
				p.logger.Info("presolve 命中（注册表驱动）",
					zap.String("engine", h.engine),
					zap.Strings("flags", h.flags))
				return &PresolveResult{
					Flags:  h.flags,
					Engine: h.engine,
					Solved: true,
					Detail: fmt.Sprintf("[presolve:%s] 命中 %d 个候选（注册表驱动）", h.engine, len(h.flags)),
				}
			}
		}
	}

	return &PresolveResult{Detail: "presolve 未命中（注册表驱动，共 " + fmt.Sprintf("%d", len(solvers)) + " 个求解器）"}
}

// groupByPriority 将求解器按优先级分组（同优先级的一组，并行执行）。
func groupByPriority(solvers []SolverEntry) [][]SolverEntry {
	if len(solvers) == 0 {
		return nil
	}
	var groups [][]SolverEntry
	currentPriority := solvers[0].Priority
	currentGroup := []SolverEntry{solvers[0]}

	for _, s := range solvers[1:] {
		if s.Priority == currentPriority {
			currentGroup = append(currentGroup, s)
		} else {
			groups = append(groups, currentGroup)
			currentPriority = s.Priority
			currentGroup = []SolverEntry{s}
		}
	}
	groups = append(groups, currentGroup)
	return groups
}
