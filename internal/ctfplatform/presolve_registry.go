package ctfplatform

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"strconv"
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

// flagShapeRegex 通用 flag 外形：前缀{内容}，如 picoCTF{...} / BZHCTF{...}。
var flagShapeRegex = regexp.MustCompile(`[A-Za-z0-9_]{2,20}\{[^}\s]{4,}\}`)

// flagLikeness 评估一组候选「有多像真 flag」，用于裁决不同求解器的结果。
// 这是修复「注册表首命中缺陷」的关键：像 tryAESECB 那样返回
// "AES ECB 检测：发现 N 个重复块" 的诊断文本只值 1 分，
// 真正解出 flag 外形的候选值 3 分，绝不会被诊断文本抢走命中。
//   - 3：命中 flag 正则（品牌前缀 / 大写前缀 / 通用 前缀{内容} 外形）**且**是干净的可打印串
//   - 1：非空但无 flag 外形（视为诊断提示，不当命中）；或混有不可打印字节的乱码
//   - 0：空
//
// 「可打印」这一条是实测踩坑补上的：把随机二进制当 base64 解开会产出形如
// kEY{\x00\x1f乱码} 的假 flag，旧版给了 3 分，直接抢占真 flag 的命中
// （artifact_carve_zip / artifact_xor_crib 就是这么丢的）。真 flag 一定是
// 可打印 ASCII，含控制字符一律降级。
func flagLikeness(flags []string) int {
	best := 0
	for _, f := range flags {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		score := 1
		if flagRegexPresolve.MatchString(f) || flagRegexUppercase.MatchString(f) || flagShapeRegex.MatchString(f) {
			score = 3
		}
		if score == 3 && !isPrintableFlagCandidate(f) {
			score = 1
		}
		if score > best {
			best = score
		}
	}
	return best
}

// isPrintableFlagCandidate 候选必须是干净的可打印 ASCII（长度 1..128，无控制字符）。
func isPrintableFlagCandidate(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// solverRunStats 记录每个注册求解器的**实际执行次数**。
// 用途：机验「对外宣称 N 个求解器」与「生产链路真的跑到几个」是否一致，
// 杜绝「注册了 145 个、生产只用 25 个」这类注水。
var solverRunStats = struct {
	mu sync.Mutex
	n  map[string]int
}{n: make(map[string]int)}

func recordSolverRun(name string) {
	solverRunStats.mu.Lock()
	solverRunStats.n[name]++
	solverRunStats.mu.Unlock()
}

// SolverRunCounts 返回各求解器实际执行次数的快照（测试/自检用）。
func SolverRunCounts() map[string]int {
	solverRunStats.mu.Lock()
	defer solverRunStats.mu.Unlock()
	out := make(map[string]int, len(solverRunStats.n))
	for k, v := range solverRunStats.n {
		out[k] = v
	}
	return out
}

// registrySweepTimeout 注册表全量扫描的总时限（默认 6s，可用环境变量覆盖）。
func registrySweepTimeout() time.Duration {
	if v := os.Getenv("SECAUTOMIND_REGISTRY_SWEEP_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 6 * time.Second
}

// registrySweepEnabled 是否启用注册表全量扫描（生产 Presolve 会并入）。
func registrySweepEnabled() bool {
	v := strings.TrimSpace(os.Getenv("SECAUTOMIND_REGISTRY_SWEEP"))
	return v != "0"
}

// sweepCandidate 注册表扫描的一个候选命中。
type sweepCandidate struct {
	name  string
	prio  int
	flags []string
	like  int
}

// betterSweep 候选排序：先看「像不像 flag」，再比优先级，最后比名字保证确定性。
func betterSweep(a, b sweepCandidate) bool {
	if a.like != b.like {
		return a.like > b.like
	}
	if a.prio != b.prio {
		return a.prio < b.prio
	}
	return a.name < b.name
}

// presolveRegistrySweep 并发跑遍注册表内**所有** Enabled 求解器，
// 收集全部结果后按 flag 可信度裁决出最优命中。
//
// 与旧实现的本质区别：旧版「首个非空即返回」，会把诊断提示当命中，
// 且同一时刻只跑一个优先级组、高优先级组未命中才轮到下一组
// （=> 低优先级的正确解可能根本没机会跑）。新版一次跑全量。
func (p *Presolver) presolveRegistrySweep(ctx context.Context, text string, attachments map[string]string) *PresolveResult {
	solvers := GetSolvers()
	if len(solvers) == 0 {
		return nil
	}
	if p.cache == nil {
		p.cache = newPresolveCache(5 * time.Minute)
	}

	sweepCtx, cancel := context.WithTimeout(ctx, registrySweepTimeout())
	defer cancel()

	res := make(chan sweepCandidate, len(solvers))
	var wg sync.WaitGroup
	for _, entry := range solvers {
		if !entry.Enabled {
			continue
		}
		wg.Add(1)
		go func(s SolverEntry) {
			defer wg.Done()
			// 单个求解器 panic 不得拖垮整体扫描
			defer func() {
				if r := recover(); r != nil {
					p.logger.Warn("求解器 panic 已隔离", zap.String("solver", s.Name), zap.Any("panic", r))
				}
			}()
			key := cacheKey(s.Name, text)
			if cached, ok := p.cache.Get(key); ok {
				recordSolverRun(s.Name)
				if cached.Solved && len(cached.Flags) > 0 {
					res <- sweepCandidate{s.Name, s.Priority, cached.Flags, flagLikeness(cached.Flags)}
				}
				return
			}
			flags := s.Solver(sweepCtx, text, attachments)
			recordSolverRun(s.Name)
			p.cache.Set(key, &PresolveResult{Solved: len(flags) > 0, Engine: s.Name, Flags: flags})
			if len(flags) > 0 {
				res <- sweepCandidate{s.Name, s.Priority, flags, flagLikeness(flags)}
			}
		}(entry)
	}
	go func() {
		wg.Wait()
		close(res)
	}()

	var best *sweepCandidate
	for c := range res {
		if best == nil || betterSweep(c, *best) {
			c := c
			best = &c
		}
	}
	if best == nil {
		return nil
	}
	return &PresolveResult{
		Flags:  best.flags,
		Engine: best.name,
		Solved: true,
		Detail: fmt.Sprintf("[presolve:%s] 命中 %d 个候选（注册表全量扫描）", best.name, len(best.flags)),
	}
}

// PresolveWithRegistry 使用注册表驱动的 presolve（全量并发 + 缓存 + 热插拔 + 可信度裁决）。
// 相比原版 Presolve（硬编码快速路径），此版本：
//   - 一次跑遍注册表内所有 Enabled 求解器（不再只跑高优先级组）
//   - 结果按 flagLikeness 裁决，诊断提示不会再被误判为命中
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
	if len(GetSolvers()) == 0 {
		p.logger.Warn("注册表为空，回退到原始 Presolve")
		return p.Presolve(ctx, ch, attachments)
	}
	if r := p.presolveRegistrySweep(ctx, text, attachments); r != nil {
		p.logger.Info("presolve 命中（注册表驱动）",
			zap.String("engine", r.Engine), zap.Strings("flags", r.Flags))
		return r
	}
	return &PresolveResult{
		Solved: false,
		Detail: "presolve 未命中（注册表驱动，共 " + fmt.Sprintf("%d", len(GetSolvers())) + " 个求解器）",
	}
}

// init 补齐「硬编码快速路径独有、却未注册进注册表」的求解器。
//
// 历史断层：endian / rail_fence / rsa_common_factor / b64_caesar_alphabet /
// web_exploit 这 5 个求解器只在硬编码 Presolve 里被 goroutine 直接调用，
// 从未 RegisterSolver —— 在注册表视角下完全隐形，导致
// PresolveWithRegistry 覆盖率显著低于生产路径（14/55 vs 19/55）。
// 补齐后注册表成为生产能力的超集。
func init() {
	RegisterSolver(SolverEntry{
		Name: "web_exploit", Category: CategoryWebS, Priority: 1,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return ExploitURLsInText(ctx, text)
		},
	})
	RegisterSolver(SolverEntry{
		Name: "endian", Category: CategoryMiscS, Priority: 20,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryEndian(text)
		},
	})
	RegisterSolver(SolverEntry{
		Name: "rail_fence", Category: CategoryCryptoS, Priority: 21,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryRailFence(text)
		},
	})
	RegisterSolver(SolverEntry{
		Name: "rsa_common_factor", Category: CategoryCryptoS, Priority: 22,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryCommonFactor(text)
		},
	})
	RegisterSolver(SolverEntry{
		Name: "b64_caesar_alphabet", Category: CategoryCryptoS, Priority: 23,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryB64AlphabetCaesar(text)
		},
	})
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
