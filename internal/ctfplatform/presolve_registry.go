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

// minFlagLikenessForHit 判定「算一次命中」所需的最低 flag 可信度。
//
// 只接受 likeness=3（真 flag 外形）；likeness=1（诊断/标签文本，如
// "AES ECB 检测：发现 N 个重复块"、"攻击链: TTP战术技术程序"）一律**不当命中**。
//
// 这正是本文件与 presolve_misc.go 注释早已声明的语义（"诊断提示不当命中"），
// 但旧实现"首个非空即 best"使其形同虚设——2026-10-03 实锤后果：
// `tryExploitChainDetection` 用 strings.Contains(text,"ttp") 匹配，而 "http" 里
// 就含 "ttp"，于是任何带 http/https URL 的消息（如用户发的"对http://...渗透测试"）
// 都被误判为"解出攻击链"，返回垃圾文本 `攻击链: TTP战术技术程序` 并**短路真正的
// Agent 推理**——用户看到的就是一句没头没尾的"候选 Flag"。
//
// 安全性：55/55 真题 flag 均带 {} 外壳（likeness=3），故收紧门槛**不可能**降低
// SHA-256 校验的真实覆盖率，只会消除假阳性短路。
const minFlagLikenessForHit = 3

// flagPlaceholderRe 题面「flag 格式声明」的占位符形态（非真 flag）。
//
// 实测实锤（2026-10-15 cross-bench FilterRandom，两轮才抓全）：
//   - 题面写「flag 格式为 DASCTF{init1-init2}」→ scanFlags 刮出 likeness=3；
//   - 脚本源码写 b'DASCTF{%d-%d}'%(init1,init2) → printf 模板同样 likeness=3。
//
// 二者都以 priority 10 的 flag_scan 胜出，压掉 priority 36 的 lfsr_correlation
// 正确解——占位符与真 flag 外形完全同分，只靠优先级裁决必然输。
//
// 保守取值：只收**unambiguous 的占位符族**（init1/xxxx/…/your/****/printf 说明符
// 出现在真 flag 内容里的概率可忽略），避免误伤真 flag 把命中率打下来。
// ⚠️ your 只带前边界——"your_flag_here" 中 "_" 是单词字符，\byour\b 会漏掉。
//
// 2026-10-18 扩表（外部真题尺 40 题实锤，见 externalbench_false_positive_test.go）：
// 上表只覆盖「Python 格式化占位符」一族，漏掉了**上游仓库把真 flag 抹成占位词**的另一族：
//   - `ext_gctf2025_bpfbox/flag.txt`、`numerology/flag.txt` 内容就是 `CTF{flag}`；
//   - `ext_gctf2021_h1/chall.py` 的 f-string 模板 `f'...here is the flag: {flag}'`；
//   - 变形产物 `ZPA{????}`（问号串）。
//
// 后果不是"少解一道题"，而是**假阳性短路**：Presolve 返回 Solved=true →
// integrator 置 SkipAgent=true → handler 直接把这串占位符当答案回给用户，
// 整条 Agent 推理被跳过（40 题里 6 题如此，见测试）。
// 故新增 `\?{2,}` 与「整词占位符」表；判据只作用于花括号内内容，前缀不参与。
var flagPlaceholderRe = regexp.MustCompile(`(?i)(\binit\d+\b|x{4,}|\.\.\.|\byour|\*{4,}|%[a-z]|\?{2,})`)

// flagPlaceholderWords 内容**整串**就是占位词（忽略大小写与分隔符）——上游脱敏仓库的
// 典型产物：`flag.txt` 里留一行 `CTF{flag}` / `flag{test}`。map 键为小写、去分隔符形态。
//
// 判定方向的不对称性（有意为之）：误判占位符 ⇒ likeness 降到 1 ⇒ 不短路 ⇒ 退回 LLM 真推理
// （只是少一次 0-token 命中）；漏判占位符 ⇒ 短路 ⇒ 用户拿到假答案。
// 故此处宁可宽，只排除「本身就是占位语义」的词，不含任何随机串。
var flagPlaceholderWords = map[string]bool{
	"flag": true, "flags": true, "flaghere": true, "yourflag": true,
	"yourflaghere": true, "insertflag": true, "insertflaghere": true,
	"putflaghere": true, "test": true, "testflag": true, "example": true,
	"placeholder": true, "redacted": true, "dummy": true, "sample": true,
	"changeme": true, "todo": true, "tbd": true, "filler": true,
}

// isLowInformationContent 花括号内是否「低信息量」：去掉分隔符后只剩 ≤1 种字符
// （`????` / `aaaa` / `0000` / `----`）——真 flag 不可能只有一个字符种类。
func isLowInformationContent(s string) bool {
	distinct := map[rune]bool{}
	for _, r := range s {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			continue
		}
		distinct[r] = true
		if len(distinct) > 1 {
			return false
		}
	}
	return len(distinct) == 1
}

// isPlaceholderFlag 判断 flag 串是否为「格式声明占位符」而非真 flag。
// 只检查第一层花括号内的内容，避免前缀/后缀误伤。
func isPlaceholderFlag(s string) bool {
	open := strings.Index(s, "{")
	closing := strings.LastIndex(s, "}")
	if open < 0 || closing <= open {
		return false
	}
	content := s[open+1 : closing]
	if flagPlaceholderRe.MatchString(content) {
		return true
	}
	if isLowInformationContent(content) {
		return true
	}
	var key strings.Builder
	for _, r := range strings.ToLower(content) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			key.WriteRune(r)
		}
	}
	return flagPlaceholderWords[key.String()]
}

// flagLikeness 评估一组候选「有多像真 flag」，用于裁决不同求解器的结果。
// 这是修复「注册表首命中缺陷」的关键：像 tryAESECB 那样返回
// "AES ECB 检测：发现 N 个重复块" 的诊断文本只值 1 分，
// 真正解出 flag 外形的候选值 3 分，绝不会被诊断文本抢走命中。
//   - 3：命中 flag 正则（品牌前缀 / 大写前缀 / 通用 前缀{内容} 外形）**且**是干净的可打印串
//     **且**不是占位符形态（见 flagPlaceholderRe）
//   - 1：非空但无 flag 外形（视为诊断提示，不当命中）；或混有不可打印字节的乱码；
//     或是题面格式声明占位符（DASCTF{init1-init2} 型）
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
		// 占位符形态（题面格式声明，如 DASCTF{init1-init2}）降级为诊断级：
		// 它与真 flag 同形同分，不过滤就会在优先级裁决中压掉真解。
		if score == 3 && isPlaceholderFlag(f) {
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
// registrySweepTimeout 注册表全量扫描的时间预算。
//
// 默认值从 6s 提到 20s（2026-09-28 依据 CI 实测数据调整）：
//   - CI（共享 runner + `go test -race`）上该基准集单题耗时最高 **6.849s**（artifact_png_lsb），
//     已经超过原 6s 预算 —— 意味着**尊重 ctx 的求解器会被超时砍掉、结果直接丢失**
//     （不尊重 ctx 的纯计算求解器如 bfxZipInner 不受影响）。
//   - 决赛单题时间预算是分钟级，多等 14s 无实质影响；而"慢环境下丢求解器结果"= 直接丢分。
//   - 仍可用环境变量覆盖：SECAUTOMIND_REGISTRY_SWEEP_MS（毫秒，>0 生效）。
func registrySweepTimeout() time.Duration {
	if v := os.Getenv("SECAUTOMIND_REGISTRY_SWEEP_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 20 * time.Second
}

// registrySweepEnabled 是否启用注册表全量扫描（生产 Presolve 会并入）。
// webExploitApplies URL 渗透链求解器（WebExploitChain）的启用门控：
// 仅 web 类或未声明类别的题目启用。
//
// 2026-10-15 立尺实测（specialcurve2，crypto 题，附件注释含 writeup 链接
// cn-sec.com）：九件套对该不可达/无关主机发起真实请求并干等满超时——
// 逐 solver 计时 jwt 40s / upload 29.8s / web_exploit 25s / gql 6.8s /
// deser 6.3s / xxe 4.5s，生产路径单题 60.002s（跨-bench 子集测试 4 遍
// 扫描 267s 的主因）；关断后单题 18ms。且 deser/xxe 从第三方页面刮回
// `body{margin:0;padding:0}` 外形串污染 solved 判定（不匹配 sha256，
// 但会挤占引擎优先级）。非 web 题文本中的 URL 基本是来源/ writeup 引用，
// 不是靶机——按题目类别门控是唯一可靠的区分信号。
func webExploitApplies(category string) bool {
	return category == "" || category == string(CategoryWebS)
}

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
	// verbatim 标记该候选的 flags[0] 是否原样出现在输入文本里（即「原文刮中」
	// 而非变换产出）。用于同分裁决：密文本身常具 flag 外形（如维吉尼亚题面的
	// OHGF{...}），原文扫描（flag_scan，priority 10）会与真解（解密产出，
	// priority 20）同 likeness 打平并按优先级胜出——把真解挤出局。生产
	// huntPresolve 用固定顺序规避（tryVigenereKnownKey 先于 scanFlags，
	// 见 presolve.go 注释），注册表裁决必须等价表达该语义。
	verbatim bool
}

// isVerbatimFlag 候选的 flags[0] 是否原样出现在输入文本中（原文刮中 vs 变换产出）。
// 判据取 flags[0]——机验口径（sha256 比对）也只认 Flags[0]。
func isVerbatimFlag(text string, flags []string) bool {
	if len(flags) == 0 {
		return false
	}
	return strings.Contains(text, flags[0])
}

// betterSweep 候选排序：先看「像不像 flag」，同等像则**变换产出优先于原文刮中**
// （verbatim 密文挤真解缺陷的修复，详见 sweepCandidate.verbatim 注释），
// 再比优先级，最后比名字保证确定性。
func betterSweep(a, b sweepCandidate) bool {
	if a.like != b.like {
		return a.like > b.like
	}
	if a.verbatim != b.verbatim {
		return !a.verbatim
	}
	if a.prio != b.prio {
		return a.prio < b.prio
	}
	return a.name < b.name
}

// presolveRegistrySweep 并发跑遍注册表内**所有** Enabled 求解器，
// 收集全部结果后按 flag 可信度裁决出最优命中。
// category 为题目类别（web/crypto/misc/reverse/pwn，空=未声明）：
// WebExploitChain 求解器仅在 webExploitApplies(category) 为真时参与，
// 避免非 web 题文本中的 URL（writeup/来源注释）触发真实渗透链干等超时。
//
// 与旧实现的本质区别：旧版「首个非空即返回」，会把诊断提示当命中，
// 且同一时刻只跑一个优先级组、高优先级组未命中才轮到下一组
// （=> 低优先级的正确解可能根本没机会跑）。新版一次跑全量。
func (p *Presolver) presolveRegistrySweep(ctx context.Context, text string, attachments map[string]string, category string) *PresolveResult {
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
		// URL 渗透链九件套按题目类别门控（见 webExploitApplies 注释）。
		if entry.WebExploitChain && !webExploitApplies(category) {
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
					res <- sweepCandidate{s.Name, s.Priority, cached.Flags, flagLikeness(cached.Flags), isVerbatimFlag(text, cached.Flags)}
				}
				return
			}
			flags := s.Solver(sweepCtx, text, attachments)
			recordSolverRun(s.Name)
			p.cache.Set(key, &PresolveResult{Solved: len(flags) > 0, Engine: s.Name, Flags: flags})
			if len(flags) > 0 {
				res <- sweepCandidate{s.Name, s.Priority, flags, flagLikeness(flags), isVerbatimFlag(text, flags)}
			}
		}(entry)
	}
	go func() {
		wg.Wait()
		close(res)
	}()

	var best *sweepCandidate
	for c := range res {
		// 只接受真 flag 外形（likeness>=minFlagLikenessForHit）；诊断/标签文本
		// 一律丢弃，否则孤立出现的诊断（如 exploit_chain 的"攻击链: ..."）会被
		// 当成命中返回并短路 Agent。见 minFlagLikenessForHit 注释。
		if c.like < minFlagLikenessForHit {
			continue
		}
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
	if r := p.presolveRegistrySweep(ctx, text, attachments, ch.Category); r != nil {
		p.logger.Info("presolve 命中（注册表驱动）",
			zap.String("engine", r.Engine), zap.Strings("flags", r.Flags))
		return r
	}
	// 兜底：西湖论剑 Python skills（吞并接入，fail-closed，无命中/环境缺失返回 nil）
	if pr := pythonFallbackResult(tryPythonLegacyFallback(text, attachments)); pr != nil {
		p.logger.Info("presolve 命中（xhlj_python 兜底）",
			zap.Strings("flags", pr.Flags))
		return pr
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
		Name: "web_exploit", Category: CategoryWebS, Priority: 1, WebExploitChain: true,
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
