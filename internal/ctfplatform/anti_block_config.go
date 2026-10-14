package ctfplatform

import (
	"net/http"
	"time"
)

// AntiBlockOptions 抗打击治理的配置面（总纲 §2.4：**config 开关化、默认开、一键回退**）。
//
// 设计取舍——为什么对外是 Enabled 正向位、对内却是 antiBlockDisabled 反向零值位：
// 零值 `DasCTFPlatform{}` 必须等价于「7 项全开」。既有测试与调用方大量直接构造
// 结构体再逐字段赋值（`p.MaxRetries = 5` / `p.listCacheTTL = 200ms`），若把开关
// 做成正向零值，这些路径会在无人察觉的情况下**静默退化为朴素直连**，而功能测试
// 照不出来——这恰恰就是初赛被 37 次 429 打爆的成因。故零值取「开」。
type AntiBlockOptions struct {
	// Enabled 总开关。false = 一键回退：7 项抗打击机制全部停用，退化为朴素直连
	// （单次请求不重试、不解析 Retry-After、不计连续 429、不给阶梯建议、
	// 不冷却 WAF、不缓存列表、不复用连接）。
	Enabled bool

	// MaxRetries 最大重试次数；>0 生效，<=0 沿用包内默认（5）。
	MaxRetries int
	// RetryBackoff 指数退避基准；>0 生效，<=0 沿用包内默认（2s）。
	RetryBackoff time.Duration
	// WAFTimeout 403 冷却时长；>0 生效，<=0 沿用包内默认（300s）。
	WAFTimeout time.Duration
	// ListCacheTTL 列表缓存 TTL。nil = 沿用包内默认（10s）；显式指向 0 = 关闭缓存。
	// 用指针是为了区分「未配置」与「显式关缓存」——0 值语义在时长类型上有二义。
	ListCacheTTL *time.Duration
}

// SetAntiBlock 应用抗打击治理配置面。
//
// **调用时机是接线期（构造后、开始服务前），不是热路径**：本方法会改
// `MaxRetries`/`RetryBackoff`/`WAFTimeout`/`listCacheTTL` 与 `HTTPClient.Transport`，
// 其中 Transport 由 `http.Client` 内部并发读取，本包的 `mu` 保护不到它。
// 若将来确实需要运行时热切换，必须改为「整体替换客户端引用 + 原子指针」，
// 不能只是在方法里加锁。
//
// **默认开**由零值保证：不调用本方法时 7 项全开，行为与接线前逐字节一致。
// **一键回退** = `SetAntiBlock(AntiBlockOptions{Enabled: false})`：单个布尔位把
// ①指数退避重试 ②Retry-After 尊重 ③连续 429 计数 ④429 阶梯退避建议
// ⑤403 WAF 冷却 ⑥列表 TTL 缓存 ⑦HTTP 连接复用 一次性退回朴素直连，
// 用于赛时抗打击层一旦引入回归时的快速兜底（总纲 §6 风险预案同款要求）。
func (p *DasCTFPlatform) SetAntiBlock(o AntiBlockOptions) {
	p.mu.Lock()
	p.antiBlockDisabled = !o.Enabled
	if !o.Enabled {
		// 回退时**清零抗打击状态**：否则会出现「开关已关、残留计数/冷却仍在影响
		// 行为」的半开状态——回退不彻底，故障排查时也看不出到底退没退干净。
		p.consec429 = 0
		p.wafBlockedUntil = time.Time{}
		p.listCache = nil
		p.listCacheAt = time.Time{}
	} else {
		if o.MaxRetries > 0 {
			p.MaxRetries = o.MaxRetries
		}
		if o.RetryBackoff > 0 {
			p.RetryBackoff = o.RetryBackoff
		}
		if o.WAFTimeout > 0 {
			p.WAFTimeout = o.WAFTimeout
		}
		if o.ListCacheTTL != nil {
			p.listCacheTTL = *o.ListCacheTTL
		}
	}
	p.mu.Unlock()

	p.setConnectionReuse(o.Enabled)
}

// AntiBlockDisabled 暴露「一键回退」位（true = 7 项已停用），供观测与门禁断言。
func (p *DasCTFPlatform) AntiBlockDisabled() bool {
	return !p.antiBlockOn()
}

// antiBlockOn 抗打击治理是否生效。零值平台返回 true —— 「默认开」。
func (p *DasCTFPlatform) antiBlockOn() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.antiBlockDisabled
}

// setConnectionReuse ⑦ 连接复用开关。
//
// 关闭时必须先克隆出**私有** Transport 再改 DisableKeepAlives。直接写
// `http.DefaultTransport.(*http.Transport).DisableKeepAlives = true` 会改到进程内
// 全局共享的 DefaultTransport：本想只把这个 CTF 客户端退回朴素直连，实际却把整个
// 进程的 HTTP 连接复用一起关掉——回退动作自身变成事故源。
func (p *DasCTFPlatform) setConnectionReuse(enabled bool) {
	if p.HTTPClient == nil {
		return
	}
	tr, ok := p.HTTPClient.Transport.(*http.Transport)
	if !ok {
		// Transport 为 nil（走 http.DefaultTransport）或自定义实现。
		// 开启方向不做改动（默认即复用）；关闭方向克隆一份私有副本再改。
		if enabled {
			return
		}
		base, _ := http.DefaultTransport.(*http.Transport)
		if base == nil {
			return
		}
		tr = base.Clone()
		p.HTTPClient.Transport = tr
	}
	tr.DisableKeepAlives = !enabled
}
