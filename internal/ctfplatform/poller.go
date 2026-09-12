package ctfplatform

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SolverFunc 定义求解函数签名：输入题目信息，输出候选 flag 列表。
type SolverFunc func(ctx context.Context, ch *Challenge) ([]string, error)

// BackoffAdvisor 平台抗打击建议接口（由 DasCTFPlatform 实现；可选注入 Poller）。
// Poller 据此动态拉长轮询间隔（连续 429 阶梯）或在 WAF 冷却期跳过本轮，
// 避免雪崩式打平台。
type BackoffAdvisor interface {
	BackoffSuggestion(base float64) float64
	WafBlockedSeconds() float64
	LastListOK() bool
}

// PollerConfig 轮询器配置。
type PollerConfig struct {
	PollInterval     time.Duration `json:"poll_interval"`      // 拉题间隔，默认 30s
	SolveTimeout     time.Duration `json:"solve_timeout"`      // 单题求解超时，默认 300s
	SubmitAfterSolve bool          `json:"submit_after_solve"` // 解出后自动提交
	MaxRetrySubmit   int           `json:"max_retry_submit"`   // 提交失败重试次数，默认 2
	MaxConcurrency   int           `json:"max_concurrency"`    // 跨题并发上限，默认 2
}

func DefaultPollerConfig() PollerConfig {
	return PollerConfig{
		PollInterval:     30 * time.Second,
		SolveTimeout:     300 * time.Second,
		SubmitAfterSolve: true,
		MaxRetrySubmit:   2,
		MaxConcurrency:   2,
	}
}

// Poller 平台轮询器：定时拉题 → 去重 → 求解 → 提交。
type Poller struct {
	platform PlatformAPI
	solver   SolverFunc
	config   PollerConfig
	logger   *zap.Logger
	advisor  BackoffAdvisor // 可选：平台抗打击建议（连续 429 阶梯 / WAF 冷却）

	mu        sync.Mutex
	processed map[string]bool        // 已处理题目 ID（去重）
	records   map[string]*PollRecord // 审计记录
}

// NewPoller 创建轮询器。
func NewPoller(platform PlatformAPI, solver SolverFunc, config PollerConfig, logger *zap.Logger) *Poller {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Poller{
		platform:  platform,
		solver:    solver,
		config:    config,
		logger:    logger,
		processed: make(map[string]bool),
		records:   make(map[string]*PollRecord),
	}
}

// SetAdvisor 注入平台抗打击建议（可选；nil 表示不做动态退避/WAF 跳过）。
func (p *Poller) SetAdvisor(advisor BackoffAdvisor) {
	p.advisor = advisor
}

// RunOnce 执行一轮：拉题 → 对未处理的新题求解/提交。
func (p *Poller) RunOnce(ctx context.Context) ([]PollRecord, error) {
	challenges, err := p.platform.ListChallenges(ctx)
	if err != nil {
		return nil, fmt.Errorf("拉取题目列表失败: %w", err)
	}

	p.mu.Lock()
	var newChallenges []Challenge
	for _, ch := range challenges {
		// 题号为空 = 列表解析异常：既无法提交（exerciseId 无效），
		// 又会在去重表里坍缩成一个条目吞掉后续题，必须直接跳过。
		if ch.ID == "" {
			continue
		}
		if !p.processed[ch.ID] {
			newChallenges = append(newChallenges, ch)
		}
	}
	p.mu.Unlock()

	if len(newChallenges) == 0 {
		p.mu.Lock()
		n := len(p.processed)
		p.mu.Unlock()
		p.logger.Debug("轮询：无新题", zap.Int("已处理", n))
		return nil, nil
	}

	p.logger.Info("轮询：发现新题", zap.Int("count", len(newChallenges)))

	// 并发求解（受 maxConcurrency 限制）
	sem := make(chan struct{}, p.config.MaxConcurrency)
	var wg sync.WaitGroup
	var recMu sync.Mutex // 仅保护 records 切片；共享 map 一律走 p.mu（GetRecords 亦读 p.mu）
	var records []PollRecord

	for _, ch := range newChallenges {
		wg.Add(1)
		go func(c Challenge) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rec := p.handleChallenge(ctx, &c)

			recMu.Lock()
			records = append(records, *rec)
			recMu.Unlock()
			p.mu.Lock()
			p.records[c.ID] = rec
			p.processed[c.ID] = true
			p.mu.Unlock()
		}(ch)
	}
	wg.Wait()
	return records, nil
}

// RunForever 持续轮询（阻塞）。
// 引入 advisor 后，轮询节奏由「固定 ticker」改为「动态退避」：
//   - ⑤ WAF 冷却中 → 跳过本轮，休眠至冷却结束，避免雪崩；
//   - ④ 连续 429 ≥3 → 按阶梯拉长本轮等待（30s/60s/120s/300s），而非死磕平台。
func (p *Poller) RunForever(ctx context.Context) error {
	p.logger.Info("轮询器启动",
		zap.Duration("interval", p.config.PollInterval),
		zap.Bool("submit_after_solve", p.config.SubmitAfterSolve))

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("轮询器停止")
			return ctx.Err()
		default:
		}

		// ⑤ WAF 冷却中：跳过本轮，休眠至冷却结束
		if p.advisor != nil {
			if secs := p.advisor.WafBlockedSeconds(); secs > 0 {
				p.logger.Warn("WAF 风控冷却中，跳过本轮", zap.Float64("剩余秒", secs))
				if err := p.sleepCtx(ctx, time.Duration(secs)*time.Second); err != nil {
					return err
				}
				continue
			}
		}

		records, err := p.RunOnce(ctx)
		if err != nil {
			p.logger.Error("轮询失败", zap.Error(err))
		} else {
			for _, rec := range records {
				if rec.Accepted {
					p.logger.Info("✅ flag 已接受",
						zap.String("题目", rec.Title),
						zap.String("flag", rec.Flag))
				}
			}
		}

		// ④ 连续 429 阶梯退避：建议间隔 > 基础间隔时拉长本轮等待
		wait := p.config.PollInterval
		if p.advisor != nil {
			if s := p.advisor.BackoffSuggestion(p.config.PollInterval.Seconds()); s > wait.Seconds() {
				wait = time.Duration(s) * time.Second
			}
		}
		if err := p.sleepCtx(ctx, wait); err != nil {
			return err
		}
	}
}

// sleepCtx 在 ctx 取消前休眠 d（尊重生命周期，便于优雅退出）。
func (p *Poller) sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// FilterFlagCandidates 仅保留 flag 形态的候选，杜绝把 "hash_crack: x=weak" 这类
// 非 flag 文本误提交到真实平台。旗形判定沿用 flagRegex。
func FilterFlagCandidates(flags []string) []string {
	var out []string
	for _, f := range flags {
		if flagRegex.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

// GetRecords 获取审计记录。
func (p *Poller) GetRecords() map[string]*PollRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make(map[string]*PollRecord, len(p.records))
	for k, v := range p.records {
		result[k] = v
	}
	return result
}

// handleChallenge 处理单题：求解 → 提交（含墙钟止损）。
func (p *Poller) handleChallenge(ctx context.Context, ch *Challenge) *PollRecord {
	rec := &PollRecord{
		ChallengeID: ch.ID,
		Title:       ch.Title,
		Category:    ch.Category,
		StartedAt:   time.Now(),
	}

	// 墙钟止损
	solveCtx, cancel := context.WithTimeout(ctx, p.config.SolveTimeout)
	defer cancel()

	// 求解
	flags, err := p.solver(solveCtx, ch)
	if err != nil {
		rec.Error = err.Error()
		rec.FinishedAt = time.Now()
		p.logger.Warn("求解失败", zap.String("题目", ch.Title), zap.Error(err))
		return rec
	}

	if len(flags) == 0 {
		rec.Error = "无候选 flag"
		rec.FinishedAt = time.Now()
		return rec
	}

	// 兜底闸门：只认 flag 形态候选。Poller 是被外部复用的公开 API，
	// 调用方若未过滤，此处必须拦住 "hash_crack: x=weak" 之类文本误提交真实平台。
	flags = FilterFlagCandidates(flags)
	if len(flags) == 0 {
		rec.Error = "候选均不符合 flag 格式，已拦截"
		rec.FinishedAt = time.Now()
		p.logger.Warn("拦截非 flag 形态候选", zap.String("题目", ch.Title))
		return rec
	}

	rec.Flag = flags[0]
	rec.ExtraCandidates = flags

	// 提交
	if p.config.SubmitAfterSolve {
		for i, flag := range flags {
			if i > p.config.MaxRetrySubmit {
				break
			}
			result, submitErr := p.platform.SubmitFlag(ctx, ch.ID, flag)
			if submitErr != nil {
				rec.Error = submitErr.Error()
				continue
			}
			rec.Submitted = true
			rec.Accepted = result.Correct
			rec.Detail = result.Detail
			if result.Correct {
				rec.Flag = flag
				break
			}
		}
	}

	rec.FinishedAt = time.Now()
	return rec
}

// flagRegex 通用 flag 格式匹配。
var flagRegex = regexp.MustCompile(`(?i)(?:flag|ctf|dasctf)\{[^}]{3,}\}`)

// ExtractFlags 从文本中提取 flag 候选。
func ExtractFlags(text string) []string {
	matches := flagRegex.FindAllString(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}
