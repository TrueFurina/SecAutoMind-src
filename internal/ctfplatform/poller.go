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

// RunOnce 执行一轮：拉题 → 对未处理的新题求解/提交。
func (p *Poller) RunOnce(ctx context.Context) ([]PollRecord, error) {
	challenges, err := p.platform.ListChallenges(ctx)
	if err != nil {
		return nil, fmt.Errorf("拉取题目列表失败: %w", err)
	}

	p.mu.Lock()
	var newChallenges []Challenge
	for _, ch := range challenges {
		if !p.processed[ch.ID] {
			newChallenges = append(newChallenges, ch)
		}
	}
	p.mu.Unlock()

	if len(newChallenges) == 0 {
		p.logger.Debug("轮询：无新题", zap.Int("已处理", len(p.processed)))
		return nil, nil
	}

	p.logger.Info("轮询：发现新题", zap.Int("count", len(newChallenges)))

	// 并发求解（受 maxConcurrency 限制）
	sem := make(chan struct{}, p.config.MaxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var records []PollRecord

	for _, ch := range newChallenges {
		wg.Add(1)
		go func(c Challenge) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rec := p.handleChallenge(ctx, &c)

			mu.Lock()
			records = append(records, *rec)
			p.records[c.ID] = rec
			p.processed[c.ID] = true
			mu.Unlock()
		}(ch)
	}
	wg.Wait()
	return records, nil
}

// RunForever 持续轮询（阻塞）。
func (p *Poller) RunForever(ctx context.Context) error {
	ticker := time.NewTicker(p.config.PollInterval)
	defer ticker.Stop()

	p.logger.Info("轮询器启动", zap.Duration("interval", p.config.PollInterval))

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("轮询器停止")
			return ctx.Err()
		case <-ticker.C:
			records, err := p.RunOnce(ctx)
			if err != nil {
				p.logger.Error("轮询失败", zap.Error(err))
				continue
			}
			for _, rec := range records {
				if rec.Accepted {
					p.logger.Info("✅ flag 已接受",
						zap.String("题目", rec.Title),
						zap.String("flag", rec.Flag))
				}
			}
		}
	}
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
