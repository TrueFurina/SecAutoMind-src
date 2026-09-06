// Package ctfplatform 提供 Agent 编排链路集成。
//
// 集成逻辑：在 Agent 推理之前，先跑 presolve 确定性预解层；
// 命中则直接返回候选 flag（0 token），未命中则交给 Agent 处理。
//
// 接入点：AgentHandler.ProcessMessageForRobot / RunDeepAgent 调用前。
package ctfplatform

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// PresolveAgentIntegrator 将 presolve 集成到 Agent 编排链路。
type PresolveAgentIntegrator struct {
	presolver *Presolver
	analyzer  *TaskAnalyzer
	platform  PlatformAPI
	logger    *zap.Logger
}

// NewPresolveAgentIntegrator 创建集成器。
func NewPresolveAgentIntegrator(presolver *Presolver, analyzer *TaskAnalyzer, platform PlatformAPI, logger *zap.Logger) *PresolveAgentIntegrator {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &PresolveAgentIntegrator{
		presolver: presolver,
		analyzer:  analyzer,
		platform:  platform,
		logger:    logger,
	}
}

// PresolveAttempt 表示一次 presolve 尝试结果。
type PresolveAttempt struct {
	Solved     bool     `json:"solved"`
	Engine     string   `json:"engine"`
	Flags      []string `json:"flags"`
	Detail     string   `json:"detail"`
	DurationMs int64    `json:"duration_ms"`
	SkipAgent  bool     `json:"skip_agent"`  // 是否跳过 Agent（命中则跳）
	RedirectTo string   `json:"redirect_to"` // 路由建议（如有）
}

// TryPresolve 在 Agent 推理前尝试确定性预解。
// 返回 nil 表示未命中（继续 Agent 推理）；返回非 nil 表示已解出（跳过 Agent）。
func (i *PresolveAgentIntegrator) TryPresolve(ctx context.Context, userMessage string, attachments map[string]string) *PresolveAttempt {
	start := time.Now()

	// 构造虚拟 Challenge 用于分析
	ch := &Challenge{
		Description: userMessage,
	}

	// 1. 任务分析/路由
	routes := i.analyzer.Analyze(ch, attachments)
	if len(routes) > 0 {
		best := routes[0]
		ch.Category = string(best.Category)
		i.logger.Info("任务路由",
			zap.String("category", string(best.Category)),
			zap.String("sub_type", best.SubType),
			zap.String("solver", best.Solver),
			zap.Float64("confidence", best.Confidence))
	}

	// 2. presolve 确定性预解
	result := i.presolver.Presolve(ctx, ch, attachments)

	attempt := &PresolveAttempt{
		Solved:     result.Solved,
		Engine:     result.Engine,
		Flags:      result.Flags,
		Detail:     result.Detail,
		DurationMs: time.Since(start).Milliseconds(),
	}

	if result.Solved && len(result.Flags) > 0 {
		attempt.SkipAgent = true
		i.logger.Info("presolve 命中，跳过 Agent 推理",
			zap.String("engine", result.Engine),
			zap.Strings("flags", result.Flags),
			zap.Int64("duration_ms", attempt.DurationMs))
	}

	return attempt
}

// FormatPresolveResult 格式化 presolve 结果为可读文本（返回给用户/日志）。
func FormatPresolveResult(attempt *PresolveAttempt) string {
	if attempt == nil || !attempt.Solved {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🎯 **确定性预解命中** [%s]\n", attempt.Engine))
	sb.WriteString(fmt.Sprintf("⏱️ 耗时: %dms（0 token 消耗）\n\n", attempt.DurationMs))
	sb.WriteString("**候选 Flag:**\n")
	for i, flag := range attempt.Flags {
		sb.WriteString(fmt.Sprintf("  %d. `%s`\n", i+1, flag))
	}
	return sb.String()
}

// ShouldSkipAgent 判断是否应跳过 Agent 推理。
func (i *PresolveAgentIntegrator) ShouldSkipAgent(attempt *PresolveAttempt) bool {
	return attempt != nil && attempt.SkipAgent && len(attempt.Flags) > 0
}
