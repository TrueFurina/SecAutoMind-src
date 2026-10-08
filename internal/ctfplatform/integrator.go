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
	"regexp"
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

// Platform 返回当前接线的平台实例（可能为 nil——未接线时 TryPresolve 仅做本地预解）。
func (i *PresolveAgentIntegrator) Platform() PlatformAPI {
	return i.platform
}

// SubmitFlag 经平台提交 flag（平台未接线时返回错误）。
// 决赛链路：Agent 推理命中后，可经此路径向真实平台提交，完成「预解/推理 → 提交」闭环。
func (i *PresolveAgentIntegrator) SubmitFlag(ctx context.Context, challengeID, flag string) (*SubmitResult, error) {
	if i.platform == nil {
		return nil, fmt.Errorf("平台未接线：无法提交 flag")
	}
	return i.platform.SubmitFlag(ctx, challengeID, flag)
}

// PrepareChallenge 为「用户粘贴题面辅助解题」之外的场景准备靶机与附件：
// 当能从平台拿到 challengeID（如机器人消息里带题号、或主动轮询匹配）时，自动
// 拉详情 → 起靶机 → 取访问地址 → 下附件，并把靶机地址/附件标记注入返回的 Challenge，
// 使其可直接交给 presolve/Agent 使用（与 poller 的 buildEnvAndInject/fetchAttachments 等价）。
//
// 设计（2026-10-08）：本方法是「可选能力」，不破坏既有 TryPresolve(ctx, message, nil) 行为。
// challengeID 为空时直接返回 nil（by-design：IM 路径当前无题号来源，默认不激活建靶机）。
// 是否要让 IM 机器人自动建靶机，是决赛运行模式决策，由调用方（agent.go）是否传入 challengeID 决定。
func (i *PresolveAgentIntegrator) PrepareChallenge(ctx context.Context, challengeID string) (*Challenge, error) {
	if i.platform == nil {
		return nil, fmt.Errorf("平台未接线：无法准备靶机")
	}
	if challengeID == "" {
		return nil, nil // by-design：无题号不激活
	}

	ch, err := i.platform.GetChallenge(ctx, challengeID)
	if err != nil || ch == nil {
		return nil, fmt.Errorf("取题目详情失败: %w", err)
	}

	// ① 建靶机（需要靶机的题）
	if ch.HasInstance {
		if _, cerr := i.platform.CreateInstance(ctx, challengeID); cerr != nil {
			i.logger.Warn("起靶机失败（继续尝试取地址）",
				zap.String("challenge_id", challengeID), zap.Error(cerr))
		}
		if acc, aerr := i.platform.GetAccess(ctx, challengeID); aerr == nil && acc != nil && acc.URL != "" {
			if ch.Extra == nil {
				ch.Extra = map[string]interface{}{}
			}
			ch.Extra["target_url"] = acc.URL
			if !strings.Contains(ch.Description, acc.URL) {
				ch.Description += "\n靶机地址: " + acc.URL
			}
		}
	}

	// ② 下附件（有附件的题）
	if ch.HasAttachment {
		if paths, derr := i.platform.DownloadAttachment(ctx, challengeID); derr == nil && len(paths) > 0 {
			var b strings.Builder
			b.WriteString("\n[用户上传的文件]\n")
			for _, p := range paths {
				b.WriteString(fmt.Sprintf("- %s\n", p))
			}
			ch.Description += b.String()
		}
	}

	return ch, nil
}

// challengeRefPatterns 仅匹配显式标记，避免把题面里的任意数字误判为 challengeID
// （误判会导致给错误题目建靶机/下附件，是最贵的失败）。
var challengeRefPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:题号|编号|题目编号|题目ID|challenge\s+id|exercise[_\s]?id)[:：]?\s*(\d+)`),
	regexp.MustCompile(`#(\d{3,})`),
	regexp.MustCompile(`(?:挑战|题目)[:：]?\s*(\d+)`),
}

// ExtractChallengeRef 从机器人自由文本消息中提取 challengeID（DASCTF 数值 exerciseId）。
// 仅匹配显式标记（题号/编号/challenge id/#三位数以上/挑战/题目 + 数字），无匹配返回 ""。
// 返回 "" 时 PrepareChallenge 保持 by-design 不激活（不建靶机、不下附件）。
func ExtractChallengeRef(message string) string {
	for _, re := range challengeRefPatterns {
		if m := re.FindStringSubmatch(message); m != nil && m[1] != "" {
			return m[1]
		}
	}
	return ""
}
