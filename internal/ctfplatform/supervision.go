// supervision.go —— 监督反思/错误分类 Go 化（融合 P1-9，2026-10-25）。
//
// 蓝本：西湖论剑 ctf_agent core/error_taxonomy.py + core/budget_reflection.py
// （纯规则、无 LLM、可单测——A 库 2026-09/10 实战打磨版，规则注释里的实证
// 编号均为 A 库原案例，移植时保留以防空烧预算的历史教训复发）。
//
// 两个组成部分：
//  1. 错误分类单一真值源（TRUNCATED / NON_RETRYABLE / 瞬时）——所有重试层
//     必须从这里取口径，不得各写一份字面量（A 库 2026-09-23 实证：口径散落
//     各层导致单题被 4 段步循环重烧 111K token 零候选）。
//  2. Budget 反思（CONTINUE / SWITCH / ABANDON）——预算比例 + 进展信号 +
//     信心 + token 口径的确定性早停/换路。规则⑥含 2026-10-03 修正：
//     零候选 ABANDON 需 token 也过 60%，防「步数口径先到、token 还剩大半」
//     的过早认输（race_abandon ×5 实证）。
package ctfplatform

import (
	"context"
	"strings"
)

// ── ① 错误分类单一真值源 ──────────────────────────────────────────

// ErrorClass 错误类别（对 raw error 字符串的模式分类）。
type ErrorClass string

const (
	// ClassBudgetExceeded 预算耗尽（token/步数）
	ClassBudgetExceeded ErrorClass = "budget_exceeded"
	// ClassWallclockTimeout Agent 内部墙钟止损
	ClassWallclockTimeout ErrorClass = "wallclock_timeout"
	// ClassWallclockKilled 评测器外部 wait_for 掐断（真 infra 故障）
	ClassWallclockKilled ErrorClass = "wallclock_killed"
	// ClassRaceAbandon 预算反思早停
	ClassRaceAbandon ErrorClass = "race_abandon"
	// ClassSolverException solver 抛异常
	ClassSolverException ErrorClass = "solver_exception"
	// ClassNotAttempted 显式未尝试
	ClassNotAttempted ErrorClass = "not_attempted"
	// ClassRateLimited 限流（瞬时）
	ClassRateLimited ErrorClass = "rate_limited"
	// ClassProviderError provider 侧错误（瞬时）
	ClassProviderError ErrorClass = "provider_error"
	// ClassProviderCircuitOpen provider 熔断打开（401/402/403）
	ClassProviderCircuitOpen ErrorClass = "provider_circuit_open"
	// ClassInfraError 基础设施错误（瞬时）
	ClassInfraError ErrorClass = "infra_error"
	// ClassNoCredential 无凭证（铁律：不算推理失败）
	ClassNoCredential ErrorClass = "infra_no_credential"
	// ClassUnknown 未分类（正常判负类，如「无候选 flag」）
	ClassUnknown ErrorClass = "unknown"
)

// truncatedClasses 「被外部条件掐断」的类别：题未走完正常求解流程，
// solve_rate 对它们不构成能力度量。**不含** no_output 类正常判负。
func truncatedClasses() map[ErrorClass]bool {
	return map[ErrorClass]bool{
		ClassBudgetExceeded:      true,
		ClassWallclockTimeout:    true,
		ClassWallclockKilled:     true,
		ClassRaceAbandon:         true,
		ClassSolverException:     true,
		ClassNotAttempted:        true,
		ClassRateLimited:         true,
		ClassProviderError:       true,
		ClassProviderCircuitOpen: true,
		ClassInfraError:          true,
		ClassNoCredential:        true,
	}
}

// nonRetryableClasses 终态失败：本轮内不可通过「立即重跑同一题」恢复，
// 每一层重试循环都必须短路（重跑=把预算/墙钟再烧一遍）。
// 瞬时类（rate_limited/provider_error/infra_error/no_credential）保留重试。
func nonRetryableClasses() map[ErrorClass]bool {
	return map[ErrorClass]bool{
		ClassBudgetExceeded:   true,
		ClassWallclockTimeout: true,
		ClassWallclockKilled:  true,
		ClassRaceAbandon:      true,
		ClassSolverException:  true,
		ClassNotAttempted:     true,
	}
}

// IsTruncatedError 报告口径：该类别题是否被外部条件掐断（非能力判负）。
func IsTruncatedError(c ErrorClass) bool { return truncatedClasses()[c] }

// IsNonRetryable 重试口径：该类别是否终态失败（重试循环须短路）。
func IsNonRetryable(c ErrorClass) bool { return nonRetryableClasses()[c] }

// ClassifyError 对 raw error 字符串做模式分类（小写匹配，前缀宽松）。
// 未命中任何模式返回 ClassUnknown（正常判负类，不触发任何短路）。
func ClassifyError(raw string) ErrorClass {
	s := strings.ToLower(raw)
	switch {
	case strings.Contains(s, "budget_exceeded") || strings.Contains(s, "预算耗尽"):
		return ClassBudgetExceeded
	case strings.Contains(s, "wallclock_killed"), strings.Contains(s, "wait_for") && strings.Contains(s, "kill"):
		return ClassWallclockKilled
	case strings.Contains(s, "wallclock_timeout"), strings.Contains(s, "墙钟"),
		strings.Contains(s, "context deadline exceeded"), strings.Contains(s, "solver timeout"):
		return ClassWallclockTimeout
	case strings.Contains(s, "race_abandon") || strings.Contains(s, "早停"):
		return ClassRaceAbandon
	case strings.Contains(s, "not_attempted") || strings.Contains(s, "未尝试"):
		return ClassNotAttempted
	case strings.Contains(s, "rate_limited"), strings.Contains(s, "429"):
		return ClassRateLimited
	case strings.Contains(s, "circuit_open"), strings.Contains(s, "熔断"):
		return ClassProviderCircuitOpen
	case strings.Contains(s, "401"), strings.Contains(s, "402"), strings.Contains(s, "403"),
		strings.Contains(s, "provider_error"):
		return ClassProviderError
	case strings.Contains(s, "no_credential"), strings.Contains(s, "无凭证"):
		return ClassNoCredential
	case strings.Contains(s, "infra_error"), strings.Contains(s, "infra"):
		return ClassInfraError
	case strings.Contains(s, "panic") || strings.Contains(s, "exception"):
		return ClassSolverException
	default:
		return ClassUnknown
	}
}

// ── ② Budget 反思（纯规则、无 LLM） ────────────────────────────────

// 反思决策
const (
	DecisionContinue = "CONTINUE"
	DecisionSwitch   = "SWITCH"
	DecisionAbandon  = "ABANDON"
)

// SupervisionState 预算/时间快照。指针字段 nil = 未知（对应 A 库 None 语义：
// 该信号不参与判定，向后兼容），非 nil 0 值 = 明确信号。
type SupervisionState struct {
	BudgetTotal int      // 步数预算（默认 12）
	BudgetUsed  int      // 已用步数
	Candidates  *int     // 本次求解至今的候选 flag 数（不可自欺硬信号）
	TokenRatio  *float64 // 真实 token 用量 / 单题预算（0..1）
	Challenge   string   // 题目标识（仅遥测落盘用；不参与判定）
}

// SupervisionStep 一步的进展信号（最小接口：非空 observation 且无错误）。
type SupervisionStep struct {
	Observation string
	ErrCategory string // 空串 = 无错
}

func (s SupervisionStep) madeProgress() bool {
	return strings.TrimSpace(s.Observation) != "" && s.ErrCategory == ""
}

// SupervisionDecision 反思结果。
type SupervisionDecision struct {
	Decision string
	Reason   string
	Metrics  map[string]any
}

// ReflectSupervision 核心反思（确定性、无 LLM）。confidence nil 视为 0.5 中性。
// 消费方：agent 求解循环每 N 步调用；ABANDON → 提前收口该题；
// SWITCH → 交监督层换策略（换工具面/换模型档）；CONTINUE → 继续。
// 每次调用经包级账本（若已 Enable）落盘一条遥测（fail-open，见 supervision_ledger.go）。
func ReflectSupervision(state SupervisionState, steps []SupervisionStep, confidence *float64) SupervisionDecision {
	dec := reflectSupervisionCore(state, steps, confidence)
	recordSupervision(state, dec)
	return dec
}

func reflectSupervisionCore(state SupervisionState, steps []SupervisionStep, confidence *float64) SupervisionDecision {
	total := state.BudgetTotal
	if total < 1 {
		total = 12
	}
	used := state.BudgetUsed
	if used < 0 {
		used = 0
	}
	if used > total {
		used = total
	}
	ratio := float64(used) / float64(total)
	conf := 0.5
	if confidence != nil {
		conf = *confidence
	}

	// 近 10 步窗口进展 + 尾部连续无进展
	window := steps
	if len(window) > 10 {
		window = window[len(window)-10:]
	}
	progressInWindow := 0
	for _, s := range window {
		if s.madeProgress() {
			progressInWindow++
		}
	}
	noProgressRecent := progressInWindow == 0
	trailing := 0
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].madeProgress() {
			break
		}
		trailing++
	}

	metrics := map[string]any{
		"budget_ratio":         ratio,
		"confidence":           conf,
		"progress_in_window":   progressInWindow,
		"trailing_no_progress": trailing,
		"candidates_found":     state.Candidates,
		"token_ratio":          state.TokenRatio,
	}
	hasCand := state.Candidates != nil && *state.Candidates > 0

	// ① 预算将尽 + 零进展 + 低信心 → 早停（候选在手时不早停：主循环立即收敛）
	if ratio >= 0.85 && noProgressRecent && conf < 0.4 && !hasCand {
		return SupervisionDecision{DecisionAbandon,
			"预算将尽(>=85%)+近期零进展+低信心：早停避免空烧", metrics}
	}
	// ② 过半预算 + 低信心 + 连续>=4步无进展 → 换策略
	if ratio >= 0.5 && conf < 0.3 && trailing >= 4 {
		return SupervisionDecision{DecisionSwitch,
			"过半预算+低信心+连续>=4步无进展：建议换策略", metrics}
	}
	// ⑥ 全程零候选 + 消耗>=60% + 步数>=5 + (token 未知或也>=60%) → 早停
	// （候选 flag 数是不可自欺硬信号；token 双口径门防步数口径先到时误降）
	if state.Candidates != nil && *state.Candidates <= 0 &&
		ratio >= 0.6 && used >= 5 &&
		(state.TokenRatio == nil || *state.TokenRatio >= 0.6) {
		return SupervisionDecision{DecisionAbandon,
			"消耗>=60%且全程零候选 flag：无收敛信号，早停避免空烧（候选口径）", metrics}
	}
	// ③ 预算充足 + 信心尚可 → 继续
	if ratio < 0.5 && conf >= 0.5 {
		return SupervisionDecision{DecisionContinue, "预算充足+信心尚可：继续", metrics}
	}
	// ④ 预算偏紧但信心高 → 继续收敛
	if ratio >= 0.7 && conf >= 0.6 {
		return SupervisionDecision{DecisionContinue, "预算偏紧但信心高：继续收敛", metrics}
	}
	// ⑤ 默认继续
	return SupervisionDecision{DecisionContinue, "默认继续", metrics}
}

// ── ③ poller 接线：错误分类落 PollRecord ─────────────────────────

// classifyRecordError 对 PollRecord.Error 做分类（nil-safe）。
// 消费：看板/终报按 IsTruncatedError 区分「能力判负」与「被掐断」；
// 任何上层重试循环按 IsNonRetryable 短路。
func classifyRecordError(rec *PollRecord) {
	if rec == nil {
		return
	}
	rec.ErrorClass = string(ClassifyError(rec.Error))
}

// withSolveTimeout 供求解层复用的墙钟包装（分类由 classifyRecordError 兜底）。
var _ = context.Background
