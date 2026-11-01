package runnerl3

// 输出预算与截断观测的回归测试（2026-11-01）。
//
// ## 存在原因
//
// 推理型模型（deepseek-reasoner / deepseek-v4-*）先把 token 花在
// reasoning_content 上，**推理 token 与正文共用同一个 max_tokens 预算**。
// eino 自己的 Options.MaxTokens 注释就写着：
//
//	"if reached the max tokens, the model will stop generating, and mostly
//	 return a finish reason of \"length\"."
//
// 预算是 4096 还是 8000，决定的不是"答案好坏"，而是 content 是完整正文
// 还是空/半截 JSON —— 后者在报告里与"模型不会"完全同形。
//
// ## 这两类断言为什么必须变红
//
// ① 默认值断言：把 8000 改回 4096 必须红。否则"抬预算"这件事没有任何
//    防护，下一个人随手调小又回到无从分辨的状态。
// ② 截断计数断言：删掉 finish_reason 检查必须红。否则"被截断"重新变成
//    不可观测 —— 本项目已有多次"实现了但没接线"的先例。

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// captureModel 记录每次 Generate 实际收到的 options，供断言读回真实预算。
type captureModel struct {
	resps    []*schema.Message
	calls    int
	lastOpts []model.Option
}

func (m *captureModel) Generate(_ context.Context, _ []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	m.calls++
	m.lastOpts = opts
	if len(m.resps) == 0 {
		return &schema.Message{Role: schema.Assistant, Content: "无响应"}, nil
	}
	if m.calls <= len(m.resps) {
		return m.resps[m.calls-1], nil
	}
	return m.resps[len(m.resps)-1], nil
}

func (m *captureModel) Stream(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, fmt.Errorf("capture: stream not implemented")
}

// maxTokensOf 从捕获到的 options 里读回实际下发的 MaxTokens。
func maxTokensOf(t *testing.T, m *captureModel) int {
	t.Helper()
	if len(m.lastOpts) == 0 {
		t.Fatal("模型没有收到任何 options —— 预算根本没下发")
	}
	o := model.GetCommonOptions(nil, m.lastOpts...)
	if o == nil || o.MaxTokens == nil {
		t.Fatal("options 里没有 MaxTokens —— 未显式设预算，推理模型会截断正文")
	}
	return *o.MaxTokens
}

// 未设环境变量时，输出预算必须是 8000（推理 token 与正文共用，实测下限）。
func TestOutputBudgetDefaultIs8000(t *testing.T) {
	t.Setenv("RUNNER_LLM_MAX_TOKENS", "") // 空串 → envInt 回落到默认值

	m := &captureModel{resps: []*schema.Message{{Role: schema.Assistant, Content: "ok"}}}
	ff := newTestFallback(m, 1, 1)
	if _, err := ff.Solve(context.Background(), testChallenge()); err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}

	if got := maxTokensOf(t, m); got != 8000 {
		t.Fatalf("默认输出预算应为 8000（推理 token 与正文共用），实际 %d", got)
	}
}

// 环境变量显式设置时必须生效（运营需要在长链题上继续上调）。
func TestOutputBudgetEnvOverride(t *testing.T) {
	t.Setenv("RUNNER_LLM_MAX_TOKENS", "12345")

	m := &captureModel{resps: []*schema.Message{{Role: schema.Assistant, Content: "ok"}}}
	ff := newTestFallback(m, 1, 1)
	if _, err := ff.Solve(context.Background(), testChallenge()); err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}

	if got := maxTokensOf(t, m); got != 12345 {
		t.Fatalf("env 覆盖未生效，期望 12345，实际 %d", got)
	}
}

// finish_reason=="length" 必须被计进收口归因（否则截断重新不可观测）。
func TestTruncationCountedInOutcome(t *testing.T) {
	truncatedResp := func() *schema.Message {
		return &schema.Message{
			Role:    schema.Assistant,
			Content: "", // 推理烧完预算，正文为空 —— 正是要抓的形态
			ResponseMeta: &schema.ResponseMeta{
				FinishReason: "length",
			},
		}
	}

	m := &captureModel{resps: []*schema.Message{truncatedResp(), truncatedResp()}}
	ff := newTestFallback(m, 2, 2)
	if _, err := ff.Solve(context.Background(), testChallenge()); err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}

	o := ff.LastOutcome()
	if o.Truncated == 0 {
		t.Fatalf("finish_reason=length 未被计入 Truncated，收口归因 %+v", o)
	}
	if o.Reason != ReasonNoCandidate {
		t.Fatalf("截断题仍应归为 no_candidate（本改动只做可见化，不改分类），实际 %q", o.Reason)
	}
}

// finish_reason=="stop" 不得误计为截断（否则"截断"这个信号会被稀释成噪音）。
func TestNoTruncationOnNormalStop(t *testing.T) {
	m := &captureModel{resps: []*schema.Message{{
		Role:         schema.Assistant,
		Content:      "这题我没做出来，需要更多信息。",
		ResponseMeta: &schema.ResponseMeta{FinishReason: "stop"},
	}}}
	ff := newTestFallback(m, 2, 2)
	if _, err := ff.Solve(context.Background(), testChallenge()); err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}

	if o := ff.LastOutcome(); o.Truncated != 0 {
		t.Fatalf("正常收尾被误计为截断 %d 次，收口归因 %+v", o.Truncated, o)
	}
}

// 只返回 reasoning、正文为空（且没有工具调用）→ 预算被推理吃掉，必须计入。
// 这一类的 finish_reason 可能不是 "length"，只看 length 会漏。
func TestReasoningOnlyCountedAsTruncation(t *testing.T) {
	reasoningOnly := func() *schema.Message {
		return &schema.Message{
			Role:             schema.Assistant,
			Content:          "", // 正文没写出来
			ReasoningContent: "先看题目描述……再考虑 RSA 因式分解……",
			ResponseMeta:     &schema.ResponseMeta{FinishReason: "stop"},
		}
	}

	m := &captureModel{resps: []*schema.Message{reasoningOnly(), reasoningOnly()}}
	ff := newTestFallback(m, 2, 2)
	if _, err := ff.Solve(context.Background(), testChallenge()); err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}

	if o := ff.LastOutcome(); o.Truncated == 0 {
		t.Fatalf("「只思考不答」未被计入 Truncated，收口归因 %+v", o)
	}
}

// 反例（本改动最容易踩的坑）：带 ToolCalls 时 content 为空是 OpenAI 格式的
// **正常**路径（模型调工具时不写正文）。若不排除，每轮工具调用都会被误计
// 成截断，这个信号就彻底失去意义。
func TestToolCallWithEmptyContentIsNotTruncation(t *testing.T) {
	m := &captureModel{resps: []*schema.Message{{
		Role:             schema.Assistant,
		Content:          "", // 正常：调工具时不写正文
		ReasoningContent: "我需要先看看附件里有什么，调个工具。",
		ToolCalls: []schema.ToolCall{{
			ID:       "call-empty-content",
			Function: schema.FunctionCall{Name: "no_such_tool", Arguments: "{}"},
		}},
		ResponseMeta: &schema.ResponseMeta{FinishReason: "tool_calls"},
	}}}
	ff := newTestFallback(m, 2, 2)
	if _, err := ff.Solve(context.Background(), testChallenge()); err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}

	if o := ff.LastOutcome(); o.Truncated != 0 {
		t.Fatalf("带工具调用的空正文被误计为截断 %d 次（这是正常路径），收口归因 %+v",
			o.Truncated, o)
	}
}
