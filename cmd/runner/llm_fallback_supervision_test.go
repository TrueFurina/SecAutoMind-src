// llm_fallback_supervision_test.go —— LLM 循环逐轮监督回归（听风 2026-10-25 第二刀）。
//
// 锁死的不变量：
//   A. 零候选空转题必须在预算 60%（used>=5，12 轮预算即第 8 轮）被监督
//      ABANDON 收口——省掉尾部 4 轮 token（A 库 race_abandon ×5 教训的
//      Go 侧落地；规则⑥的 used>=5 门槛要求预算 >= 8 才可达，故默认
//      maxRounds/maxToolCalls 必须保持 12，改小即红）。
//   B. 工具输出中出现候选 flag（不可自欺硬信号）→ 规则⑥不得触发，
//      循环必须跑满预算——监督不许杀死有收敛信号的努力。
//   C. 候选账本端到端：ABANDON 决策必须落监督消费率账本。
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

// fakeModel 脚本化模型：按预设队列吐响应（超出后重复最后一条），计数 Generate 调用。
type fakeModel struct {
	resps []*schema.Message
	calls int
}

func (m *fakeModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.calls++
	if m.calls <= len(m.resps) {
		return m.resps[m.calls-1], nil
	}
	return m.resps[len(m.resps)-1], nil
}

func (m *fakeModel) Stream(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, fmt.Errorf("fake: stream not implemented")
}

func toolResp(name, argsJSON string) *schema.Message {
	return &schema.Message{
		Role: schema.Assistant,
		ToolCalls: []schema.ToolCall{{
			ID:       "call-fake",
			Function: schema.FunctionCall{Name: name, Arguments: argsJSON},
		}},
	}
}

func textResp(content string) *schema.Message {
	return &schema.Message{Role: schema.Assistant, Content: content}
}

func newTestFallback(m model.BaseChatModel, rounds, toolCalls int) *llmFallback {
	return &llmFallback{
		model: m, logger: zap.NewNop(), enabled: true,
		maxRounds: rounds, maxToolCalls: toolCalls,
	}
}

func testChallenge() *ctfplatform.Challenge {
	return &ctfplatform.Challenge{Title: "监督测试题", Category: "misc"}
}

// A. 零候选空转 → 第 8 轮（8/12）ABANDON 收口，不跑满 12 轮。
func TestSupervisionAbandonsZeroCandidateLoop(t *testing.T) {
	m := &fakeModel{resps: []*schema.Message{toolResp("no_such_tool", "{}")}}
	ff := newTestFallback(m, 12, 12)

	flags, err := ff.solve(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}
	if flags != nil {
		t.Fatalf("零候选题应无产出，got %v", flags)
	}
	if m.calls != 8 {
		t.Fatalf("规则⑥应在第 8 轮收口（8/12≥60%% 且 used>=5），实际 %d 次调用", m.calls)
	}
}

// A'. 预算缩回 3/5（旧默认）时规则⑥不可达 → 必须跑满 —— 锁死「预算必须 >= 8」。
func TestSmallBudgetDefeatsSupervision(t *testing.T) {
	m := &fakeModel{resps: []*schema.Message{toolResp("no_such_tool", "{}")}}
	ff := newTestFallback(m, 3, 5) // 旧默认

	_, _ = ff.solve(context.Background(), testChallenge())
	if m.calls != 3 {
		t.Fatalf("3 轮预算下无监督介入，应跑满 3 轮，实际 %d", m.calls)
	}
}

// B. 工具输出含候选 flag → 规则⑥不得触发，跑满预算。
func TestSupervisionCandidateKeepsLoopAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ATTACH DUMP\nfound flag{cand_keepalive_1}\nend")
	}))
	defer srv.Close()

	m := &fakeModel{resps: []*schema.Message{
		toolResp("read_attachment", fmt.Sprintf(`{"attachment_url": %q}`, srv.URL+"/flag.txt")),
	}}
	ff := newTestFallback(m, 12, 12)

	flags, err := ff.solve(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}
	if flags != nil {
		t.Fatalf("模型未输出终局文本，应无产出，got %v", flags)
	}
	if m.calls != 12 {
		t.Fatalf("候选在手时监督不得收口，应跑满 12 轮，实际 %d", m.calls)
	}
}

// B'. 终局文本命中 → 正常返回候选（监督不得吞掉命中）。
func TestLLMFinalTextHitReturns(t *testing.T) {
	m := &fakeModel{resps: []*schema.Message{
		toolResp("no_such_tool", "{}"),
		toolResp("no_such_tool", "{}"),
		textResp("分析完毕，答案是 flag{real_hit_1}"),
	}}
	ff := newTestFallback(m, 12, 12)

	flags, err := ff.solve(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("solve 不应报错: %v", err)
	}
	if len(flags) != 1 || flags[0] != "flag{real_hit_1}" {
		t.Fatalf("应返回命中候选，got %v", flags)
	}
	if m.calls != 3 {
		t.Fatalf("第 3 轮文本命中即返回，实际 %d 次调用", m.calls)
	}
}

// C. 未启用 → 零模型调用。
func TestLLMFallbackDisabledNoModelCalls(t *testing.T) {
	m := &fakeModel{resps: []*schema.Message{textResp("x")}}
	ff := &llmFallback{model: m, logger: zap.NewNop(), enabled: false}

	flags, err := ff.solve(context.Background(), testChallenge())
	if err != nil || flags != nil {
		t.Fatalf("disabled 应 (nil,nil)，got (%v,%v)", flags, err)
	}
	if m.calls != 0 {
		t.Fatalf("disabled 不得调用模型，实际 %d", m.calls)
	}
}

// D. 账本端到端：ABANDON 决策必须落消费率账本（含题目标识）。
func TestSupervisionAbandonRecordedInLedger(t *testing.T) {
	ctfplatform.DisableSupervisionLedger()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := ctfplatform.EnableSupervisionLedger(path); err != nil {
		t.Fatalf("启用账本失败: %v", err)
	}
	t.Cleanup(ctfplatform.DisableSupervisionLedger)

	m := &fakeModel{resps: []*schema.Message{toolResp("no_such_tool", "{}")}}
	ff := newTestFallback(m, 12, 12)
	_, _ = ff.solve(context.Background(), testChallenge()) //nolint:errcheck

	stats, err := ctfplatform.SummarizeSupervisionLedger(path)
	if err != nil {
		t.Fatalf("汇总失败: %v", err)
	}
	if stats.ByDecision["ABANDON"] < 1 {
		t.Fatalf("账本必须记录 ABANDON，got %+v", stats.ByDecision)
	}
	data, _ := os.ReadFile(path) //nolint:errcheck // 内容断言失败由下方捕获
	if !strings.Contains(string(data), `"challenge":"监督测试题"`) {
		t.Fatalf("账本记录必须带题目标识，内容: %s", truncate(string(data), 300))
	}
}
