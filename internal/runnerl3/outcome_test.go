package runnerl3

import (
	"context"
	"testing"

	"github.com/cloudwego/eino/schema"

	"secautomind-ai/internal/ctfplatform"
)

// 归因分类的唯一判据。这些用例就是"cand=0 到底意味着什么"的定义，
// 改动 classifyMiss 的顺序或条件必须让其中某条变红。
func TestClassifyMiss(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		returned int
		tally    solveTally
		want     string
	}{
		{"通道全挂优先于一切", ErrLLMUnavailable, 0, solveTally{}, ReasonLLMUnavailable},
		{"交出候选即 solved", nil, 2, solveTally{CandSeen: 3, Distinct: 2}, ReasonAnswered},
		{"给了候选但没交出=抑制(幻觉类)", nil, 0, solveTally{CandSeen: 5, Distinct: 3}, ReasonCandidatesSuppressed},
		{"只出现过一次也算给过", nil, 0, solveTally{CandSeen: 1, Distinct: 1}, ReasonCandidatesSuppressed},
		{"去重表非空也必须判抑制", nil, 0, solveTally{Distinct: 2}, ReasonCandidatesSuppressed},
		{"闸门打回的候选也算给过", nil, 0, solveTally{Suppressed: 1}, ReasonCandidatesSuppressed},
		{"真零候选", nil, 0, solveTally{}, ReasonNoCandidate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyMiss(c.err, c.returned, c.tally); got != c.want {
				t.Fatalf("classifyMiss(err=%v, ret=%d, tally=%+v) = %q，期望 %q",
					c.err, c.returned, c.tally, got, c.want)
			}
		})
	}
}

// 通道不可用不许被当成能力失败重算进分母 —— 这是 skipped 口径的判据。
func TestClassifyMissChannelDownIsNotCapability(t *testing.T) {
	got := classifyMiss(ErrLLMUnavailable, 0, solveTally{CandSeen: 4, Distinct: 2, Suppressed: 1})
	if got != ReasonLLMUnavailable {
		t.Fatalf("通道全挂且中途出现过候选时，应判 %q（基础设施失效），实际 %q",
			ReasonLLMUnavailable, got)
	}
}

// 归因槽必须零值可用：NewLLMFallback 有多条 return 路径，靠"记得初始化"必漏。
func TestOutcomeZeroValueUsable(t *testing.T) {
	f := &LLMFallback{}
	if got := f.LastOutcome(); got.Reason != "" {
		t.Fatalf("未跑过时 Reason 应为空串，实际 %q", got.Reason)
	}
}

// nil 接收者不许 panic（跑批工具在未启用分支也会读）。
func TestOutcomeNilReceiver(t *testing.T) {
	var f *LLMFallback
	if got := f.LastOutcome(); got.Reason != "" {
		t.Fatalf("nil 接收者应返回零值，实际 %q", got.Reason)
	}
}

// 未启用不许被记成"零候选=模型不行"。
func TestSolveRecordsDisabledOutcome(t *testing.T) {
	f := &LLMFallback{} // Enabled=false：走最早那条退出路径
	if _, err := f.Solve(context.Background(), &ctfplatform.Challenge{Title: "t"}); err != nil {
		t.Fatalf("禁用实例不应返回错误: %v", err)
	}
	if got := f.LastOutcome().Reason; got != ReasonDisabled {
		t.Fatalf("未启用实例应记 %q，实际 %q", ReasonDisabled, got)
	}
}

// 走 defer 的真实退出路径①：模型说了话但没有 flag 形态 → no_candidate。
// 这条覆盖"终局文本无 flag"分支（原实现只在 Debug 级留痕，跑批里看不见）。
func TestSolveRecordsNoCandidateViaDefer(t *testing.T) {
	ff := newTestFallback(&fakeModel{resps: []*schema.Message{textResp("我还没想出来")}}, 2, 2)
	flags, err := ff.Solve(context.Background(), testChallenge())
	if err != nil || flags != nil {
		t.Fatalf("不应产出候选: flags=%v err=%v", flags, err)
	}
	got := ff.LastOutcome()
	if got.Reason != ReasonNoCandidate {
		t.Fatalf("应记 %q，实际 %q（tally=%+v）", ReasonNoCandidate, got.Reason, got.solveTally)
	}
	if got.ToolCalls != 0 {
		t.Fatalf("该路径没有工具调用，实际 %d", got.ToolCalls)
	}
}

// 走 defer 的真实退出路径②：模型给了 flag，但声称读取了不存在的文件 →
// 反幻觉闸门打回。必须记成 candidates_suppressed 而不是 no_candidate。
// 这条就是 Primes 案的形状：有产出、但不被采信。判反了会把"补幻觉抑制"
// 误判成"补能力"。
func TestSolveRecordsSuppressedByHallucinationGate(t *testing.T) {
	resp := textResp("我读取了 /tmp/fake/flag.txt，得到最终答案 CTF{deadbeefcafe1234}")
	ff := newTestFallback(&fakeModel{resps: []*schema.Message{resp}}, 2, 2)
	flags, err := ff.Solve(context.Background(), testChallenge())
	if err != nil || flags != nil {
		t.Fatalf("闸门应打回（不提交）: flags=%v err=%v", flags, err)
	}
	got := ff.LastOutcome()
	if got.Reason != ReasonCandidatesSuppressed {
		t.Fatalf("闸门打回必须记 %q，实际 %q（tally=%+v）",
			ReasonCandidatesSuppressed, got.Reason, got.solveTally)
	}
	if got.Suppressed != 1 {
		t.Fatalf("应记 1 个被扣下的候选，实际 %d", got.Suppressed)
	}
}

// dropped 必须按**去重后**计数：同一个假 flag 会在多轮反复出现。
// 2026-11-01 实测 Primes 同一串出现 8 次；若按出现次数记，报告会写成
// dropped=8，让人误以为有 8 个不同候选。
func TestDroppedCountsDistinctNotOccurrences(t *testing.T) {
	const fake = "CTF{fakefakefake1234}"
	m := &fakeModel{resps: []*schema.Message{
		toolResp("no_such_tool", `{"q":"`+fake+`"}`),
		toolResp("no_such_tool", `{"q":"`+fake+`"}`),
		textResp("我还是没想出来"),
	}}
	ff := newTestFallback(m, 3, 5)
	if flags, err := ff.Solve(context.Background(), testChallenge()); err != nil || flags != nil {
		t.Fatalf("不应产出候选: flags=%v err=%v", flags, err)
	}
	got := ff.LastOutcome()
	if got.Reason != ReasonCandidatesSuppressed {
		t.Fatalf("应记 %q，实际 %q", ReasonCandidatesSuppressed, got.Reason)
	}
	if got.Suppressed != 1 {
		t.Fatalf("同一候选出现 2 次应记 1（去重），实际 %d", got.Suppressed)
	}
	if got.ToolCalls != 2 {
		t.Fatalf("应有 2 次工具调用，实际 %d", got.ToolCalls)
	}
}

// 走 defer 的真实退出路径③：正常给出答案 → solved，且 Returned 与之一致。
func TestSolveRecordsSolvedOutcome(t *testing.T) {
	ff := newTestFallback(&fakeModel{resps: []*schema.Message{textResp("最终 flag{abc123def456}")}}, 2, 2)
	flags, err := ff.Solve(context.Background(), testChallenge())
	if err != nil || len(flags) == 0 {
		t.Fatalf("应产出候选: flags=%v err=%v", flags, err)
	}
	got := ff.LastOutcome()
	if got.Reason != ReasonAnswered || got.Returned != len(flags) {
		t.Fatalf("应记 %q 且 Returned=%d，实际 %q/%d",
			ReasonAnswered, len(flags), got.Reason, got.Returned)
	}
}
