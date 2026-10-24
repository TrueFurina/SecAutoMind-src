package ctfplatform

// supervision_test.go —— 监督反思/错误分类移植回归（融合 P1-9，2026-10-25）。
// 用例镜像 A 库 budget_reflection / error_taxonomy 的实战边界（含 2026-10-03
// token 双口径门修正的两侧）。

import (
	"testing"
)

// ── 错误分类 ──

func TestClassifyErrorPatterns(t *testing.T) {
	cases := []struct {
		raw  string
		want ErrorClass
	}{
		{"budget_exceeded: 12 steps used", ClassBudgetExceeded},
		{"context deadline exceeded", ClassWallclockTimeout},
		{"solver timeout after 300s", ClassWallclockTimeout},
		{"rate_limited (429 too many requests)", ClassRateLimited},
		{"provider circuit open: baidu 熔断 (401)", ClassProviderCircuitOpen},
		{"panic: runtime error", ClassSolverException},
		{"无候选 flag", ClassUnknown},
		{"", ClassUnknown},
	}
	for _, c := range cases {
		if got := ClassifyError(c.raw); got != c.want {
			t.Errorf("ClassifyError(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestErrorTaxonomySets(t *testing.T) {
	// 终态类必须同时是 truncated（报告口径 ⊇ 重试口径）
	for _, c := range []ErrorClass{ClassBudgetExceeded, ClassRaceAbandon, ClassSolverException} {
		if !IsNonRetryable(c) || !IsTruncatedError(c) {
			t.Errorf("%s 应为 non-retryable+truncated", c)
		}
	}
	// 瞬时类：truncated 但可重试（保留重试行为）
	for _, c := range []ErrorClass{ClassRateLimited, ClassProviderError, ClassInfraError, ClassNoCredential} {
		if IsNonRetryable(c) {
			t.Errorf("%s 为瞬时类，不应 non-retryable", c)
		}
		if !IsTruncatedError(c) {
			t.Errorf("%s 应为 truncated（非能力判负）", c)
		}
	}
	// 正常判负类：两个口径都不触发
	if IsTruncatedError(ClassUnknown) || IsNonRetryable(ClassUnknown) {
		t.Error("unknown 正常判负类不应进任何口径")
	}
}

// ── Budget 反思 ──

func fp(v float64) *float64 { return &v }
func fi(v int) *int         { return &v }

func prog(n int) []SupervisionStep { // n 个有进展步
	s := make([]SupervisionStep, n)
	for i := range s {
		s[i] = SupervisionStep{Observation: "found something"}
	}
	return s
}

func stuck(n int) []SupervisionStep { // n 个无进展步（有错误）
	s := make([]SupervisionStep, n)
	for i := range s {
		s[i] = SupervisionStep{Observation: "x", ErrCategory: "tool_failure"}
	}
	return s
}

func TestReflectRule1AbandonLowConfidence(t *testing.T) {
	// ① 预算 85% + 近期零进展 + 低信心 → ABANDON
	d := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 11},
		stuck(6), fp(0.2))
	if d.Decision != DecisionAbandon {
		t.Fatalf("规则①: got %s (%s)", d.Decision, d.Reason)
	}
}

func TestReflectRule1NotAbandonWithCandidates(t *testing.T) {
	// ① 候选在手时不早停（主循环立即收敛）
	d := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 11, Candidates: fi(2)},
		stuck(6), fp(0.2))
	if d.Decision == DecisionAbandon {
		t.Fatalf("有候选不应早停: %s", d.Reason)
	}
}

func TestReflectRule2Switch(t *testing.T) {
	// ② 过半 + 低信心 + 尾部>=4 无进展 → SWITCH
	d := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 8},
		append(prog(4), stuck(5)...), fp(0.2))
	if d.Decision != DecisionSwitch {
		t.Fatalf("规则②: got %s (%s)", d.Decision, d.Reason)
	}
}

func TestReflectRule6ZeroCandidatesTokenGate(t *testing.T) {
	// ⑥ 零候选 + 步数>=60% + token<60% → 不 ABANDON（2026-10-03 修正的防误降侧）
	d := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 8,
		Candidates: fi(0), TokenRatio: fp(0.35)}, prog(8), fp(0.9))
	if d.Decision == DecisionAbandon {
		t.Fatalf("token 仅 0.35 不应早停（步数口径先到误降复发）: %s", d.Reason)
	}
	// ⑥ 同场景 token>=60% → ABANDON
	d2 := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 8,
		Candidates: fi(0), TokenRatio: fp(0.65)}, prog(8), fp(0.9))
	if d2.Decision != DecisionAbandon {
		t.Fatalf("token 0.65 加零候选应早停: got %s (%s)", d2.Decision, d2.Reason)
	}
	// ⑥ token 未知（nil，向后兼容）→ 仅步数口径即可早停
	d3 := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 8,
		Candidates: fi(0)}, prog(8), fp(0.9))
	if d3.Decision != DecisionAbandon {
		t.Fatalf("token 未知+零候选应早停: got %s", d3.Decision)
	}
}

func TestReflectContinueRules(t *testing.T) {
	// ③ 预算充足 + 信心尚可 → CONTINUE
	if d := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 3},
		prog(3), fp(0.6)); d.Decision != DecisionContinue {
		t.Fatalf("规则③: %s", d.Decision)
	}
	// ④ 预算紧 + 信心高 → CONTINUE
	if d := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 9},
		prog(9), fp(0.8)); d.Decision != DecisionContinue {
		t.Fatalf("规则④: %s", d.Decision)
	}
	// 候选未知（nil）→ 硬信号不参与判定，低信心零进展但预算未到 85% 不早停
	if d := ReflectSupervision(SupervisionState{BudgetTotal: 12, BudgetUsed: 6},
		stuck(6), fp(0.5)); d.Decision != DecisionContinue {
		t.Fatalf("候选未知+中性信心应默认继续: %s (%s)", d.Decision, d.Reason)
	}
}

func TestReflectProgressDetection(t *testing.T) {
	// 进展判定：非空 observation 且无错误
	if !(SupervisionStep{Observation: "ok"}).madeProgress() {
		t.Fatal("非空无错应为进展")
	}
	if (SupervisionStep{Observation: "ok", ErrCategory: "x"}).madeProgress() {
		t.Fatal("有错不应为进展")
	}
	if (SupervisionStep{Observation: "  ", ErrCategory: ""}).madeProgress() {
		t.Fatal("空 observation 不应为进展")
	}
}

func TestClassifyRecordErrorWiring(t *testing.T) {
	rec := &PollRecord{Error: "context deadline exceeded"}
	classifyRecordError(rec)
	if rec.ErrorClass != string(ClassWallclockTimeout) {
		t.Fatalf("PollRecord 接线: %q", rec.ErrorClass)
	}
	if !IsNonRetryable(ClassWallclockTimeout) {
		t.Fatal("墙钟超时应为终态（重试短路）")
	}
}
