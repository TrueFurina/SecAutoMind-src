package ctfplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"go.uber.org/zap"

	"secautomind-ai/internal/flagverify"
)

// P1-4 确定性验证后置（求解能力深化计划 L158，治失败模式⑤：把中间量当答案）。
//
// 背景（接线审计发现）：internal/flagverify 包设计完备（三态真值仲裁），
// 但**生产链路零调用**——典型「写了、测了、没人接」（AGENTS.md 第八条，第六例）。
// 本文件锁的是接线后的行为，重点是「无真值时零回归」这条底线。

func truthGateSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// 有真值：错的候选必须被拦下，只提交命中项（不浪费提交次数、不挨扣分）。
func TestPollerTruthArbitrationDropsWrongCandidates(t *testing.T) {
	real := "flag{real_answer}"
	wrong := "flag{intermediate_value}"
	fp := &fakePlatform{
		list: []Challenge{{
			ID: "9001", Title: "真值仲裁题", Category: "misc",
			FlagSHA256: truthGateSHA256(real),
		}},
		byID: map[string]*Challenge{},
	}
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoBuildEnv = false
	pc.AutoFetchDetail = false

	p := NewPoller(fp, func(ctx context.Context, ch *Challenge) ([]string, error) {
		return []string{wrong, real}, nil
	}, pc, zap.NewNop())

	recs, err := p.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 不应报错: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("应有 1 条记录，实际 %d", len(recs))
	}
	if len(fp.submittedFlags) != 1 {
		t.Fatalf("应只提交命中项 1 次，实际提交 %v", fp.submittedFlags)
	}
	if fp.submittedFlags[0] != real {
		t.Fatalf("提交的应是真值命中的候选 %q，实际 %q", real, fp.submittedFlags[0])
	}
	if !recs[0].Accepted {
		t.Fatalf("命中项提交后应 accepted")
	}
}

// neverCorrectPlatform 恒判「不正确」，逼提交循环走完全部候选 ——
// 只有这样才能验证"无真值时一个都没被拦"（默认假平台首个即 Correct，会提前 break）。
type neverCorrectPlatform struct{ *fakePlatform }

func (n *neverCorrectPlatform) SubmitFlag(ctx context.Context, id, flag string) (*SubmitResult, error) {
	n.fakePlatform.SubmitFlag(ctx, id, flag)
	return &SubmitResult{Accepted: true, Correct: false}, nil
}

// 无真值（真实比赛常态）：行为必须与接线前一致 —— 全部候选照常送平台，不拦、不判错。
func TestPollerNoTruthSubmitsCandidatesUnchanged(t *testing.T) {
	inner := &fakePlatform{
		list: []Challenge{{ID: "9002", Title: "无真值题", Category: "web"}},
		byID: map[string]*Challenge{},
	}
	fp := &neverCorrectPlatform{inner}
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoBuildEnv = false
	pc.AutoFetchDetail = false
	pc.MaxRetrySubmit = 5 // 允许走完所有候选（默认 0 只提交首个，是既有设计）

	want := []string{"flag{cand_one}", "flag{cand_two}"}
	p := NewPoller(fp, func(ctx context.Context, ch *Challenge) ([]string, error) {
		return want, nil
	}, pc, zap.NewNop())

	if _, err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 不应报错: %v", err)
	}
	if len(inner.submittedFlags) != len(want) {
		t.Fatalf("无真值时不得拦截，应提交 %d 个，实际 %v", len(want), inner.submittedFlags)
	}
	for i, w := range want {
		if inner.submittedFlags[i] != w {
			t.Fatalf("第 %d 个提交应为 %q，实际 %q", i, w, inner.submittedFlags[i])
		}
	}
}

// 全部候选都与真值不符 → 一个都不提交（fail-closed），并在记录里写明拦截原因。
func TestPollerAllCandidatesMismatchSubmitsNothing(t *testing.T) {
	fp := &fakePlatform{
		list: []Challenge{{
			ID: "9003", Title: "全错题", Category: "crypto",
			FlagSHA256: truthGateSHA256("flag{the_real_one}"),
		}},
		byID: map[string]*Challenge{},
	}
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoBuildEnv = false
	pc.AutoFetchDetail = false

	p := NewPoller(fp, func(ctx context.Context, ch *Challenge) ([]string, error) {
		return []string{"flag{guess_a}", "flag{guess_b}"}, nil
	}, pc, zap.NewNop())

	recs, err := p.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 不应报错: %v", err)
	}
	if len(fp.submittedFlags) != 0 {
		t.Fatalf("全错候选不得提交任何内容，实际 %v", fp.submittedFlags)
	}
	if len(recs) == 0 || recs[0].Error == "" {
		t.Fatalf("拦截必须在记录里留痕（Error 说明），实际 %+v", recs)
	}
}

// 内文哈希口径：题库常只登记 flag 内文的 sha256，此时"整串提交"也必须判 Match。
func TestPollerInnerHashTruthStillMatches(t *testing.T) {
	inner := "inner_secret"
	fp := &fakePlatform{
		list: []Challenge{{
			ID: "9004", Title: "内文哈希题", Category: "misc",
			FlagSHA256: truthGateSHA256(inner), // 只登记内文
		}},
		byID: map[string]*Challenge{},
	}
	pc := DefaultPollerConfig()
	pc.SubmitAfterSolve = true
	pc.AutoBuildEnv = false
	pc.AutoFetchDetail = false

	p := NewPoller(fp, func(ctx context.Context, ch *Challenge) ([]string, error) {
		return []string{"flag{" + inner + "}"}, nil
	}, pc, zap.NewNop())

	if _, err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 不应报错: %v", err)
	}
	if len(fp.submittedFlags) != 1 {
		t.Fatalf("内文哈希口径下整串提交应判命中，实际提交 %v", fp.submittedFlags)
	}
}

// flagverify.Arbitrate 的三态语义（与 poller 接线解耦，单独锁死）。
func TestArbitrateThreeState(t *testing.T) {
	real := "flag{ok}"
	truth := truthGateSHA256(real)
	innerTruth := truthGateSHA256("ok_inner")

	cases := []struct {
		name       string
		cands      []string
		truth      string
		wantKeep   int
		wantDropped int
	}{
		{"无真值全部原样保留", []string{"flag{a}", "flag{b}"}, "", 2, 0},
		{"真值非法格式按不可判定", []string{"flag{a}"}, "not-hex", 1, 0},
		{"命中只留命中项", []string{"flag{bad}", real}, truth, 1, 1},
		{"全错全丢", []string{"flag{x}", "flag{y}"}, truth, 0, 2},
		{"内文哈希命中", []string{"flag{ok_inner}"}, innerTruth, 1, 0},
		{"空候选按不可判定", []string{""}, truth, 1, 0},
	}
	for _, c := range cases {
		keep, dropped := flagverify.Arbitrate(c.cands, c.truth)
		if len(keep) != c.wantKeep || len(dropped) != c.wantDropped {
			t.Errorf("%s: keep=%d dropped=%d, want %d/%d",
				c.name, len(keep), len(dropped), c.wantKeep, c.wantDropped)
		}
	}
}
