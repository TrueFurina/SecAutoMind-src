package ctfplatform

// solve_attribution_test.go —— 解出归因口径护栏（立尺 2026-10-25）。
//
// 背景：runner 三层链（presolve/python_skill/llm）上线后全仓无归因字段——
// A 库 E3 验收实证过它的致命性：14/15 presolve 直出在无归因时整体冒充链路
// 能力。本护栏锁三件事：① Challenge.SolvedBy 不进题目 JSON（它是 provenance
// 不是题目属性）；② PollRecord 透传；③ 归因枚举值封闭（新层必须登记）。

import (
	"encoding/json"
	"strings"
	"testing"
)

// SolveByAttributions 合法归因枚举（封闭集合：新增求解层必须在此登记，
// 否则统计侧无法识别 → 口径分母漏项）。
var SolveByAttributions = map[string]bool{
	"presolve":     true, // Layer 1：Go 确定性（0 token）
	"python_skill": true, // Layer 2：Python 桥（0 LLM token）
	"llm":          true, // Layer 3：LLM 推理（真 token）
	"":             true, // 未解出
}

func TestSolvedByNotSerializedInChallenge(t *testing.T) {
	// 归因是求解过程属性，不是题目属性——序列化必须忽略，防平台侧/缓存侧
	// 把上一题的归因带到下一题。
	ch := Challenge{ID: "x", SolvedBy: "llm"}
	b, err := json.Marshal(ch)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(b, &map[string]any{}) == nil {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if _, ok := m["SolvedBy"]; ok {
			t.Fatalf("SolvedBy 泄漏进题目 JSON: %s", b)
		}
		if _, ok := m["solved_by"]; ok {
			t.Fatalf("solved_by 泄漏进题目 JSON: %s", b)
		}
	}
}

func TestSolvedByAttributionEnumClosed(t *testing.T) {
	// 归因值必须是封闭枚举——统计侧按此分桶，未知值=口径漏项。
	known := map[string]bool{"presolve": true, "python_skill": true, "llm": true, "": true}
	for k := range SolveByAttributions {
		if !known[k] {
			t.Fatalf("未登记的归因值 %q——先在统计侧登记再使用", k)
		}
	}
}

func TestPollRecordSolvedByField(t *testing.T) {
	// PollRecord 序列化必含 solved_by（统计侧消费入口）
	rec := PollRecord{ChallengeID: "t", Flag: "flag{x}", SolvedBy: "presolve"}
	b, _ := json.Marshal(rec)
	s := string(b)
	if !strings.Contains(s, `"solved_by":"presolve"`) {
		t.Fatalf("PollRecord.solved_by 序列化缺失/值错: %s", s)
	}
	rec2 := PollRecord{ChallengeID: "t2"}
	b2, _ := json.Marshal(rec2)
	if strings.Contains(string(b2), "solved_by") {
		t.Fatalf("未解出的 record 不应带 solved_by（omitempty）: %s", b2)
	}
}
