// llm_solver_rich_test.go —— P0-1 ctf_sage 模板接入回归（2026-10-25）。
//
// 锁死的不变量：
//   A. execute_python 的 params 透传：LLM 传了数学参数（JSON 字符串或 object）
//      且 bridge 实现 RichSkillRunner → 必须走富结果路径，原文进 ToolMessage；
//   B. 向后兼容：bridge 只实现 SkillRunner（旧 fake/旧 bridge）时，即使传了
//      params 也逐字节保持旧 flag 契约行为——不许因为新接口破坏存量；
//   C. params 缺失/空/解析失败 → 回落 flag 契约，不制造新失败模式；
//   D. parseExtraParams 对两种形态（JSON 字符串 / 已解析 object）都容错。
package runnerl3

import (
	"context"
	"strings"
	"testing"

	"secautomind-ai/internal/ctfplatform"
)

// fakePlainRunner 只实现 SkillRunner（存量契约）。
type fakePlainRunner struct {
	gotSkill string
	flags    []string
	ok       bool
	calls    int
}

func (r *fakePlainRunner) RunSkill(_ context.Context, skillName string, _ *ctfplatform.Challenge) ([]string, bool) {
	r.calls++
	r.gotSkill = skillName
	return r.flags, r.ok
}

// fakeRichRunner 同时实现 RichSkillRunner（P0-1 新契约）。
type fakeRichRunner struct {
	fakePlainRunner
	gotExtra map[string]any
	richText string
	richOK   bool
}

func (r *fakeRichRunner) RunSkillRich(_ context.Context, skillName string, _ *ctfplatform.Challenge, extra map[string]any) (string, bool) {
	r.calls++
	r.gotSkill = skillName
	r.gotExtra = extra
	return r.richText, r.richOK
}

func richChallenge() *ctfplatform.Challenge {
	return &ctfplatform.Challenge{Title: "Coppersmith 题", Category: "crypto"}
}

func TestExecutePythonRichPathWithParams(t *testing.T) {
	rich := &fakeRichRunner{
		fakePlainRunner: fakePlainRunner{flags: []string{"flag{stale}"}, ok: true},
		richText:        `{"ok":true,"status":"solved","roots":[12345]}`,
		richOK:          true,
	}
	f := &LLMFallback{pyBridge: rich}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "ctf_sage_t1_coppersmith",
		"params":     `{"modulus":10001,"poly":[1,2,3]}`,
	}, richChallenge())

	if !strings.Contains(got, "ctf_sage_t1_coppersmith") || !strings.Contains(got, "12345") {
		t.Fatalf("富结果路径未透传模板输出: %q", got)
	}
	if strings.Contains(got, "flag{stale}") {
		t.Fatalf("富路径却混入 flag 契约输出（路由错了）: %q", got)
	}
	if rich.gotExtra["modulus"] == nil {
		t.Fatalf("数学参数未透传到 bridge: %v", rich.gotExtra)
	}
	if rich.calls != 1 || rich.gotSkill != "ctf_sage_t1_coppersmith" {
		t.Fatalf("调用次数/技能名不对: calls=%d skill=%q", rich.calls, rich.gotSkill)
	}
}

func TestExecutePythonParamsAsObject(t *testing.T) {
	rich := &fakeRichRunner{richText: `{"ok":true}`, richOK: true}
	f := &LLMFallback{pyBridge: rich}

	f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "ctf_sage_t5_dlp_bsgs_ph",
		"params":     map[string]any{"g": 2, "h": 5, "p": 101},
	}, richChallenge())

	if rich.calls != 1 {
		t.Fatalf("object 形态 params 未触发富路径: calls=%d", rich.calls)
	}
	if rich.gotExtra["p"] != 101 {
		t.Fatalf("object 形态参数透传错误: %v", rich.gotExtra)
	}
}

func TestExecutePythonNoParamsFallsBackToFlagContract(t *testing.T) {
	plain := &fakePlainRunner{flags: []string{"flag{ok}"}, ok: true}
	f := &LLMFallback{pyBridge: plain}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "crypto_hastad_broadcast",
	}, richChallenge())

	if !strings.Contains(got, "flag{ok}") {
		t.Fatalf("无 params 时应保持旧 flag 契约: %q", got)
	}
	if plain.calls != 1 {
		t.Fatalf("flag 契约调用次数不对: %d", plain.calls)
	}
}

func TestExecutePythonPlainRunnerWithParamsStaysOnFlagContract(t *testing.T) {
	// 存量 bridge 不实现 RichSkillRunner：传 params 也必须走老路（不静默丢参数，
	// 但也不许改行为——升级 bridge 是独立动作）。
	plain := &fakePlainRunner{flags: []string{"flag{legacy}"}, ok: true}
	f := &LLMFallback{pyBridge: plain}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "ctf_sage_t1_coppersmith",
		"params":     `{"modulus":10001}`,
	}, richChallenge())

	if !strings.Contains(got, "flag{legacy}") {
		t.Fatalf("存量 bridge 行为被改变: %q", got)
	}
}

func TestExecutePythonRichFailureReported(t *testing.T) {
	rich := &fakeRichRunner{richText: "", richOK: false}
	f := &LLMFallback{pyBridge: rich}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "ctf_sage_t2_ecdsa_hnp",
		"params":     `{"mode":"hnp","n":7}`,
	}, richChallenge())

	if !strings.Contains(got, "执行失败或无依赖") {
		t.Fatalf("富路径失败未按约定报错: %q", got)
	}
}

func TestExecutePythonRichEmptyOutputReported(t *testing.T) {
	rich := &fakeRichRunner{richText: "   ", richOK: true}
	f := &LLMFallback{pyBridge: rich}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "ctf_sage_t4_boneh_durfee",
		"params":     `{"n":15,"e":3}`,
	}, richChallenge())

	if !strings.Contains(got, "无输出") {
		t.Fatalf("空输出未按约定报错: %q", got)
	}
}

func TestParseExtraParams(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want map[string]any // nil = 期望返回 nil
	}{
		{"json 字符串", `{"a":1,"b":"x"}`, map[string]any{"a": float64(1), "b": "x"}},
		{"object", map[string]any{"a": 1}, map[string]any{"a": 1}},
		{"空串", "", nil},
		{"空对象串", "{}", nil},
		{"空 map", map[string]any{}, nil},
		{"非法 JSON", "{not json", nil},
		{"数字标量", 42, nil},
		{"nil", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseExtraParams(tc.in)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("期望 nil，得到 %v", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("期望 %v，得到 %v", tc.want, got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("键 %s：期望 %v，得到 %v", k, v, got[k])
				}
			}
		})
	}
}
