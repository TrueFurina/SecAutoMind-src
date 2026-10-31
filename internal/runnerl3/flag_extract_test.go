package runnerl3

import "testing"

// TestDefaultWholeSolveTimeoutNotRegressed 锁死「整题预算默认 300s」这条口径。
//
// 存在理由（2026-10-29 服务器真机事故）：
// RUNNER_LLM_TIMEOUT_SEC 的 ctx 建在 round 循环**之外**，是**整题**预算。
// 旧默认 60s 实测把 YCB 两题、real_benchmark 的 buuctf_upload_basic 精确掐死在
// 超时点上（round 3/4 起 context deadline exceeded）→ 直接 return nil,nil 记 MISS。
// 放开到 600s 后 12 题全部自然结束（7~63s）⇒ 60s 是纯人为截断。
// 本测试防止有人"顺手把数字改回去"而没人发现。
func TestDefaultWholeSolveTimeoutNotRegressed(t *testing.T) {
	if defaultWholeSolveTimeoutSec < 300 {
		t.Fatalf("整题预算默认值 %ds 过小：实测会把正在解题的题掐成 MISS，"+
			"必须 >= 300（证据见 internal/runnerl3/llm_solver.go Solve 内注释）",
			defaultWholeSolveTimeoutSec)
	}
}

// TestExtractFlagCandidatesPrefixAllowlist 锁死「前缀白名单」这条口径。
//
// 存在理由（2026-10-29 真机事故，非理论推演）：
// 旧实现用 strings.Index(lower, "flag{") 找候选，而真值前缀并不统一。
// 服务器冒烟实锤：pico2024_interencdec 题模型已输出正确解
// `picoCTF{caesar_d3cr9pt3d_f0212758}`，旧实现判「没找到 flag 格式」
// → 候选 0 → 不提交 → 记 MISS。真实题库里非 flag{} 前缀普遍存在，
// 旧实现对它们逐道系统性判死。本测试就是防止这个 bug 再长回来。
func TestExtractFlagCandidatesPrefixAllowlist(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"flag 标准前缀", "答案是 flag{abc_123}", []string{"flag{abc_123}"}},
		{"picoCTF 前缀（事故原题）", "picoCTF{caesar_d3cr9pt3d_f0212758}\n\nCONFIDENCE: 1.0",
			[]string{"picoCTF{caesar_d3cr9pt3d_f0212758}"}},
		{"sdctf 前缀", "sdctf{Case64_ar!}", []string{"sdctf{Case64_ar!}"}},
		{"大写 FLAG", "FLAG{UPPER}", []string{"FLAG{UPPER}"}},
		{"带 flag: 引导词", "flag: flag{led}", []string{"flag{led}"}},
		{"多候选去重", "flag{a}\nflag{a}\nflag{b}", []string{"flag{a}", "flag{b}"}},
		{"无花括号文本不是候选", "CONFIDENCE: 1.0 没有 flag", nil},
		{"未闭合不算候选", "flag{unclosed", nil},
		{"空内容不算候选", "flag{}", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractFlagCandidates(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("extractFlagCandidates(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("extractFlagCandidates(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}
