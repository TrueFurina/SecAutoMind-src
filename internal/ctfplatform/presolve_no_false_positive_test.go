package ctfplatform

// presolve_no_false_positive_test.go —— 锁死「诊断文本被当成 flag 命中」这一类缺陷。
//
// 背景（2026-10-03 实锤，用户实测）：用户向钉钉机器人发
//   「对http://120.48.36.201:18086/#dashboard渗透测试与等保测评」
// 预解层返回垃圾文本 `攻击链: TTP战术技术程序` 并短路了真正的 Agent 推理。
// 根因有两层：
//   1) tryExploitChainDetection 用 strings.Contains(text,"ttp")，而 "http" 里就含 "ttp"
//      → 任何带 http/https URL 的输入都被误判为「攻击链题」；
//   2) 预解选择逻辑「首个非空即 best」，把 likeness=1 的诊断文本当作命中
//      ——与本文件自身注释「诊断提示不当命中」自相矛盾。
//
// 本测试同时覆盖两层，并带正向对照（真关键词/真 flag 仍须命中），防止「改死」。

import (
	"context"
	"testing"
)

// TestExploitChainKeyword_NoSubstringFalsePositive 校验攻击链关键词走词边界，
// 不再因子串而误命中（"ttp"⊂"http"、"apt"⊂"adapter"）。
func TestExploitChainKeyword_NoSubstringFalsePositive(t *testing.T) {
	negative := []string{
		"对http://120.48.36.201:18086/#dashboard渗透测试与等保测评", // http 含 ttp（用户实测样本）
		"https://example.com/path?q=1",
		"adapter chapter", // 含 "apt"
		"plain text without any keyword",
	}
	for _, in := range negative {
		if got := tryExploitChainDetection(in, nil); len(got) != 0 {
			t.Errorf("输入 %q 不应命中攻击链，实际 %v", in, got)
		}
	}

	// 正向对照：真关键词必须仍能命中，避免把检测器改成永不触发。
	positive := []string{
		"请分析该 TTP 战术技术程序",
		"attack chain analysis",
		"MITRE ATT&CK 矩阵映射",
		"lateral movement and privilege escalation",
	}
	for _, in := range positive {
		if got := tryExploitChainDetection(in, nil); len(got) == 0 {
			t.Errorf("输入 %q 应命中攻击链，实际未命中", in)
		}
	}
}

// TestDiagnosticLabelBelowHitThreshold 诊断/标签文本的 likeness 必须低于命中门槛。
func TestDiagnosticLabelBelowHitThreshold(t *testing.T) {
	diag := []string{
		"攻击链: TTP战术技术程序",
		"AES ECB 检测：发现 3 个重复的 16 字节块（ECB 模式特征）",
		"Rust逆向: Rust语言",
	}
	for _, d := range diag {
		if got := flagLikeness([]string{d}); got >= minFlagLikenessForHit {
			t.Errorf("诊断文本 %q likeness=%d 不应达到命中门槛 %d", d, got, minFlagLikenessForHit)
		}
	}
	// 正向对照：真 flag 必须达到门槛。
	for _, f := range []string{"flag{a_b_c_d}", "picoCTF{n3v3r_g0nn4}", "BZHCTF{sur3m3nt}"} {
		if got := flagLikeness([]string{f}); got < minFlagLikenessForHit {
			t.Errorf("真 flag %q likeness=%d 应达到门槛 %d", f, got, minFlagLikenessForHit)
		}
	}
}

// TestPresolve_NoDiagnosticHit_OnURLInput 用户实测场景：
// 含 http URL 的输入不得返回「诊断文本式」命中（若命中，必须是真 flag 外形）。
func TestPresolve_NoDiagnosticHit_OnURLInput(t *testing.T) {
	pr := NewPresolver(nil)
	inputs := []string{
		"对http://120.48.36.201:18086/#dashboard渗透测试与等保测评",
		"请对 https://target.example/ 做渗透测试",
	}
	for _, in := range inputs {
		ch := &Challenge{ID: "user_scenario", Description: in}
		for name, fn := range map[string]func(*Challenge) *PresolveResult{
			"Presolve":             func(c *Challenge) *PresolveResult { return pr.Presolve(context.Background(), c, nil) },
			"PresolveWithRegistry": func(c *Challenge) *PresolveResult { return pr.PresolveWithRegistry(context.Background(), c, nil) },
		} {
			r := fn(ch)
			if r == nil || !r.Solved {
				continue
			}
			if flagLikeness(r.Flags) < minFlagLikenessForHit {
				t.Errorf("%s 对 %q 误报命中（诊断文本当 flag）：engine=%s flags=%v",
					name, in, r.Engine, r.Flags)
			}
		}
	}
}
