package ctfplatform

// externalbench_false_positive_test.go —— 「假阳性短路」双向钉。
//
// 为什么单独一根钉子（2026-10-18 外部真题尺实测）：
// Presolve 返回 Solved=true ⇒ integrator 置 SkipAgent=true ⇒ agent handler
// 直接把候选串当答案回给用户、**整条 Agent 推理被跳过**。所以"候选像不像 flag"
// 这件事在**短路语义**下不是准确率问题，而是正确性问题：
// 漏判占位符 = 用户拿到假答案且没有补救；误判占位符 = 少一次 0-token 命中，
// 退回 LLM 真推理。方向不对称，故占位符判据必须"宁宽勿窄"。
//
// 第一根（TestPlaceholderFlagExtended）：纯单元，钉住**实测观测到的 4 个**占位符串，
// 不依赖基准数据，任何机器都跑。
// 第二根（TestExternalBench_NoPlaceholderShortCircuit）：数据驱动双向钉，
// 既防「新增占位符假阳性」混进来，也防台账过期后无人清理。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"testing"

	"go.uber.org/zap"
)

// externalBenchKnownFalsePositive 台账：**不是占位符形态**但 Presolve 仍会给出
// Solved=true 的题，逐题写明机制。判据现状是"能识别就不要台账，识别不了才登记"。
//
// 之所以允许非空：这两例的候选串与真 flag 同形同构（长度/字符集/花括号），
// 任何形态判据都无法在不误伤真 flag 的前提下拒绝它们。
var externalBenchKnownFalsePositive = map[string]string{
	"ext_gctf2023_primes": "附件 chal.sage 内嵌诱饵明文 m = b\"I have a sweet flag for you: CTF{...}\"；" +
		"上游部署时替换了真 flag ⇒ 串是**逐字输入回显**，非推导所得，形态上与真 flag 完全一致",
	"ext_gctf2025_filtermaze": "候选 JFM{rsmn} 由 base64_multilayer 的变换链产出，" +
		"底层 attachments 中不存在该串的字面量（已逐文件检索）⇒ 变换产物，非占位词、非输入回显",
}

// TestPlaceholderFlagExtended 实测占位符族必须低于命中门槛，真 flag 必须仍达标。
func TestPlaceholderFlagExtended(t *testing.T) {
	// 来源逐条可溯源，勿凭想象扩表（扩表前先跑外部尺确认它真会短路）。
	observed := []struct{ flag, why string }{
		{"CTF{flag}", "ext_gctf2025_bpfbox/flag.txt、ext_gctf2025_numerology/flag.txt 的脱敏内容"},
		{"flag: {flag}", "ext_gctf2021_h1/chall.py 的 f-string 模板 f'...here is the flag: {flag}'"},
		{"ZPA{????}", "ext_gctf2023_mhk2 解码链产出的问号占位"},
		{"flag{xxxx}", "既有用例（掩码占位）"},
		{"flag{test}", "整词占位"},
		{"DASCTF{0000}", "单一字符种类（低信息量）"},
		{"picoCTF{your_flag_here}", "既有用例（your + 整词）"},
	}
	for _, c := range observed {
		if got := flagLikeness([]string{c.flag}); got >= minFlagLikenessForHit {
			t.Errorf("占位符 %q likeness=%d 不应达门槛 %d（来源：%s）",
				c.flag, got, minFlagLikenessForHit, c.why)
		}
	}

	// 反向钉：真 flag 必须**仍**达门槛，否则就是把过滤器改宽到会误伤真解。
	// 含真实 GCTF 形态（长 base64 内容）、制造级样本（连字符/数字/大小写混排）。
	real := []string{
		"CTF{YkDOLIStjpjP5Am1SXDt5d2r9es3b5KZP47v8rXF}",
		"flag{5ynthet1c-P0s1t1ve-C0ntr0l}",
		"DASCTF{1234567890123456789-987654321098765432}",
		"BZHCTF{sur3m3nt}",
		"picoCTF{n3v3r_g0nn4}",
	}
	for _, f := range real {
		if got := flagLikeness([]string{f}); got < minFlagLikenessForHit {
			t.Errorf("真 flag %q likeness=%d 应达门槛 %d —— 占位符判据过宽会误伤真解",
				f, got, minFlagLikenessForHit)
		}
	}
}

// TestExternalBench_NoPlaceholderShortCircuit 外部尺上「占位符假阳性短路」必须为 0。
//
// 断言的是**正确性**而非命中率：本尺的设计约束是"不拿命中率问责"（见
// externalbench_test.go 三条诚实边界），但"把题面/附件里的占位符当答案短路 Agent"
// 与命中率无关，是纯粹的假阳性缺陷，必须 fail-closed。
func TestExternalBench_NoPlaceholderShortCircuit(t *testing.T) {
	doc := loadExternalBench(t)
	if len(doc.Problems) == 0 {
		t.Fatal("external_bench.json 无题目——无法执行假阳性钉子（fail-closed）")
	}
	pr := NewPresolver(zap.NewNop())

	ids := make([]string, 0, len(doc.Problems))
	for id := range doc.Problems {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	seen := map[string]string{} // 本次仍复现的台账项
	placeholderHits := 0
	for _, id := range ids {
		p := doc.Problems[id]
		att, _, _ := loadExternalBenchAttachments(p, true)
		// 与 TestExternalBench_AttachmentSubset 同管道（description + 文本附件），
		// 保证钉子测的是被判分的同一条路径。
		res := pr.Presolve(context.Background(),
			&Challenge{ID: id, Category: p.Category, Description: p.Description + att}, nil)
		if res == nil || !res.Solved || len(res.Flags) == 0 {
			continue
		}
		cand := res.Flags[0]
		sum := sha256.Sum256([]byte(cand))
		if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
			continue // 真命中，与假阳性无关
		}
		if isPlaceholderFlag(cand) {
			placeholderHits++
			t.Errorf("🔴 %s 以占位符 %q 报 Solved（engine=%s）——会短路 Agent 并回假答案；"+
				"请把该形态补进 flagPlaceholderRe/flagPlaceholderWords", id, cand, res.Engine)
			continue
		}
		if why, ok := externalBenchKnownFalsePositive[id]; ok {
			seen[id] = why
			continue
		}
		t.Errorf("🔴 %s 出现**未登记**的非占位符假阳性 %q（engine=%s）。"+
			"先判定机制（输入回显？变换产物？），再决定是补判据还是登记台账；"+
			"不得直接把题号加进 externalBenchKnownFalsePositive 了事。", id, cand, res.Engine)
	}

	// 反向钉：台账项若已不再复现，必须删除该条——过期台账会让钉子对环境变化失明。
	stale := []string{}
	for id, why := range externalBenchKnownFalsePositive {
		if _, ok := seen[id]; !ok {
			stale = append(stale, id+"（"+why[:min(24, len(why))]+"…）")
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("🔴 台账项已不再复现，请从 externalBenchKnownFalsePositive 删除：%s", s)
	}

	t.Logf("外部尺 %d 题：占位符假阳性 %d 例｜已登记非占位符假阳性 %d 例",
		len(ids), placeholderHits, len(seen))
}
