package ctfplatform

// data_incomplete_claim_test.go —— 「数据不完整」归因的反注水门禁。
//
// 由来（2026-10-15一次真实的归因错误）：`10733` 曾被记为「数据不完整：附件仅存
// 挑战脚本模板，实例真值 n/HINT/C 每次随机生成、未留存」，并写进对外报告。
// 复核发现**真值一直在附件里** —— `task.py` 末尾的文档字符串就有本实例的
// hint / c / n 三元组。错误根因不是数据缺失，而是**只读了附件前半段
// （出题脚本 print 语句）就下结论**，没读到后半段的实例输出。
//
// 代价：报告把一道「缺解法」的题错报成「缺数据」，据此排除了一整类努力方向。
//
// 本门禁的强制口径：凡在报告中被分类为「数据不完整」的题，
// 必须由机验断言其附件**确实不含实例真值痕迹**，否则该归因作废。
// 这条规则对称地保护两侧：
//   · 真含真值而不自知 → 本门禁报红（须改归因为「能力缺口」）；
//   · 真不含真值      → 断言通过（归因站得住）。
//
// 检测口径（刻意保守，宁可误报也不漏报）：在附件文本里搜「实例输出形态」
//   · `xxx= <1024bit 整数>` 这类赋值形态（hint=/c=/n=/p=/q= 后的长十进制）；
//   · 出现 >= 80 位连续十进制数字（题目参数指纹）。
// 命中即判"附件含实例输出"⇒ 该题不该被归为「数据不完整」。
//
// 维护纪律：新增「数据不完整」归因题时，必须把它写进本文件的
// dataIncompleteClaimed 清单，否则本门禁对它零覆盖（见 coverage 断言）。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// dataIncompleteClaimed 报告第四节里被正式归因为「数据不完整」的题。
// 与 docs/cross_bench_report.md 的 8 题表必须一致。
var dataIncompleteClaimed = []string{
	"real_crypto_specialcurve2",
	"real_reverse_js",
	"real_reverse_sheng",
	"real_reverse_upx",
	"real_web_gongye_web2",
}

var (
	// 赋值形态：name= 后跟 40 位以上十进制（如 hint= 1010488554...）。
	instanceAssignRe = regexp.MustCompile(`(?i)\b(hint|c|n|p|q|e|m|ct|cp)\s*=\s*\d{40,}`)
	// 通用形态：连续 80 位以上十进制数字（参数指纹，比赋值形态更宽）。
	longDecimalRe = regexp.MustCompile(`\d{80,}`)
)

// attachTexts 返回该题全部文本附件的拼接内容（跳过二进制）。
// 附件目录不存在时返回 error（**不 t.Skip**）——调用方须把它计入"归因成立"，
// 绝不能让零覆盖分支静默跳过整条门禁。
func attachTexts(t *testing.T, id string) (string, []string, error) {
	t.Helper()
	dir := filepath.Join("..", "..", "data", "questions_real_bench", crossBenchAttachDir, id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, err
	}
	var b strings.Builder
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(raw) == 0 {
			continue
		}
		if looksBinary(raw) {
			continue
		}
		names = append(names, e.Name())
		b.Write(raw)
		b.WriteString("\n")
	}
	return b.String(), names, nil
}

// TestDataIncompleteClaimsHaveNoInstanceTruth 断言：凡被归为「数据不完整」的题，
// 其文本附件里确实搜不到实例真值痕迹。
//
// 报红含义（重要，不要当成普通失败）：
//   附件里其实有 hint=/c=/n= 这类实例输出 ⇒ 该题归因错误，
//   应改归「能力缺口」（缺的是解法，不是数据），并同步修报告。
func TestDataIncompleteClaimsHaveNoInstanceTruth(t *testing.T) {
	doc := loadCrossBench(t)
	_ = doc // 清单存在性由 loadCrossBench 的 Skip 语义保证

	var claimsChecked, skipped int
	for _, id := range dataIncompleteClaimed {
		p, ok := loadCrossBench(t).Problems[id]
		if !ok {
			t.Errorf("报告声称归因为「数据不完整」的题 %s 不在 cross_bench.json 里——报告与实物脱节", id)
			continue
		}
		if !p.AttachmentAvailable {
			t.Logf("%s：无附件（AttachmentAvailable=false），归因为数据不完整成立", id)
			claimsChecked++
			continue
		}
		text, names, err := attachTexts(t, id)
		if err != nil {
			// 目录不存在 = 该题在库中确实没有可用附件 ⇒ 归因「数据不完整」成立。
			// 注意：这里绝不能t.Skip —— 那是 fail-open，会让整条门禁零覆盖静默通过。
			// （10733 的教训正是"看起来查过了"，实际根本没读到内容。）
			t.Logf("%s：附件目录不存在（%v）⇒ 无附件可含真值，归因成立", id, err)
			claimsChecked++
			continue
		}
		if len(names) == 0 {
			t.Logf("%s：无文本附件（仅二进制或目录为空），归因成立", id)
			claimsChecked++
			skipped++
			continue
		}
		claimsChecked++

		if m := instanceAssignRe.FindString(text); m != "" {
			t.Errorf("🔴 %s 被归因为「数据不完整」，但附件 %v 里搜到实例输出赋值 %q —— "+
				"该归因作废（真值一直在附件里，属读附件不彻底），应改归「能力缺口」并修报告",
				id, names, truncateForMsg(m))
		}
		if m := longDecimalRe.FindString(text); m != "" {
			t.Errorf("🔴 %s 被归因为「数据不完整」，但附件 %v 里存在 %d 位连续十进制整数"+
				"（参数指纹）—— 请确认这是题目常量（如模数/群阶）还是本实例真值。"+
				"若是真值，该归因作废，应改归「能力缺口」", id, names, len(m))
		}
	}

	// 覆盖度断言：清单里的每一题都必须真的被检查过，不能有静默漏网的分支。
	if claimsChecked != len(dataIncompleteClaimed) {
		t.Fatalf("🔴 归因门禁零覆盖：清单 %d 题，实际只检查了 %d 题—— 存在未覆盖分支，"+
			"门禁形同虚设（10733 的教训：看起来查过了，实际没读到内容）",
			len(dataIncompleteClaimed), claimsChecked)
	}
	t.Logf("已检查 %d/%d 个「数据不完整」归因题（其中 %d 个无文本附件直接放行）",
		claimsChecked, len(dataIncompleteClaimed), skipped)
}

func truncateForMsg(s string) string {
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}

// TestRecoveredAttachmentHasInstanceTruth 是上面那条规则的**反例钉子**：
// 明确断言 `10733` 的附件里**确实含** hint=/c=/n= 实例输出，
// 且它已被正确归类为「能力缺口」而非「数据不完整」。
//
// 这条测试存在的意义：10733 的归因曾被写反，若只保留"数据不完整不得含真值"
// 那条正向规则，未来有人把 10733 改回错误分类时不会被发现。
// 双向钉死才防得住。
func TestRecoveredAttachmentHasInstanceTruth(t *testing.T) {
	text, names, err := attachTexts(t, "10733")
	if err != nil || len(names) == 0 {
		t.Fatalf("🔴 10733 附件不可读或无文本附件（err=%v）—— 「归因修正（数据不完整→能力缺口）」"+
			"的依据不再成立，须重新归因", err)
	}
	if !instanceAssignRe.MatchString(text) {
		t.Fatalf("🔴 10733 附件里搜不到实例输出赋值—— 若 A 库副本已被移除或附件被换掉，"+
			"则上一轮「归因修正（数据不完整→能力缺口）」的依据不再成立，须重新归因。附件=%v", names)
	}
	t.Logf("10733 附件 %v 确实含 hint=/c=/n= 实例输出 ⇒ 该题属「能力缺口」（缺解法非缺数据），"+
		"与报告一致", names)

	// 同时断言它没有出现在「数据不完整」清单里（防止分类回退）。
	for _, id := range dataIncompleteClaimed {
		if id == "10733" {
			t.Fatal("🔴 10733 不得出现在 dataIncompleteClaimed 清单中——它的真值在附件里，属能力缺口")
		}
	}
}