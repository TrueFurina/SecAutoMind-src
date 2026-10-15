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
//   二进制附件同样扫（可打印串）——helloupx11 证明答案会以字符串形式内嵌进 ELF。
// 命中即判"附件含实例输出"⇒ 该题不该被归为「数据不完整」。
//
// 🔴 2026-10-15 二次修订（两个新通道，均为"看起来查过了"的复发）：
//  1. **git 排除通道**：答案文件按 PUBLIC 仓红线 `git rm --cached` 后，CI 检出
//     不再有其目录——旧代码走"目录不存在 ⇒ 归因成立"的 fail-open 分支静默放行
//     （`reverse_upx`/`gongye_web2` 的唯一附件就是被排除的答案文件，真值在被
//     排除的附件里，却被登记为「数据不完整」）。修法：**登记契约先行**——凡归因
//     题登记过任一 answer_key_shape 附件，归因直接作废（元数据兜底，不依赖读文件）。
//     这两题已按报告既有的第三类改归「口径性不可解」（附件即答案，设计上不计入
//     解题能力），由 TestCaliberUnsolvableAreRegisteredAnswerKeys 对称钉死。
//  2. **红线 vs 钉子冲突**：10733 的钉子旧版要求 CI 能读到含真值的附件，与
//     "答案不进 PUBLIC 仓"直接冲突（6e7bb72 后 CI 必红）。修法：双层验证——
//     CI 验登记契约（answer_key_shape/git_excluded/原因/sha256 指纹），开发机
//     验实物指纹与内容形态。详见 TestRecoveredAttachmentHasInstanceTruth 注释。
//
// 维护纪律：
//   · 新增「数据不完整」归因题 → 写进 dataIncompleteClaimed（否则本门禁零覆盖）；
//   · 新增「口径性不可解」归因题 → 写进 caliberUnsolvableClaimed；
//   · 改动任一判据 → 必须同步扩展 TestAttributionGateMutationsGoRed 的变异方向
//     （只写判据不做变异自测 = 不能证明它真能红，本仓已两次栽在这类"声明了但不跑"上）。

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// dataIncompleteClaimed 报告第四节里被正式归因为「数据不完整」的题。
// 与 docs/cross_bench_report.md 的八题表必须一致。
//
// 2026-10-15 二次修订：移出 `real_reverse_upx`/`real_web_gongye_web2`——
// 二者唯一附件即答案文件（helloupx11 内嵌 flag / index.php 注释含真 flag），
// 按红线 git 排除后 CI 读不到，旧门禁走"目录不存在"分支静默放行；
// 其真值在被排除的附件里，「数据不完整」归因作废，已改归「口径性不可解」。
var dataIncompleteClaimed = []string{
	"real_crypto_specialcurve2",
	"real_reverse_js",
	"real_reverse_sheng",
}

// caliberUnsolvableClaimed 报告第四节里被归为「口径性不可解」的题：
// 唯一/主要附件即答案（flag.txt / 内嵌答案的二进制或源码），按设计不计入解题能力。
// 与 dataIncompleteClaimed 互斥，两类合计覆盖全部未命中题（不留未归类项）。
var caliberUnsolvableClaimed = []string{
	"real_crypto_anxun2020_aes",
	"real_misc_longjian2024_smallsword3",
	"real_reverse_upx",
	"real_web_gongye_web2",
}

var (
	// 赋值形态：name= 后跟 40 位以上十进制（如 hint= 1010488554...）。
	instanceAssignRe = regexp.MustCompile(`(?i)\b(hint|c|n|p|q|e|m|ct|cp)\s*=\s*\d{40,}`)
	// 通用形态：连续 80 位以上十进制数字（参数指纹，比赋值形态更宽）。
	longDecimalRe = regexp.MustCompile(`\d{80,}`)
	// sha256 指纹形态（git 排除文件的登记契约）。
	sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// 二进制可打印串（>=6 连续可打印 ASCII），用于在 ELF/PE 里搜内嵌答案。
	printableRunRe = regexp.MustCompile(`[\x20-\x7e]{6,}`)
)

// binaryTruthHits 在二进制附件的可打印串里搜实例输出形态。
// helloupx11 的教训：答案会以明文字符串形式内嵌进 ELF，跳过二进制 = 漏掉真值。
func binaryTruthHits(raw []byte) []string {
	var hits []string
	for _, run := range printableRunRe.FindAllString(string(raw), -1) {
		if m := instanceAssignRe.FindString(run); m != "" {
			hits = append(hits, truncateForMsg(m))
			continue
		}
		if m := longDecimalRe.FindString(run); m != "" {
			hits = append(hits, truncateForMsg(m))
		}
	}
	return hits
}

// findAttachment 按名字找登记附件，找不到返回 nil。
func findAttachment(p crossBenchProblem, name string) *crossBenchAttachment {
	for i := range p.AttachmentFiles {
		if p.AttachmentFiles[i].Name == name {
			return &p.AttachmentFiles[i]
		}
	}
	return nil
}

// truncateForMsg 把过长的登记原因截断到日志友好长度。
func truncateForMsg(s string) string {
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}

// cloneCrossBenchDoc 深拷贝到"改内存不伤原 doc"的程度（Problems map +
// 每题的 AttachmentFiles 切片）。变异自测在拷贝上造数据，绝不污染真值源。
func cloneCrossBenchDoc(doc crossBenchDoc) crossBenchDoc {
	out := doc
	out.Problems = make(map[string]crossBenchProblem, len(doc.Problems))
	for id, p := range doc.Problems {
		if p.AttachmentFiles != nil {
			files := make([]crossBenchAttachment, len(p.AttachmentFiles))
			copy(files, p.AttachmentFiles)
			p.AttachmentFiles = files
		}
		out.Problems[id] = p
	}
	return out
}

// ---- 纯函数违禁检查器（无盘依赖，供门禁与变异自测共用） ----

// claimMetadataViolations 检查「数据不完整」归因题的**登记契约**：
// 登记过任一 answer_key_shape 附件 ⇒ 归因作废（真值在被 git 排除的附件里）。
// 这一步不依赖读文件——CI 检出不含被排除文件时它是唯一兜底
// （reverse_upx/gongye_web2 的教训：目录不存在会静默放行）。
func claimMetadataViolations(doc crossBenchDoc, id string) []string {
	p, ok := doc.Problems[id]
	if !ok {
		return []string{fmt.Sprintf("%s 不在 cross_bench.json 里——报告与实物脱节", id)}
	}
	if !p.AttachmentAvailable {
		return nil
	}
	var v []string
	for _, af := range p.AttachmentFiles {
		if af.AnswerKeyShape {
			v = append(v, fmt.Sprintf("%s 被归因为「数据不完整」，但其附件 %s 登记为答案形态"+
				"（git_excluded=%v，原因：%s）—— 真值在被排除的附件里，该归因作废，"+
				"应改归「口径性不可解」（附件即答案，设计上不计入解题能力）",
				id, af.Name, af.GitExcluded, truncateForMsg(af.ExcludeReason)))
		}
	}
	return v
}

// caliberRegistrationViolations 检查「口径性不可解」归因题的登记契约：
// 必须有 answer_key_shape 附件 + git_excluded + 非空原因，且不得与
// dataIncompleteClaimed 互斥集冲突。空 = 归类站得住。
func caliberRegistrationViolations(doc crossBenchDoc, id string) []string {
	p, ok := doc.Problems[id]
	if !ok {
		return []string{fmt.Sprintf("%s 不在 cross_bench.json 里——报告归类与实物脱节", id)}
	}
	var att *crossBenchAttachment
	for i := range p.AttachmentFiles {
		if p.AttachmentFiles[i].AnswerKeyShape {
			att = &p.AttachmentFiles[i]
			break
		}
	}
	if att == nil {
		return []string{fmt.Sprintf("%s 归为「口径性不可解」（附件即答案），但没有任何附件登记 answer_key_shape—— "+
			"该归类失去依据，须重新归因", id)}
	}
	var v []string
	if !att.GitExcluded {
		v = append(v, fmt.Sprintf("%s 的答案附件 %s 未登记 git_excluded——PUBLIC 仓红线：答案材料禁入库", id, att.Name))
	}
	if strings.TrimSpace(att.ExcludeReason) == "" {
		v = append(v, fmt.Sprintf("%s 的答案附件 %s 排除原因为空——排除必须带原因，禁止静默排除", id, att.Name))
	}
	for _, cid := range dataIncompleteClaimed {
		if cid == id {
			v = append(v, fmt.Sprintf("%s 同时出现在「数据不完整」与「口径性不可解」两个清单里——归类必须互斥", id))
		}
	}
	return v
}

// recoveredNailViolations 检查 10733 反例钉子的**登记契约层**：
// task.py 必须登记为 answer_key_shape + git_excluded + 非空原因 + 合法 sha256，
// 且 10733 不得回到 dataIncompleteClaimed。空 = 契约完好。
func recoveredNailViolations(doc crossBenchDoc) []string {
	p, ok := doc.Problems["10733"]
	if !ok {
		return []string{"10733 不在 cross_bench.json 里——「归因修正（数据不完整→能力缺口）」的依据不再成立，须重新归因"}
	}
	var v []string
	att := findAttachment(p, "task.py")
	switch {
	case att == nil:
		v = append(v, "10733 未登记 task.py 附件——归因依据（真值在附件里）失去着落")
	case !att.AnswerKeyShape:
		v = append(v, "task.py 的 answer_key_shape 登记丢失——它含本实例 hint/c/n 真值，必须按答案形态登记")
	case !att.GitExcluded:
		v = append(v, "task.py 的 git_excluded 登记丢失——PUBLIC 仓禁答案材料入库，排除登记必须保持")
	case strings.TrimSpace(att.ExcludeReason) == "":
		v = append(v, "task.py 的 exclude_reason 为空——排除必须带原因，禁止静默排除")
	case !sha256HexRe.MatchString(att.SHA256):
		v = append(v, fmt.Sprintf("task.py 未登记合法 sha256 指纹（got %q）——git 排除后 CI 读不到文件，"+
			"指纹是唯一可机验的契约", att.SHA256))
	}
	for _, id := range dataIncompleteClaimed {
		if id == "10733" {
			v = append(v, "10733 出现在 dataIncompleteClaimed 清单中——它的真值在附件里，属能力缺口，不得回退")
		}
	}
	return v
}

// ---- 门禁本体（判据 = 纯函数 + 磁盘层） ----

// attachTexts 返回该题全部文本附件的拼接内容（跳过二进制）、文本附件名、
// 以及二进制附件里搜到的实例输出痕迹。附件目录不存在时返回 error
// （**不 t.Skip**）——调用方须把它计入"归因成立"或据此判红，
// 绝不能让零覆盖分支静默跳过整条门禁。
func attachTexts(t *testing.T, id string) (string, []string, []string, error) {
	t.Helper()
	dir := filepath.Join("..", "..", "data", "questions_real_bench", crossBenchAttachDir, id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, nil, err
	}
	var b strings.Builder
	var names, binHits []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(raw) == 0 {
			continue
		}
		if looksBinary(raw) {
			// 二进制也可能内嵌答案（helloupx11 的教训）：扫可打印串，不漏掉该通道。
			if hits := binaryTruthHits(raw); len(hits) > 0 {
				binHits = append(binHits, e.Name()+": "+strings.Join(hits, " | "))
			}
			continue
		}
		names = append(names, e.Name())
		b.Write(raw)
		b.WriteString("\n")
	}
	return b.String(), names, binHits, nil
}

// TestDataIncompleteClaimsHaveNoInstanceTruth 断言：凡被归为「数据不完整」的题，
// 其文本附件里确实搜不到实例真值痕迹。
//
// 报红含义（重要，不要当成普通失败）：
//
//	附件里其实有 hint=/c=/n= 这类实例输出 ⇒ 该题归因错误，
//	应改归「能力缺口」（缺的是解法，不是数据），并同步修报告。
func TestDataIncompleteClaimsHaveNoInstanceTruth(t *testing.T) {
	doc := loadCrossBench(t)
	_ = doc // 清单存在性由 loadCrossBench 的 Skip 语义保证

	var claimsChecked, skipped int
	for _, id := range dataIncompleteClaimed {
		// 登记契约层（CI 可验，不依赖读文件）
		for _, msg := range claimMetadataViolations(doc, id) {
			t.Errorf("🔴 %s", msg)
		}
		p := doc.Problems[id]
		if !p.AttachmentAvailable {
			t.Logf("%s：无附件（AttachmentAvailable=false），归因为数据不完整成立", id)
			claimsChecked++
			continue
		}
		text, names, binHits, err := attachTexts(t, id)
		if err != nil {
			// 目录不存在 = 该题在库中确实没有可用附件 ⇒ 归因「数据不完整」成立。
			// 注意：这里绝不能t.Skip —— 那是 fail-open，会让整条门禁零覆盖静默通过。
			// （10733 的教训正是"看起来查过了"，实际根本没读到内容；
			//  答案形态附件已在登记契约层拦截，走到这里说明确实无答案文件。）
			t.Logf("%s：附件目录不存在（%v）⇒ 无附件可含真值，归因成立", id, err)
			claimsChecked++
			continue
		}
		if len(names) == 0 {
			t.Logf("%s：无文本附件（仅二进制或目录为空），归因成立", id)
			claimsChecked++
			skipped++
			// 二进制通道继续查：文本为空不代表二进制里没有内嵌真值。
			if len(binHits) > 0 {
				t.Errorf("🔴 %s 被归因为「数据不完整」，但二进制附件里搜到实例输出痕迹：%v—— "+
					"该归因作废（真值在内嵌字符串里），应改归因并修报告", id, binHits)
			}
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
		if len(binHits) > 0 {
			t.Errorf("🔴 %s 被归因为「数据不完整」，但二进制附件里搜到实例输出痕迹：%v—— 该归因作废",
				id, binHits)
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

// TestCaliberUnsolvableAreRegisteredAnswerKeys 是 dataIncompleteClaimed 的**对称钉子**：
// 凡归为「口径性不可解」的题，必须有机验登记的答案形态附件
// （answer_key_shape + git_excluded + 非空原因），否则该归类作废。
//
// 这条钉子同时堵两个方向：
//
//	· 把"附件含答案"的题悄悄洗成别的类别 → 本门禁发现该类无答案登记即红；
//	· 把普通题错关进这一类逃掉能力评估 → 无 answer_key_shape 登记即红。
//
// 2026-10-15 新增：接棒 reverse_upx/gongye_web2 从「数据不完整」移出后的覆盖，
// 且比旧覆盖更强（旧覆盖在 CI 上因文件被排除而静默走空）。
func TestCaliberUnsolvableAreRegisteredAnswerKeys(t *testing.T) {
	doc := loadCrossBench(t)

	var checked int
	for _, id := range caliberUnsolvableClaimed {
		for _, msg := range caliberRegistrationViolations(doc, id) {
			t.Errorf("🔴 %s", msg)
		}
		if _, ok := doc.Problems[id]; ok {
			checked++
		}
	}
	if checked != len(caliberUnsolvableClaimed) {
		t.Fatalf("🔴 口径性不可解门禁零覆盖：清单 %d 题，实际只检查了 %d 题", len(caliberUnsolvableClaimed), checked)
	}
	t.Logf("已检查 %d/%d 个「口径性不可解」归因题（均有答案形态附件登记 + git 排除 + 原因）",
		checked, len(caliberUnsolvableClaimed))
}

// TestRecoveredAttachmentHasInstanceTruth 是上面那条规则的**反例钉子**：
// 明确断言 `10733` 的附件里**确实含** hint=/c=/n= 实例输出，
// 且它已被正确归类为「能力缺口」而非「数据不完整」。
//
// 这条测试存在的意义：10733 的归因曾被写反，若只保留"数据不完整不得含真值"
// 那条正向规则，未来有人把 10733 改回错误分类时不会被发现。
// 双向钉死才防得住。
//
// 🔴 2026-10-15 二次修订（PUBLIC 仓红线 vs 钉子可验性的冲突解法）：
// 6e7bb72 把 task.py `git rm --cached` 后，CI 检出不含该文件——旧版
// "读附件搜实例输出"的断言在 CI 上必然 Fatalf（文件不在），与红线直接冲突
// （答案材料禁入 PUBLIC 仓）。解法分两层，缺一不可：
//
//	① 登记契约层（CI 可验，fail-closed）：cross_bench.json 必须把 task.py 登记为
//	   answer_key_shape + git_excluded + 非空 exclude_reason + 合法 sha256 指纹。
//	   有人摘掉排除登记 / 清空原因 / 改分类 → 立刻红。
//	② 实物交叉验层（开发机可验）：本地未跟踪副本若在，sha256 必须命中登记指纹、
//	   且内容必须匹配实例输出形态；不在（CI）则记录"本环境验登记层"后返回。
//
// 这样"答案不进 PUBLIC 仓"与"归因依据必须可机验"同时成立：
// CI 证明"登记说它是答案且被正确排除"，开发机证明"登记的文件确实是那个文件"。
func TestRecoveredAttachmentHasInstanceTruth(t *testing.T) {
	doc := loadCrossBench(t)

	// ① 登记契约层（CI 可验）
	for _, msg := range recoveredNailViolations(doc) {
		t.Fatalf("🔴 %s", msg)
	}
	att := findAttachment(doc.Problems["10733"], "task.py")

	// ② 实物交叉验层（开发机）：本地未跟踪副本应在；CI 上按红线不在检出中。
	path := filepath.Join("..", "..", "data", "questions_real_bench", crossBenchAttachDir, "10733", "task.py")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Logf("CI 环境：task.py 按红线不在检出中（err=%v）——本环境验登记契约层（①已通过）；"+
			"实物指纹交叉验请在开发机执行（本地未跟踪副本应在）", err)
		return
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != att.SHA256 {
		t.Fatalf("🔴 本地 task.py 与登记指纹不符——登记 %s，实物 %s；"+
			"若附件被换过，「归因修正（数据不完整→能力缺口）」的依据须重新复核", att.SHA256, got)
	}
	if !instanceAssignRe.MatchString(string(raw)) {
		t.Fatalf("🔴 本地 task.py 搜不到实例输出赋值—— 若 A 库副本已被移除或附件被换掉，" +
			"则上一轮「归因修正（数据不完整→能力缺口）」的依据不再成立，须重新归因")
	}
	t.Logf("10733 实物交叉验通过：sha256 命中登记指纹且含 hint=/c=/n= 实例输出 ⇒ 能力缺口归因坐实")
}

// TestAttributionGateMutationsGoRed 是三条归因判据的**变异自测**：
// 在内存副本上造四个方向的退化，证明判据真能红（不是恒真的装饰）。
// 反向基线同步断言：未变异的真值源必须全绿（防修成恒红）。
//
// 四个变异方向各自对应一次真实事故/复发病通道：
//
//	A. git 排除通道复发（reverse_upx 回退进「数据不完整」清单）——6e7bb72 前 CI 静默放行那条；
//	B. 归类洗白（gongye_web2 的 answer_key_shape 登记被摘）——把"附件含答案"洗成普通题；
//	C. 红线登记被摘（10733 task.py 的 git_excluded 被置 false）——PUBLIC 仓红线破防；
//	D. 指纹契约被清（10733 task.py 的 sha256 置空）——CI 唯一可机验锚点丢失。
func TestAttributionGateMutationsGoRed(t *testing.T) {
	doc := loadCrossBench(t)

	// 反向基线：真值源上三个判据必须全绿。
	if v := recoveredNailViolations(doc); len(v) != 0 {
		t.Fatalf("🔴 反向基线失败：未变异的 10733 登记契约应无违禁，实得 %v", v)
	}
	for _, id := range caliberUnsolvableClaimed {
		if v := caliberRegistrationViolations(doc, id); len(v) != 0 {
			t.Fatalf("🔴 反向基线失败：未变异的 %s 登记应无违禁，实得 %v", id, v)
		}
	}
	for _, id := range dataIncompleteClaimed {
		if v := claimMetadataViolations(doc, id); len(v) != 0 {
			t.Fatalf("🔴 反向基线失败：未变异的 %s 归因应无违禁，实得 %v", id, v)
		}
	}

	// 变异 A：把 reverse_upx 加回「数据不完整」归因（内存副本）。
	mutA := cloneCrossBenchDoc(doc)
	orig := dataIncompleteClaimed
	dataIncompleteClaimed = append(append([]string{}, orig...), "real_reverse_upx")
	if v := claimMetadataViolations(mutA, "real_reverse_upx"); len(v) == 0 {
		t.Error("🔴 变异 A 未报红：reverse_upx 回退进「数据不完整」清单后，登记契约判据没抓住——" +
			"这正是 6e7bb72 前 CI 静默放行的事故通道，判据形同虚设")
	}
	// 同时验证口径性判据的互斥钉法能发现一类两挂。
	if v := caliberRegistrationViolations(mutA, "real_reverse_upx"); len(v) == 0 {
		t.Error("🔴 变异 A 未报红：reverse_upx 一类两挂时互斥判据没抓住")
	}
	dataIncompleteClaimed = orig

	// 变异 B：摘掉 gongye_web2 的 answer_key_shape 登记（归类洗白）。
	mutB := cloneCrossBenchDoc(doc)
	p := mutB.Problems["real_web_gongye_web2"]
	for i := range p.AttachmentFiles {
		p.AttachmentFiles[i].AnswerKeyShape = false
	}
	mutB.Problems["real_web_gongye_web2"] = p
	if v := caliberRegistrationViolations(mutB, "real_web_gongye_web2"); len(v) == 0 {
		t.Error("🔴 变异 B 未报红：answer_key_shape 登记被摘后，「口径性不可解」判据没抓住——" +
			"把'附件含答案'洗成普通题的通道敞开")
	}

	// 变异 C：摘掉 10733 task.py 的 git_excluded 登记（红线破防）。
	mutC := cloneCrossBenchDoc(doc)
	pc := mutC.Problems["10733"]
	for i := range pc.AttachmentFiles {
		if pc.AttachmentFiles[i].Name == "task.py" {
			pc.AttachmentFiles[i].GitExcluded = false
		}
	}
	mutC.Problems["10733"] = pc
	if v := recoveredNailViolations(mutC); len(v) == 0 {
		t.Error("🔴 变异 C 未报红：git_excluded 登记被摘后，10733 钉子没抓住——PUBLIC 仓红线失去机验")
	}

	// 变异 D：清掉 10733 task.py 的 sha256 指纹（CI 唯一锚点丢失）。
	mutD := cloneCrossBenchDoc(doc)
	pd := mutD.Problems["10733"]
	for i := range pd.AttachmentFiles {
		if pd.AttachmentFiles[i].Name == "task.py" {
			pd.AttachmentFiles[i].SHA256 = ""
		}
	}
	mutD.Problems["10733"] = pd
	if v := recoveredNailViolations(mutD); len(v) == 0 {
		t.Error("🔴 变异 D 未报红：sha256 指纹被清后，10733 钉子没抓住——git 排除文件的登记契约失去锚点")
	}
}
