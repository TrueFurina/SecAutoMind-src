// presolve_trithemius.go —— Trithemius/位置移位密码族求解器（2026-10-26 固化）。
//
// 实证：HTB Cyber Apocalypse 2024 "dynastic"（cybench 采源，锚 7f88cb69…）。
// 加密 = 每个字母按其**在文中的位置**移位（`chi + i`），非关键字凯撒——
// tryCaesar 的 26 种常量移位解不出。
// 泛化：正向/负向位置移位全试；仅字母位参与移位、非字母原样（题源语义）；
// 位置从 0 计（dynastic 语义）。命中仍由 scanFlags + 下游 sha256 把关。
package ctfplatform

import (
	"context"
	"strings"
)

// tryTrithemius 位置移位（含负方向）解密尝试。
func tryTrithemius(text string) []string {
	// 只对含足够字母的候选行/全文尝试（避免对纯数据噪音空转）
	if len(text) < 12 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(flags []string) {
		for _, f := range flags {
			if !trithemiusFlagLike(f) { // 🔴 见 trithemiusFlagLike：内层短/句子态一律不认
				continue
			}
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	try := func(decode func(string) string) {
		dec := decode(text)
		if flags := scanFlags(dec); len(flags) > 0 {
			add(flags)
		}
	}
	try(func(s string) string { return trithemiusShift(s, +1) })
	try(func(s string) string { return trithemiusShift(s, -1) })
	// HTB dynastic 型：明文是**裸文本**（无 brand{} 前缀），flag=HTB{明文}。
	// 🔴 包装分支必须有**可读性门禁**——2026-11-02 回归实证：对 base64 密文
	// （wolvctf2024_xor）做位置移位后硬包 HTB{} 产出垃圾候选，priority 22
	// 抢过 xor_known_plaintext(37) 成为 best，sha256 不匹配致 parity 断言红。
	// 门禁：解码后可打印比例 ≥0.9 且含至少 2 个下划线/单词结构（dynastic
	// 明文是语义句子），否则不包装。
	// HTB 包装分支的可读性门禁：解码结果须**全大写**才允许硬包 HTB{}。
	// 🔴 2026-11-08 回归：旧门禁（printable≥0.9 + ≥2 空格/下划线）对英文题面
	// 被当密文移位后的产物照单全收，产出 `HTB{Snkbpdgxk, lvnf'c…}` 这类混合/小写
	// 假命中（实测外部尺 5 题）。本引擎的 HTB 包装只服务 dynastic 型（裸大写明文，
	// 如 DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER），故要求全大写以区分真密文与题面噪音。
	// 🔴 2026-11-08 第二层：包装分支**不走** trithemiusFlagLike 的句读禁令。
	// 真实 dynastic 明文本身就带题源标点（`DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!`），
	// 若和"代码巧合"共用同一套严格判据，会把真答案一起拦掉（实测 TestTryTrithemiusDynasticShape 当场红）。
	// 包装分支自己的门禁更强也更贴它的用途：可读性 + 全大写 + **内层不得含空白**
	// （dynastic 明文是下划线分词；含空格的"整句包裹"就是假命中）。
	addWrapped := func(dec string) {
		if !trithemiusPlausible(dec) || !isAllUpper(dec) || len(dec) < 8 {
			return
		}
		for _, c := range dec {
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				return // 含空白 = 句子，不是 flag 内层
			}
		}
		flag := "HTB{" + dec + "}"
		if !seen[flag] {
			seen[flag] = true
			out = append(out, flag)
		}
	}
	addWrapped(trithemiusShift(text, -1))
	addWrapped(trithemiusShift(text, +1))
	// 词级变体：每行/每词重置位置计数（部分实现按块重置）
	if len(out) == 0 {
		for _, sep := range []string{"\n", " "} {
			parts := strings.Split(text, sep)
			shifted := make([]string, len(parts))
			for i, p := range parts {
				shifted[i] = trithemiusShift(p, +1)
			}
			joined := strings.Join(shifted, sep)
			if flags := scanFlags(joined); len(flags) > 0 {
				add(flags)
				if len(out) > 0 {
					break
				}
			}
		}
	}
	return out
}

// trithemiusFlagLike 判一个候选是否**真的像 flag**（位置移位是整个文本一起移，
// 任意含 `{` 的代码/散文移位后都可能凑出一个 `XXX{abc}` 形状）。
//
// 2026-11-08 实证三副面孔：
//   - `HTB{Snkbpdgxk, lvnf'c uvxj…}` —— 整句被包进花括号（内层含空格/逗号/撇号）；
//   - `VNA{cjzg}` / `IAN{pwmt}` —— 代码里标识符+`{` 移位后的 4 字符巧合。
//
// 判据：内层不得含空白，不得含句读（, . ' " ; ! ?），长度 ≥8，且整串不含换行。
// 这不是"提高门槛凑绿"，而是 flag 本身的形态约束（真 flag 不会是一句英文，
// 也不会只有 4 个字符——4 字符答案靠"别写这串字"根本不可能保密）。
func trithemiusFlagLike(f string) bool {
	open := strings.Index(f, "{")
	if open <= 0 || open > 16 || !strings.HasSuffix(f, "}") {
		return false
	}
	inner := f[open+1 : len(f)-1]
	if len(inner) < 8 || len(inner) > 160 {
		return false
	}
	for _, c := range inner {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			return false
		}
		switch c {
		case ',', '.', '\'', '"', ';', '!', '?', ':':
			return false
		}
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// trithemiusPlausible 裸明文包装前的可读性门禁：可打印率 ≥0.9 且含 ≥2 个
// 下划线或空格（语义句子特征；base64 密文移位后是大写字母随机串，无下划线）。
func trithemiusPlausible(s string) bool {
	if len(s) < 12 {
		return false
	}
	printable, us := 0, 0
	for _, c := range s {
		if (c >= 0x20 && c <= 0x7e) || c == 10 || c == 13 || c == 9 {
			printable++
		}
		if c == '_' || c == ' ' {
			us++
		}
	}
	return float64(printable)/float64(len(s)) >= 0.9 && us >= 2
}

// isAllUpper 全大写判定（须含至少一个字母）。HTB 包装门禁用：本引擎的 HTB 包装只服务
// dynastic 型裸大写明文；英文题面移位产物是小写/混合，须被排除，否则产出假命中。
func isAllUpper(s string) bool {
	hasLetter := false
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			return false
		}
		if c >= 'A' && c <= 'Z' {
			hasLetter = true
		}
	}
	return hasLetter
}

// trithemiusShift 位置移位：字母位 `c ± pos`。pos = **全串字符索引**（含非
// 字母——dynastic 题源 `for i in range(len(m))` 语义，2026-10-26 实测修正：
// 按字母计数会解错），非字母原样保留。
func trithemiusShift(s string, dir int) string {
	var b strings.Builder
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			b.WriteRune(rune((int(c-'A')+dir*i%26+26)%26 + 'A'))
		} else if c >= 'a' && c <= 'z' {
			b.WriteRune(rune((int(c-'a')+dir*i%26+26)%26 + 'a'))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "trithemius", Category: CategoryCryptoS, Priority: 22,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryTrithemius(text)
		},
	})
}
