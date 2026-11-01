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
	try := func(decode func(string) string) {
		dec := decode(text)
		if flags := scanFlags(dec); len(flags) > 0 {
			for _, f := range flags {
				if !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
			}
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
	try(func(s string) string {
		dec := trithemiusShift(s, -1)
		if trithemiusPlausible(dec) {
			return "HTB{" + dec + "}"
		}
		return ""
	})
	try(func(s string) string {
		dec := trithemiusShift(s, +1)
		if trithemiusPlausible(dec) {
			return "HTB{" + dec + "}"
		}
		return ""
	})
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
				try(func(string) string { return joined })
				break
			}
		}
	}
	return out
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
