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
	// HTB dynastic 型：明文是**裸文本**（无 brand{} 前缀），flag=HTB{明文}——
	// scanFlags 对裸文本必空。补 HTB 包装尝试（题目指引原话：
	// "wrap the decrypted text with the HTB flag format"）。
	try(func(s string) string { return "HTB{" + trithemiusShift(s, -1) + "}" })
	try(func(s string) string { return "HTB{" + trithemiusShift(s, +1) + "}" })
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
