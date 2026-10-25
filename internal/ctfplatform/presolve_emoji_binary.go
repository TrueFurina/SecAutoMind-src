package ctfplatform

// presolve_emoji_binary.go —— 二进制 emoji 序列解码（CSAW-Finals 2023 forensics
// 「Emoji」；xhlj_legacy skills/emoji_binary.py Go 化，刀锋账本 #5）。
//
// 题型：纯 emoji 文本，20 个互异 emoji 构成 10 组语义对立对，每个 emoji = 1 bit，
// 每 8 个 MSB-first 拼 1 字节 → ASCII → flag。解码不依赖硬编码映射表：把每个不同
// emoji → 0/1 当作布尔变量，逐字节做可打印 ASCII 剪枝的 DFS；多候选按
// 「前缀全小写 > 正文仅 [a-z0-9_] > 更长」择优；expected_sha256 为唯一权威。
//
// 诚实口径：仅覆盖「每符号 1 bit + MSB 先 + 纯 ASCII 载荷」子集；Base100/替换表/
// 零宽隐写不在覆盖内。命中属 presolve 静态直出，不计 LLM。

import (
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
)

const (
	ebPrintLo      = 0x20
	ebPrintHi      = 0x7e
	ebMaxSymbols   = 24
	ebNodeBudget   = 4_000_000
	ebMaxSolutions = 5000
)

var (
	ebFlagRe        = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}\{[^}\s]{1,200}\}$`)
	ebLowerPrefixRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	ebLowerBodyRe   = regexp.MustCompile(`^[a-z0-9_]*$`)
)

var ebVS = [2]rune{0xFE0E, 0xFE0F}
const ebZWJ = rune(0x200D)

// ebTokenize 把文本切成 emoji grapheme 单元（base + 变体选择符 + ZWJ 序列链）。
func ebTokenize(s string) []string {
	runes := []rune(s)
	var toks []string
	i, n := 0, len(runes)
	for i < n {
		j := i + 1
		for j < n && ebIsVS(runes[j]) {
			j++
		}
		for j < n && runes[j] == ebZWJ {
			j++
			if j < n {
				j++
			}
			for j < n && ebIsVS(runes[j]) {
				j++
			}
		}
		toks = append(toks, string(runes[i:j]))
		i = j
	}
	return toks
}

func ebIsVS(r rune) bool { return r == ebVS[0] || r == ebVS[1] }

// ebIdentity 去变体选择符后的等价键（⚽ 与 ⚽️ 同一符号）。
func ebIdentity(tok string) string {
	out := tok
	for _, vs := range ebVS {
		out = strings.ReplaceAll(out, string(vs), "")
	}
	return out
}

// ebIsEmojiToken 粗判：首字符码位 ≥ U+2000 且非 ASCII 字母数字。
func ebIsEmojiToken(tok string) bool {
	if tok == "" {
		return false
	}
	ch := []rune(tok)[0]
	if ch < 0x2000 {
		return false
	}
	return !unicode.IsLetter(ch) && !unicode.IsDigit(ch)
}

func ebIsEmojiBinaryText(text string) bool {
	toks := ebNonSpaceTokens(text)
	if len(toks) < 16 || len(toks)%8 != 0 {
		return false
	}
	for _, t := range toks {
		if !ebIsEmojiToken(t) {
			return false
		}
	}
	distinct := map[string]bool{}
	for _, t := range toks {
		distinct[ebIdentity(t)] = true
	}
	return len(distinct) >= 4 && len(distinct) <= ebMaxSymbols
}

func ebNonSpaceTokens(text string) []string {
	var out []string
	for _, t := range ebTokenize(text) {
		if strings.TrimSpace(t) != "" {
			out = append(out, t)
		}
	}
	return out
}

// ebSearchBytes DFS：为每个不同 emoji 赋 0/1，逐字节可打印剪枝，产出全部候选。
func ebSearchBytes(toks []string) [][]byte {
	keys := map[string]int{}
	order := []string{}
	for _, t := range toks {
		k := ebIdentity(t)
		if _, ok := keys[k]; !ok {
			keys[k] = len(order)
			order = append(order, k)
		}
	}
	m := len(order)
	if m > ebMaxSymbols {
		return nil
	}
	var layout [][]int
	for i := 0; i+8 <= len(toks); i += 8 {
		row := make([]int, 8)
		for j := 0; j < 8; j++ {
			row[j] = keys[ebIdentity(toks[i+j])]
		}
		layout = append(layout, row)
	}
	nbytes := len(layout)

	assign := make([]int, m)
	for i := range assign {
		assign[i] = -1
	}
	out := make([]byte, nbytes)
	var results [][]byte
	nodes := 0
	exhausted := false

	var rec func(k int)
	rec = func(k int) {
		if len(results) >= ebMaxSolutions || nodes > ebNodeBudget {
			exhausted = true
			return
		}
		if k == nbytes {
			results = append(results, append([]byte{}, out...))
			return
		}
		row := layout[k]
		var unknown []int
		seen := map[int]bool{}
		for _, idx := range row {
			if assign[idx] < 0 && !seen[idx] {
				seen[idx] = true
				unknown = append(unknown, idx)
			}
		}
		total := 1 << len(unknown)
		for combo := 0; combo < total && !exhausted; combo++ {
			for i, idx := range unknown {
				assign[idx] = (combo >> i) & 1
			}
			nodes++
			v := 0
			for _, idx := range row {
				v = (v << 1) | assign[idx]
			}
			if ebPrintLo <= v && v <= ebPrintHi {
				out[k] = byte(v)
				rec(k + 1)
			}
			for _, idx := range unknown {
				assign[idx] = -1
			}
			if len(results) >= ebMaxSolutions || nodes > ebNodeBudget {
				exhausted = true
				return
			}
		}
		_ = exhausted
	}
	rec(0)
	return results
}

// ebRank 候选排序键（越大越可信）：前缀全小写 > 正文仅 [a-z0-9_] > 更长。
func ebRank(flag string) [3]int {
	pre := flag
	body := ""
	if i := strings.Index(flag, "{"); i >= 0 {
		pre = flag[:i]
		body = strings.TrimSuffix(flag[i+1:], "}")
	}
	p1, p2 := 0, 0
	if ebLowerPrefixRe.MatchString(pre) {
		p1 = 1
	}
	if ebLowerBodyRe.MatchString(body) {
		p2 = 1
	}
	return [3]int{p1, p2, len(flag)}
}

// ebDecode 从二进制 emoji 流还原 flag；expectedSHA 非空为唯一权威。
func ebDecode(text string, expectedSHA string) string {
	toks := ebNonSpaceTokens(text)
	if len(toks) < 16 || len(toks)%8 != 0 {
		return ""
	}
	for _, t := range toks {
		if !ebIsEmojiToken(t) {
			return ""
		}
	}
	var cands []string
	for _, raw := range ebSearchBytes(toks) {
		s := string(raw)
		printable := true
		for _, b := range raw {
			if b < ebPrintLo || b > ebPrintHi {
				printable = false
				break
			}
		}
		if !printable || !ebFlagRe.MatchString(s) {
			continue
		}
		cands = append(cands, s)
	}
	if len(cands) == 0 {
		return ""
	}
	if expectedSHA != "" {
		exp := strings.ToLower(strings.TrimSpace(expectedSHA))
		for _, s := range cands {
			if hex.EncodeToString(hashOf(s)) == exp {
				return s
			}
		}
		return ""
	}
	best, bestKey := "", [3]int{-1, -1, -1}
	for _, c := range cands {
		k := ebRank(c)
		if k[0] > bestKey[0] || (k[0] == bestKey[0] && (k[1] > bestKey[1] || (k[1] == bestKey[1] && k[2] > bestKey[2]))) {
			best, bestKey = c, k
		}
	}
	return best
}

// tryEmojiBinary 注册表入口：纯 emoji 流触发门。
func tryEmojiBinary(text string, attachments map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	scan := func(raw string) {
		if len(raw) < 32 || !ebIsEmojiBinaryText(raw) {
			return
		}
		if flag := ebDecode(raw, ""); flag != "" && !seen[flag] {
			seen[flag] = true
			out = append(out, flag)
		}
	}
	scan(text)
	for _, a := range attachments {
		scan(a)
	}
	return out
}
