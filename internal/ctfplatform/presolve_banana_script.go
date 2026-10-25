package ctfplatform

// presolve_banana_script.go —— CSAW-Quals 2017「bananascript」虚拟机编码解码 +
// 滚动异或还原（xhlj_legacy skills/banana_script.py Go 化，刀锋账本 #6）。
//
// 脚本里每个 token 都是 7 字母单词 "bananas" 的大小写变体（大写=1）→ 0..127 词值
// → 字符表映射 ASCII。解法：首条「store 常量」指令的 48 词常量 → crib `flag{`
// 解滚动异或密钥前 5 字节 → 花括号内 [A-Za-z0-9_] 约束解后 3 字节（列内取最大
// = 官方枚举序末位，本题恰唯一真解）。
//
// 诚实口径：只覆盖「banana 编码 + 单条 store 常量 + 8 字节滚动异或」子集；
// mix/sge/jmp 控制流未实现（本题无需）。命中属 presolve 静态直出，不计 LLM。

import (
	"regexp"
	"strings"
)

const bsAlphabet = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	" \n" +
	"0123456789" +
	",./;'[]=-`~!@#$%^&*()_+{}|\\:\"?><"

const bsWordTemplate = "bananas"
const bsCrib = "flag{"

var (
	bsWordRe      = regexp.MustCompile(`^[bB][aA][nN][aA][nN][aA][sS]$`)
	bsFlagRe      = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}\{[^}\s]{1,200}\}$`)
	bsBodyAllowed = func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
	}
)

// bsNumberToChar 词值 n(0..127) → 字符（127-n 索引字符表）。
func bsNumberToChar(n int) (byte, bool) {
	idx := 127 - n
	if idx < 0 || idx >= len(bsAlphabet) {
		return 0, false
	}
	return bsAlphabet[idx], true
}

// bsCharToNumber 字符 → 词值（bsNumberToChar 的逆）。
func bsCharToNumber(ch byte) (int, bool) {
	idx := strings.IndexByte(bsAlphabet, ch)
	if idx < 0 {
		return 0, false
	}
	return 127 - idx, true
}

// bsWordValue 7 字母大小写 → 7 比特词值（大写=1，MSB 在前）。
func bsWordValue(word string) int {
	v := 0
	for _, c := range word {
		v = (v << 1) | boolToInt(c >= 'A' && c <= 'Z')
	}
	return v
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// bsNumberToWord 词值 → banana 词（bsWordValue 的逆）。
func bsNumberToWord(n int) string {
	var sb strings.Builder
	for i, tpl := range []byte(bsWordTemplate) {
		if n>>(6-i)&1 == 1 {
			sb.WriteByte(tpl - 32) // 大写
		} else {
			sb.WriteByte(tpl)
		}
	}
	return sb.String()
}

// bsLooksLikeWord 合法 banana 词（7 字母 banANaS 大小写变体）。
func bsLooksLikeWord(tok string) bool {
	return bsWordRe.MatchString(tok)
}

// bsIsBananaScript 判定：≥20 token 且 ≥90% 为 banana 词。
func bsIsBananaScript(raw string) bool {
	toks := strings.Fields(raw)
	if len(toks) < 20 {
		return false
	}
	good := 0
	for _, t := range toks {
		if bsLooksLikeWord(t) {
			good++
		}
	}
	return good >= 20 && good*10 >= 9*len(toks)
}

// bsCandidateCiphertexts 收集「store <常量>」指令的常量词值序列（文件出现序）。
func bsCandidateCiphertexts(text string) [][]int {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	var out [][]int
	for _, line := range strings.Split(text, "\n") {
		toks := strings.Fields(line)
		if len(toks) < 4 {
			continue
		}
		ok := true
		for _, t := range toks {
			if !bsLooksLikeWord(t) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		vals := make([]int, len(toks))
		for i, t := range toks {
			vals[i] = bsWordValue(t)
		}
		// 形态：<寄存器词> <store 操作词 16> <常量词...>
		if vals[1] == 16 && len(vals)-2 >= 16 {
			out = append(out, vals[2:])
		}
	}
	return out
}

// bsRecoverFlag crib + 字符集约束解 8 字节滚动异或密钥（列内取最大 = 官方枚举序末位）。
func bsRecoverFlag(ct []int) string {
	n := len(ct)
	if n < 16 || n%8 != 0 {
		return ""
	}
	key := make([]int, 8)
	// 前 5 字节：crib "flag{" 直接推（flag 字符先过字符表换成词值）
	for i := 0; i < 5; i++ {
		cn, ok := bsCharToNumber(bsCrib[i])
		if !ok {
			return ""
		}
		k := ct[i] ^ cn
		if ch, ok2 := bsNumberToChar(ct[i] ^ k); !ok2 || ch != bsCrib[i] {
			return ""
		}
		key[i] = k
	}
	// 列分组：slot 5..7 的合法字节彼此独立，升序扫描取最大（= 官方枚举序末位）
	columns := map[int][]int{}
	for pos := 0; pos < n; pos++ {
		columns[pos%8] = append(columns[pos%8], pos)
	}
	for slot := 5; slot < 8; slot++ {
		best := -1
		for k := 0; k < 128; k++ {
			ok := true
			for _, pos := range columns[slot] {
				ch, ok2 := bsNumberToChar(ct[pos] ^ k)
				if !ok2 {
					ok = false
					break
				}
				if pos == n-1 {
					if ch != '}' {
						ok = false
						break
					}
				} else if !bsBodyAllowed(ch) {
					ok = false
					break
				}
			}
			if ok {
				best = k // 升序扫描，最后一个即最大
			}
		}
		if best < 0 {
			return ""
		}
		key[slot] = best
	}
	flag := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		ch, ok := bsNumberToChar(ct[i] ^ key[i%8])
		if !ok {
			return ""
		}
		flag = append(flag, ch)
	}
	fs := string(flag)
	if !bsFlagRe.MatchString(fs) {
		return ""
	}
	if !strings.HasPrefix(fs, bsCrib) || !strings.HasSuffix(fs, "}") {
		return ""
	}
	for _, c := range fs[5 : len(fs)-1] {
		if !bsBodyAllowed(byte(c)) {
			return ""
		}
	}
	return fs
}

// bsSolveText 从 banana 脚本正文还原 flag；非目标形态 → ""。
func bsSolveText(text string) string {
	if !bsIsBananaScript(text) {
		return ""
	}
	for _, ct := range bsCandidateCiphertexts(text) {
		if flag := bsRecoverFlag(ct); flag != "" {
			return flag
		}
	}
	return ""
}

// tryBananaScript 注册表入口：banana 脚本触发门。
func tryBananaScript(text string, attachments map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	scan := func(raw string) {
		if len(raw) < 64 || !bsIsBananaScript(raw) {
			return
		}
		if flag := bsSolveText(raw); flag != "" && !seen[flag] {
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
