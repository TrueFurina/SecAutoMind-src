// presolve_chain.go —— 跨原语递归解码链求解器（2026-10-23 能力提升）
//
// 覆盖 CTF 静态题最高频类型「多层编码/加密复合链」。西湖论剑部分覆盖链的直接答案：
//   - anwang_crypto1:  八进制 ASCII → 提取 key/data → Vigenère
//   - qiangwang_classic: A/B 摩斯（A=点/B=划）→ 单表密文（UUID 含 flag）
//   - ezmult:          base64 → ROT13
// 通用机制：对文本递归应用全部解码原语（hex/octal/binary/base64/morse/AB摩斯/caesar/
// rot13/rot47/atbash/url/html/quoted-printable/key-data-vigenere），任一层出现 flag
// 形态即收集；深度 ≤ 8；层间解码必须提升可打印率，杜绝乱码误报。
package ctfplatform

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const chainMaxDepth = 8

var (
	hexBlockRe    = regexp.MustCompile(`[0-9a-fA-F]{6,}`)
	octalBlockRe  = regexp.MustCompile(`[0-7]{2,3}`)
	binaryBlockRe = regexp.MustCompile(`[01]{8}`)
	morseOnlyRe   = regexp.MustCompile(`^[\s./\-]{3,}$`)
	abMorseRe     = regexp.MustCompile(`^[\sABab]{5,}$`)
	keyDataRe     = regexp.MustCompile(`(?i)key\s*[:：=]\s*([^\s,，;；]+)\s+(?:data|ct|text|cipher|flagtxt|flag\.txt)\s*[:：=]\s*(\S+)`)
)

// tryCodingChain 顶层入口：合并题干与附件，递归解包多层编码，返回 flag 形态候选（去重）。
func tryCodingChain(text string, attachments map[string]string) []string {
	full := text
	for _, v := range attachments {
		full += "\n" + v
	}
	if strings.TrimSpace(full) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	chainCollect(full, 0, seen, &out)
	uniq := make([]string, 0, len(out))
	uSeen := map[string]bool{}
	for _, f := range out {
		if !uSeen[f] {
			uSeen[f] = true
			uniq = append(uniq, f)
		}
	}
	return uniq
}

// chainCollect 递归解包：depth 上限内逐层尝试全部原语。
func chainCollect(s string, depth int, seen map[string]bool, out *[]string) {
	if depth > chainMaxDepth || s == "" {
		return
	}
	// 1) 当前层直接扫 flag 形态。
	// ⚠️ 不做 seen 拦截：seen 是「递归防环」，而候选本身可能正是 flag（vigenere 解出的
	// 明文）——采纳时已 seen=true，若此处再查 seen 会把这条唯一正确路径挡死
	// （2026-10-23 实测：out 恒空、seen=32）。重复由顶层去重收口。
	for _, m := range xhljFlagShapeRe.FindAllString(s, -1) {
		*out = append(*out, m)
	}
	if depth == chainMaxDepth {
		return
	}
	// 2) 单层原语展开
	for _, cand := range chainDecodeOnce(s) {
		if cand.decoded == "" || cand.decoded == s || seen[cand.decoded] {
			continue
		}
		if printableRate(cand.decoded) < printableRate(s) {
			continue // 更乱码的解码不采纳，防误报
		}
		seen[cand.decoded] = true
		chainCollect(cand.decoded, depth+1, seen, out)
	}
}

type chainCandidate struct {
	name    string
	decoded string
}

// chainDecodeOnce 对输入应用全部原语，返回候选解码结果。
func chainDecodeOnce(s string) []chainCandidate {
	var out []chainCandidate
	add := func(name, dec string) {
		if dec != "" {
			out = append(out, chainCandidate{name, dec})
		}
	}

	// 按块解码 hex/octal/binary（整串须主要是该进制形态）
	if hexBlockRe.MatchString(s) && hexLikeRatio(s) > 0.8 {
		if b, err := hex.DecodeString(strings.TrimSpace(hexOnly(s))); err == nil {
			add("hex", string(b))
		}
	}
	if octalLikeRatio(s) > 0.8 {
		if b := decodeOctal(s); len(b) > 0 {
			add("octal", string(b))
		}
	}
	if binaryLikeRatio(s) > 0.8 {
		if b := decodeBinary(s); len(b) > 0 {
			add("binary", string(b))
		}
	}
	// base64（标准 + URL-safe）
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s)); err == nil {
		add("base64", string(b))
	}
	if b, err := base64.URLEncoding.DecodeString(strings.TrimSpace(s)); err == nil {
		add("base64url", string(b))
	}
	// Morse（含 A/B 变体：A=点 B=划 与 A=划 B=点 两种）
	trim := strings.TrimSpace(s)
	if morseOnlyRe.MatchString(trim) {
		if dec := chainMorseDecode(trim); dec != "" {
			add("morse", dec)
		}
	}
	if abMorseRe.MatchString(trim) {
		abA := strings.Map(func(r rune) rune {
			switch r {
			case 'a', 'A':
				return '.'
			case 'b', 'B':
				return '-'
			}
			return r
		}, trim)
		if dec := chainMorseDecode(abA); dec != "" {
			add("ab_morse_a=dot", dec)
		}
		abB := strings.Map(func(r rune) rune {
			switch r {
			case 'a', 'A':
				return '-'
			case 'b', 'B':
				return '.'
			}
			return r
		}, trim)
		if dec := chainMorseDecode(abB); dec != "" {
			add("ab_morse_a=dash", dec)
		}
	}
	// 古典字母表变换：caesar 暴力挑可读、rot13、rot47、atbash
	lower := strings.ToLower(trim)
	// caesar 靠可读性打分挑最佳移位，需要足够长字母串才可靠 → 门槛 8。
	if hasLetterRun(lower, 8) {
		best := bestCaesar(lower)
		if best != "" {
			add("caesar", best)
		}
	}
	// rot13/atbash/rot47 是确定性双射，只需“文本里真有字母”即可尝试。
	// 门槛 8 曾把短密文（如 flag{} 的 rot13，最长连续字母仅 6）整个掐死（2026-10-23 实锤），降到 4。
	if hasLetterRun(lower, 4) {
		add("rot13", rot13(lower))
		add("atbash", atbashTransform(lower))
		if hasPrintableRun(lower, 4) {
			add("rot47", rot47(lower))
		}
	}
	// key/data → Vigenère（anwang 链的落点）
	if km := keyDataRe.FindStringSubmatch(s); len(km) == 3 {
		if key := strings.ToLower(strings.Trim(km[1], "{} ")); key != "" {
			// ⚠️ data 只去空白、绝不剥 { }：密文里的花括号是有效内容
			// （曾因 Trim(km[2], "{} ") 误删尾部 '}' 导致链断，2026-10-23 实锤）。
			data := strings.TrimSpace(km[2])
			if dec := vigenereDecode(data, key); dec != "" && dec != data {
				add("vigenere_keydata", dec)
			}
		}
	}
	// URL / HTML / quoted-printable
	if strings.Contains(trim, "%") {
		if dec, err := url.QueryUnescape(trim); err == nil && dec != trim {
			add("url", dec)
		}
	}
	if strings.Contains(lower, "&#") || strings.Contains(lower, "&amp;") || strings.Contains(lower, "&lt;") {
		add("html", html.UnescapeString(trim))
	}
	if strings.Contains(lower, "=") && strings.Contains(trim, "=") && strings.Contains(trim, "?") {
		if dec := quotedPrintableDecode(trim); dec != "" {
			add("quoted_printable", dec)
		}
	}
	return out
}

// ── 原语辅助 ──

func printableRate(s string) float64 {
	if s == "" {
		return 0
	}
	ok := 0
	for _, r := range s {
		if (r >= 0x20 && r <= 0x7e) || r == '\n' || r == '\t' || r == '\r' {
			ok++
		}
	}
	return float64(ok) / float64(len([]rune(s)))
}

func hexOnly(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func hexLikeRatio(s string) float64 {
	h, n := 0, 0
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		n++
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			h++
		}
	}
	return float64(h) / float64(max(n, 1))
}

func octalLikeRatio(s string) float64 {
	o, n := 0, 0
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		n++
		if r >= '0' && r <= '7' {
			o++
		}
	}
	return float64(o) / float64(max(n, 1))
}

func binaryLikeRatio(s string) float64 {
	b, n := 0, 0
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		n++
		if r == '0' || r == '1' {
			b++
		}
	}
	return float64(b) / float64(max(n, 1))
}

// decodeOctal 八进制 ASCII 解码：连续 2-3 位八进制分组 → 字节。
func decodeOctal(s string) []byte {
	re := regexp.MustCompile(`[0-7]{2,3}`)
	var out []byte
	for _, m := range re.FindAllString(s, -1) {
		if v, err := strconv.ParseUint(m, 8, 8); err == nil {
			out = append(out, byte(v))
		}
	}
	return out
}

// decodeBinary 二进制 ASCII 解码：8 位分组 → 字节。
func decodeBinary(s string) []byte {
	re := regexp.MustCompile(`[01]{8}`)
	var out []byte
	for _, m := range re.FindAllString(s, -1) {
		if v, err := strconv.ParseUint(m, 2, 8); err == nil {
			out = append(out, byte(v))
		}
	}
	return out
}

// chainMorseDecode 摩斯解码（链式用，返回拼接串；容忍空白分隔与 /）。
func chainMorseDecode(s string) string {
	norm := strings.ReplaceAll(strings.ReplaceAll(s, "/", " "), "|", " ")
	var sb strings.Builder
	for _, tok := range strings.Fields(norm) {
		if ch, ok := morseTable[strings.ToLower(tok)]; ok {
			sb.WriteString(ch)
		} else {
			sb.WriteString("?")
		}
	}
	return sb.String()
}

func hasLetterRun(s string, n int) bool {
	run := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func hasPrintableRun(s string, n int) bool {
	run := 0
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// bestCaesar 暴力 25 移位，返回可读性最高者。
func bestCaesar(lower string) string {
	best, bestScore := "", -1.0
	for shift := 1; shift < 26; shift++ {
		var sb strings.Builder
		for _, r := range lower {
			if r >= 'a' && r <= 'z' {
				sb.WriteRune('a' + (r-'a'+rune(shift))%26)
			} else {
				sb.WriteRune(r)
			}
		}
		s := sb.String()
		if sc := englishScore(s); sc > bestScore {
			bestScore, best = sc, s
		}
	}
	return best
}

func rot13(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			sb.WriteRune('a' + (r-'a'+13)%26)
		} else if r >= 'A' && r <= 'Z' {
			sb.WriteRune('A' + (r-'A'+13)%26)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func rot47(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 0x21 && r <= 0x7e {
			sb.WriteRune(0x21 + (r-0x21+47)%94)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func atbashTransform(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune('z' - (r - 'a'))
		case r >= 'A' && r <= 'Z':
			sb.WriteRune('Z' - (r - 'A'))
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// englishScore 粗可读性打分：常见词 + 高频字母。
func englishScore(s string) float64 {
	score := 0.0
	lower := strings.ToLower(s)
	for _, w := range []string{" the ", "flag", "ctf", " and ", " you ", " is ", " of ", " key ", "this", "that"} {
		if strings.Contains(lower, w) {
			score += 1
		}
	}
	for _, r := range lower {
		switch r {
		case 'e', 't', 'a', 'o', 'i', 'n', 's', 'r':
			score += 0.1
		}
	}
	return score
}

// quotedPrintableDecode 极简 quoted-printable 解码（=XX 字节）。
func quotedPrintableDecode(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '=' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}
