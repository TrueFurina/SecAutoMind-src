// Package ctfplatform 提供确定性预解层（presolve）。
//
// 架构参考西湖论剑 core/presolve.py：在 LLM 推理之前，
// 先扇出全部确定性求解器（0 token），命中即返回候选 flag。
//
// 解题纪律：确定性优先 → LLM 兜底。presolve 命中 = 0 成本。
package ctfplatform

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// PresolveResult 表示预解结果。
type PresolveResult struct {
	Flags  []string `json:"flags"`  // 候选 flag 列表
	Engine string   `json:"engine"` // 命中的求解器名
	Solved bool     `json:"solved"` // 是否命中
	Detail string   `json:"detail"` // 详情
}

// Presolver 确定性预解层。
type Presolver struct {
	logger *zap.Logger
	cache  *presolveCache
}

// NewPresolver 创建预解层。
func NewPresolver(logger *zap.Logger) *Presolver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Presolver{logger: logger}
}

// flagRegexPresolve 匹配常见 flag 格式（presolve 包内使用，避免与 poller.go 重复声明）。
var flagRegexPresolve = regexp.MustCompile(`(?i)(?:flag|ctf|dasctf|key)\s*[=:：]?\s*\{([^}]{4,})\}`)

// scanFlags 从文本中提取 flag 候选。
func scanFlags(text string) []string {
	matches := flagRegex.FindAllString(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}

// tryBase64Multilayer 尝试多层 base64 解码，提取 flag。
func tryBase64Multilayer(text string) []string {
	// 提取疑似 base64 串（长度≥16，含 base64 字符集）
	b64Regex := regexp.MustCompile(`[A-Za-z0-9+/=]{16,}`)
	matches := b64Regex.FindAllString(text, -1)

	for _, m := range matches {
		decoded := m
		for i := 0; i < 5; i++ { // 最多 5 层
			d, err := base64.StdEncoding.DecodeString(padBase64(decoded))
			if err != nil {
				break
			}
			decoded = string(d)
			// 每层解码后：先直接扫 flag
			if flags := scanFlags(decoded); len(flags) > 0 {
				return flags
			}
			// 链式 caesar 爆破（base64 解码后可能是 caesar 密文）
			if flags := tryCaesar(decoded); len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}

func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		return s + strings.Repeat("=", 4-m)
	}
	return s
}

// tryCaesar 对文本尝试凯撒移位爆破。
func tryCaesar(text string) []string {
	for shift := 1; shift <= 25; shift++ {
		var sb strings.Builder
		for _, r := range text {
			switch {
			case r >= 'a' && r <= 'z':
				sb.WriteRune('a' + (r-'a'+rune(shift))%26)
			case r >= 'A' && r <= 'Z':
				sb.WriteRune('A' + (r-'A'+rune(shift))%26)
			default:
				sb.WriteRune(r)
			}
		}
		decoded := sb.String()
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// tryXOR 对 hex 串尝试单字节 XOR 爆破。
func tryXOR(text string) []string {
	hexRegex := regexp.MustCompile(`[0-9a-fA-F]{8,}`)
	matches := hexRegex.FindAllString(text, -1)

	for _, m := range matches {
		data, err := hex.DecodeString(m)
		if err != nil {
			continue
		}
		for k := byte(1); k < 255; k++ {
			out := make([]byte, len(data))
			for i, b := range data {
				out[i] = b ^ k
			}
			decoded := string(out)
			if flags := scanFlags(decoded); len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}

// tryHashCrack 对文本中的哈希值尝试弱口令爆破。
func tryHashCrack(text string) []string {
	// 常见弱口令
	passwords := []string{
		"password", "123456", "admin", "root", "flag", "ctf",
		"test", "guest", "secret", "qwerty", "abc123", "letmein",
		"admin123", "passw0rd", "123456789", "secautomind",
	}

	// 提取疑似哈希串
	hash32 := regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`) // MD5
	hash40 := regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`) // SHA1
	hash64 := regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`) // SHA256

	type hashPattern struct {
		regex *regexp.Regexp
		algo  string
		hash  func(string) string
	}
	patterns := []hashPattern{
		{hash32, "md5", func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }},
		{hash40, "sha1", func(s string) string { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) }},
		{hash64, "sha256", func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }},
	}

	for _, p := range patterns {
		matches := p.regex.FindAllString(text, -1)
		for _, target := range matches {
			for _, pw := range passwords {
				if p.hash(pw) == strings.ToLower(target) {
					return []string{fmt.Sprintf("hash_crack: %s = %s", target, pw)}
				}
			}
		}
	}
	return nil
}

// tryRSATemplate 对 RSA 参数模板尝试多种攻击（费马/小指数/高指数/PKCS#1）。
func tryRSATemplate(text string) []string {
	// 提取 e, n, c 参数
	eRegex := regexp.MustCompile(`(?i)e\s*=\s*(\d+)`)
	nRegex := regexp.MustCompile(`(?i)n\s*=\s*(\d+)`)
	cRegex := regexp.MustCompile(`(?i)c\s*=\s*(\d+)`)
	hintRegex := regexp.MustCompile(`(?i)hint\s*=\s*(\d+)`)

	eMatch := eRegex.FindStringSubmatch(text)
	nMatch := nRegex.FindStringSubmatch(text)
	cMatch := cRegex.FindStringSubmatch(text)
	hintMatch := hintRegex.FindStringSubmatch(text)

	if nMatch == nil {
		return nil
	}

	n, okN := new(big.Int).SetString(nMatch[1], 10)
	if !okN || n.Sign() <= 0 {
		return nil
	}

	// hint 型：hint = (e*p + e^2)^q mod n → 解 p
	if hintMatch != nil && eMatch != nil {
		hint, okH := new(big.Int).SetString(hintMatch[1], 10)
		e, okE := new(big.Int).SetString(eMatch[1], 10)
		if okH && okE {
			if result := tryPKCS1Hint(n, e, hint); result != "" {
				return []string{result}
			}
		}
	}

	if eMatch == nil || cMatch == nil {
		return nil
	}

	e, okE := new(big.Int).SetString(eMatch[1], 10)
	c, okC := new(big.Int).SetString(cMatch[1], 10)
	if !okE || !okC || e.Sign() <= 0 || c.Sign() <= 0 {
		return nil
	}

	// 小指数攻击（e=3, 5, 7）：m^e < n 时直接开 e 次方根
	if e.Cmp(big.NewInt(7)) <= 0 {
		if result := trySmallExponent(n, e, c); result != "" {
			return []string{result}
		}
	}

	// 高指数攻击（e = 2^k）：逐步开平方根
	if e.BitLen() > 4 && e.BitLen() == bitsTrailingZeros(e)+1 {
		if result := tryHighExponent(n, e, c); result != "" {
			return []string{result}
		}
	}

	// 费马分解（n 为相近素数乘积）
	if result := tryFermatFactor(n, e, c); result != "" {
		return []string{result}
	}

	return nil
}

// bitsTrailingZeros 返回 x 的二进制末尾零的个数。
func bitsTrailingZeros(x *big.Int) int {
	if x.Sign() == 0 {
		return 0
	}
	b := new(big.Int).Set(x)
	count := 0
	for b.Bit(0) == 0 {
		b.Rsh(b, 1)
		count++
	}
	return count
}

// iroot 计算 floor(n^(1/e))（整数 e 次方根，牛顿迭代）。
func iroot(n, e *big.Int) *big.Int {
	if e.Cmp(big.NewInt(1)) == 0 {
		return new(big.Int).Set(n)
	}
	if n.Sign() <= 0 {
		return big.NewInt(0)
	}
	// 初始猜测：2^(bitlen/e)
	guess := new(big.Int).Lsh(big.NewInt(1), uint(n.BitLen()/int(e.Int64())+1))
	tmp := new(big.Int)
	for i := 0; i < 1000; i++ {
		// guess^(e-1)
		tmp.Exp(guess, new(big.Int).Sub(e, big.NewInt(1)), nil)
		if tmp.Sign() == 0 {
			break
		}
		// next = ((e-1)*guess + n/guess^(e-1)) / e
		tmp2 := new(big.Int).Div(n, tmp)
		tmp.Mul(new(big.Int).Sub(e, big.NewInt(1)), guess)
		tmp.Add(tmp, tmp2)
		tmp.Div(tmp, e)
		if tmp.Cmp(guess) >= 0 {
			// 不再收敛
			break
		}
		guess.Set(tmp)
	}
	// 向下微调确保 guess^e <= n
	for {
		tmp.Exp(guess, e, nil)
		if tmp.Cmp(n) <= 0 {
			break
		}
		guess.Sub(guess, big.NewInt(1))
	}
	return guess
}

// tryPKCS1Hint hint 型：hint = (e*p + e^2)^q mod n，通过 GCD 求 p。
func tryPKCS1Hint(n, e, hint *big.Int) string {
	// hint = (e*p + e^2)^q mod n
	// GCD(hint - e^2, n) 可能泄露 p
	e2 := new(big.Int).Mul(e, e)
	diff := new(big.Int).Sub(hint, e2)
	if diff.Sign() <= 0 {
		return ""
	}
	p := new(big.Int).GCD(nil, nil, diff, n)
	if p.Cmp(big.NewInt(1)) > 0 && p.Cmp(n) < 0 {
		q := new(big.Int).Div(n, p)
		phi := new(big.Int).Mul(
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(q, big.NewInt(1)),
		)
		d := new(big.Int).ModInverse(e, phi)
		if d != nil {
			return fmt.Sprintf("PKCS#1分解: p=%s, d=%s", p.String(), d.String())
		}
	}
	return ""
}

// tryLegendrePhi Legendre 符号攻击（phi 泄露型）：已知 phi 逐位还原明文。
func tryLegendrePhi(text string) []string {
	phiRegex := regexp.MustCompile(`(?i)phi\s*=\s*(\d+)`)
	cRegex := regexp.MustCompile(`(?i)c\s*=\s*(\d+)`)
	nRegex := regexp.MustCompile(`(?i)n\s*=\s*(\d+)`)

	phiMatch := phiRegex.FindStringSubmatch(text)
	cMatch := cRegex.FindStringSubmatch(text)
	nMatch := nRegex.FindStringSubmatch(text)

	if phiMatch == nil || cMatch == nil || nMatch == nil {
		return nil
	}

	n, okN := new(big.Int).SetString(nMatch[1], 10)
	phi, okPhi := new(big.Int).SetString(phiMatch[1], 10)
	c, okC := new(big.Int).SetString(cMatch[1], 10)
	if !okN || !okPhi || !okC {
		return nil
	}

	// 从 phi 恢复 e 的逆
	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil
	}
	m := new(big.Int).Exp(c, d, n)
	mBytes := m.Bytes()
	if flags := scanFlags(string(mBytes)); len(flags) > 0 {
		return flags
	}
	return []string{fmt.Sprintf("Legendre/phi解密(hex): %s", hex.EncodeToString(mBytes))}
}

// tryModInvFactor 模逆攻击（A*p + B*q = N+1 → CRT 分解）。
func tryModInvFactor(text string) []string {
	nRegex := regexp.MustCompile(`(?i)n\s*=\s*(\d+)`)
	eRegex := regexp.MustCompile(`(?i)e\s*=\s*(\d+)`)
	cRegex := regexp.MustCompile(`(?i)c\s*=\s*(\d+)`)
	aRegex := regexp.MustCompile(`(?i)a\s*=\s*(\d+)`)
	bRegex := regexp.MustCompile(`(?i)b\s*=\s*(\d+)`)

	nMatch := nRegex.FindStringSubmatch(text)
	eMatch := eRegex.FindStringSubmatch(text)
	cMatch := cRegex.FindStringSubmatch(text)
	aMatch := aRegex.FindStringSubmatch(text)
	bMatch := bRegex.FindStringSubmatch(text)

	if nMatch == nil || eMatch == nil || cMatch == nil || aMatch == nil || bMatch == nil {
		return nil
	}

	n, okN := new(big.Int).SetString(nMatch[1], 10)
	e, okE := new(big.Int).SetString(eMatch[1], 10)
	c, okC := new(big.Int).SetString(cMatch[1], 10)
	a, okA := new(big.Int).SetString(aMatch[1], 10)
	b, okB := new(big.Int).SetString(bMatch[1], 10)
	if !okN || !okE || !okC || !okA || !okB {
		return nil
	}

	// A*p + B*q = N+1 → 二次方程求 p, q
	// (N+1 - B*q) / A = p，代入 p*q = N → 二次方程
	np1 := new(big.Int).Add(n, big.NewInt(1))
	// 判别式 Δ = (N+1)^2 - 4*A*B*N
	delta := new(big.Int).Mul(np1, np1)
	tmp := new(big.Int).Mul(a, b)
	tmp.Mul(tmp, n)
	tmp.Mul(tmp, big.NewInt(4))
	delta.Sub(delta, tmp)
	if delta.Sign() < 0 {
		return nil
	}
	sqrtDelta := new(big.Int).Sqrt(delta)
	if new(big.Int).Mul(sqrtDelta, sqrtDelta).Cmp(delta) != 0 {
		return nil
	}
	// p = ((N+1) - sqrtDelta) / (2*A)
	p := new(big.Int).Sub(np1, sqrtDelta)
	p.Div(p, new(big.Int).Mul(a, big.NewInt(2)))
	if p.Cmp(big.NewInt(1)) <= 0 || p.Cmp(n) >= 0 {
		return nil
	}
	q := new(big.Int).Div(n, p)
	if new(big.Int).Mul(p, q).Cmp(n) != 0 {
		return nil
	}
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil
	}
	m := new(big.Int).Exp(c, d, n)
	mBytes := m.Bytes()
	if flags := scanFlags(string(mBytes)); len(flags) > 0 {
		return flags
	}
	return []string{fmt.Sprintf("ModInvFactor解密(hex): %s", hex.EncodeToString(mBytes))}
}

// tryMorse 对文本尝试 Morse 解码。
func tryMorse(text string) []string {
	morseRe := regexp.MustCompile(`^[\.\-\s/]+$`)
	clean := strings.TrimSpace(text)
	if !morseRe.MatchString(clean) {
		return nil
	}
	words := strings.Split(clean, " / ")
	var decoded []string
	for _, word := range words {
		letters := strings.Split(word, " ")
		var sb strings.Builder
		for _, letter := range letters {
			letter = strings.TrimSpace(letter)
			if letter == "" {
				continue
			}
			if ch, ok := morseTable[letter]; ok {
				sb.WriteString(ch)
			} else {
				sb.WriteString("?")
			}
		}
		decoded = append(decoded, sb.String())
	}
	result := strings.Join(decoded, " ")
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 {
		return []string{fmt.Sprintf("Morse解码: %s", result)}
	}
	return nil
}

// tryVigenere 尝试维吉尼亚解码（暴力短密钥）。
func tryVigenere(text string) []string {
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	clean := strings.TrimSpace(text)
	if !alphaRe.MatchString(clean) || len(clean) < 10 {
		return nil
	}
	for keyLen := 1; keyLen <= 4; keyLen++ {
		key := guessVigenereKey(clean, keyLen)
		if key == "" {
			continue
		}
		decoded := vigenereDecode(clean, key)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// tryZIPFakeEncryption 检测 ZIP 伪加密。
func tryZIPFakeEncryption(text string) []string {
	lower := strings.ToLower(text)
	if strings.Contains(lower, "伪加密") ||
		strings.Contains(lower, "fake encryption") ||
		strings.Contains(lower, "zip encryption flag") ||
		strings.Contains(lower, "general purpose bit flag") {
		return []string{"ZIP伪加密：将加密标志位（General Purpose Bit Flag bit 0）置0即可解压"}
	}
	return nil
}

// tryWebSourceAudit 对源码/HTML/JS 进行关键词审计（flag 注释/备份/敏感路径）。
func tryWebSourceAudit(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	if flags := scanFlags(fullText); len(flags) > 0 {
		return flags
	}
	backupRe := regexp.MustCompile(`(?i)\.(bak|old|swp|save|backup|orig|~)`)
	if m := backupRe.FindString(fullText); m != "" {
		return []string{"备份文件特征: " + m}
	}
	sqlErrRe := regexp.MustCompile(`(?i)(sql syntax|sqlite|ORA-\d+|SQLSTATE)`)
	if m := sqlErrRe.FindString(fullText); m != "" {
		limit := 60
		if len(m) < limit {
			limit = len(m)
		}
		return []string{"SQL错误泄露: " + m[:limit]}
	}
	return nil
}

// trySSTI 检测模板注入特征。
func trySSTI(text string) []string {
	sstiPatterns := []struct {
		pattern string
		proof   string
	}{
		{`(?i)\{\{.*?\}\}`, "Jinja2/Twig"},
		{`(?i)\$\{.*?\}`, "FreeMarker/OGNL"},
		{`7\*7\s*=\s*49`, "SSTI算术验证"},
		{`3\*3\s*=\s*9`, "SSTI算术验证"},
	}
	for _, p := range sstiPatterns {
		re := regexp.MustCompile(p.pattern)
		if m := re.FindString(text); m != "" {
			limit := 40
			if len(m) < limit {
				limit = len(m)
			}
			return []string{"SSTI: " + m[:limit] + " (" + p.proof + ")"}
		}
	}
	return nil
}

// minInt 返回两个整数中较小的一个（Go 1.21 前兼容）。
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isPrintableRatio 返回字符串中可打印 ASCII 字符的比例（0.0~1.0）。
func isPrintableRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	printable := 0
	for _, r := range s {
		if (r >= 32 && r <= 126) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return float64(printable) / float64(len(s))
}

// egcd 扩展欧几里得算法：返回 (g, x, y) 使得 ax + by = g = gcd(a, b)。
func egcd(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if b.Sign() == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}
	g, x1, y1 := egcd(b, new(big.Int).Mod(a, b))
	q := new(big.Int).Div(a, b)
	x := new(big.Int).Sub(x1, new(big.Int).Mul(q, y1))
	return g, y1, x
}

// buildBracketMap 构建 Brainfuck 括号匹配表。
func buildBracketMap(code string) map[int]int {
	stack := []int{}
	m := make(map[int]int)
	for i, c := range code {
		if c == '[' {
			stack = append(stack, i)
		} else if c == ']' {
			if len(stack) > 0 {
				start := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				m[start] = i
				m[i] = start
			}
		}
	}
	return m
}

// binaryToASCII 将二进制字符串转换为 ASCII 文本。
func binaryToASCII(bin string) string {
	var result strings.Builder
	for i := 0; i+7 < len(bin); i += 8 {
		val := 0
		for j := 0; j < 8; j++ {
			if bin[i+j] == '1' {
				val |= 1 << (7 - j)
			}
		}
		if val >= 32 && val < 127 {
			result.WriteByte(byte(val))
		}
	}
	return result.String()
}

// ── 补全项：morse 完整解码器 ──────────────────────────────

// tryMorseComplete 完整 Morse 解码器：支持 .- 格式、·- 格式、01 二进制格式。
func tryMorseComplete(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 8 {
		return nil
	}
	// 标准 Morse 格式：仅含 . - / 空格
	stdRe := regexp.MustCompile(`^[\.\-\s/]+$`)
	if stdRe.MatchString(clean) {
		return decodeMorse(clean)
	}
	// Unicode 格式：· —（点/长划线）
	uniClean := strings.ReplaceAll(clean, "·", ".")
	uniClean = strings.ReplaceAll(uniClean, "—", "-")
	uniClean = strings.ReplaceAll(uniClean, "−", "-")
	uniClean = strings.ReplaceAll(uniClean, "–", "-")
	if stdRe.MatchString(uniClean) {
		return decodeMorse(uniClean)
	}
	// 二进制格式：1=点 0=划，空格分隔
	binRe := regexp.MustCompile(`^[01\s/]+$`)
	if binRe.MatchString(clean) && len(clean) >= 10 {
		std := strings.ReplaceAll(clean, "1", ".")
		std = strings.ReplaceAll(std, "0", "-")
		std = strings.ReplaceAll(std, " ", " ")
		return decodeMorse(std)
	}
	return nil
}

// decodeMorse 解码标准 Morse 串（空格分隔字母，/ 分隔单词）。
func decodeMorse(code string) []string {
	morseTable := map[string]string{
		".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e",
		"..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
		"-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o",
		".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
		"..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y",
		"--..": "z", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
		".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
		"-----": "0", ".-.-.-": ".", "--..--": ",", "---...": ":",
		"-.-.-.": ";", "-....-": "-", "..--.-": "_", ".----.": "'",
		".-..-.": "\"", "-.--.": "{", "-.--.-": ")", ".-...": "&",
		".--.-": "}",  // } （非标准 Morse，CTF 约定）
	}

	words := strings.Split(code, "/")
	var decoded []string
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		letters := strings.Fields(word)
		var sb strings.Builder
		for _, letter := range letters {
			letter = strings.TrimSpace(letter)
			if letter == "" {
				continue
			}
			if ch, ok := morseTable[letter]; ok {
				sb.WriteString(ch)
			} else {
				sb.WriteString("?")
			}
		}
		decoded = append(decoded, sb.String())
	}
	result := strings.Join(decoded, " ")
	// 扫描 flag
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 {
		return []string{"Morse解码: " + result}
	}
	return nil
}

// ── 补全项：弱口令字典扩充 ──────────────────────────────

// weakPasswords 扩充弱口令字典（覆盖 CTF 常见 flag/shell/密码模式）。
var weakPasswords = []string{
	// 经典弱口令
	"password", "123456", "admin", "root", "test", "guest", "master",
	"qwerty", "abc123", "letmein", "welcome", "monkey", "dragon",
	"baseball", "football", "shadow", "michael", "superman", "batman",
	// CTF 常见
	"flag", "ctf", "ctf{", "flag{", "key", "secret", "challenge",
	"secautomind", "security", "hack", "pwn", "crypto", "reverse",
	// flag 变体
	"flag{md5_hash_crack}", "flag{ctf_challenge}", "flag{weak_password}",
	"flag{hash_cracked}", "flag{rainbow_table}", "flag{dictionary_attack}",
	// 技术相关
	"password123", "admin123", "root123", "test123", "guest123",
	"changeme", "default", "temp", "backup", "debug", "development",
	// 数字
	"0", "1", "12", "123", "1234", "12345", "123456", "1234567",
	"12345678", "123456789", "1234567890",
}

// tryHashCrackExpanded 扩展版哈希爆破（更大字典 + 更多哈希类型）。
func tryHashCrackExpanded(text string) []string {
	fullText := text
	var results []string

	// MD5 (32 hex)
	md5Re := regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	for _, m := range md5Re.FindAllString(fullText, -1) {
		h := strings.ToLower(m)
		for _, pw := range weakPasswords {
			if fmt.Sprintf("%x", md5Sum(pw)) == h {
				results = append(results, "MD5爆破: "+m+" => "+pw)
			}
		}
	}

	// SHA-1 (40 hex)
	sha1Re := regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	for _, m := range sha1Re.FindAllString(fullText, -1) {
		h := strings.ToLower(m)
		for _, pw := range weakPasswords {
			if fmt.Sprintf("%x", sha1Sum(pw)) == h {
				results = append(results, "SHA1爆破: "+m+" => "+pw)
			}
		}
	}

	// SHA-256 (64 hex)
	sha256Re := regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	for _, m := range sha256Re.FindAllString(fullText, -1) {
		h := strings.ToLower(m)
		for _, pw := range weakPasswords {
			if fmt.Sprintf("%x", sha256Sum(pw)) == h {
				results = append(results, "SHA256爆破: "+m+" => "+pw)
			}
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

func md5Sum(s string) [16]byte {
	h := md5.New()
	h.Write([]byte(s))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func sha1Sum(s string) [20]byte {
	h := sha1.New()
	h.Write([]byte(s))
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

func sha256Sum(s string) [32]byte {
	h := sha256.New()
	h.Write([]byte(s))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ── 补全项：RSA 小指数分解 ──────────────────────────────

// tryRSASmallExponentComplete 完整 RSA 小指数攻击（e=3 开根 + 费马分解）。
func tryRSASmallExponentComplete(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 提取 n, e, c
	nRe := regexp.MustCompile(`(?i)\bn\s*=\s*(\d+)`)
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	cRe := regexp.MustCompile(`(?i)\bc\s*=\s*(\d+)`)

	nMatch := nRe.FindStringSubmatch(fullText)
	eMatch := eRe.FindStringSubmatch(fullText)
	cMatch := cRe.FindStringSubmatch(fullText)

	if nMatch == nil || eMatch == nil || cMatch == nil {
		return nil
	}

	n, okN := new(big.Int).SetString(nMatch[1], 10)
	e, okE := new(big.Int).SetString(eMatch[1], 10)
	c, okC := new(big.Int).SetString(cMatch[1], 10)
	if !okN || !okE || !okC {
		return nil
	}

	// 小指数攻击：e=3 时 c^(1/e) 直接开根
	if e.Cmp(big.NewInt(3)) == 0 {
		m := iroot(c, big.NewInt(3))
		if m != nil {
			mBytes := m.Bytes()
			if flags := scanFlags(string(mBytes)); len(flags) > 0 {
				return flags
			}
			return []string{"RSA小指数(e=3)解密(hex): " + hex.EncodeToString(mBytes)}
		}
	}

	// e=5 时开5次根
	if e.Cmp(big.NewInt(5)) == 0 {
		m := iroot(c, big.NewInt(5))
		if m != nil {
			mBytes := m.Bytes()
			if flags := scanFlags(string(mBytes)); len(flags) > 0 {
				return flags
			}
			return []string{"RSA小指数(e=5)解密(hex): " + hex.EncodeToString(mBytes)}
		}
	}

	// 费马分解：n = p*q 且 p≈q
	p, q := fermatFactor(n)
	if p != nil && q != nil {
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		d := new(big.Int).ModInverse(e, phi)
		if d != nil {
			m := new(big.Int).Exp(c, d, n)
			mBytes := m.Bytes()
			if flags := scanFlags(string(mBytes)); len(flags) > 0 {
				return flags
			}
			return []string{"RSA费马分解解密(hex): " + hex.EncodeToString(mBytes)}
		}
	}

	return nil
}

// fermatFactor 费马分解：对 n 找 p,q 使得 n=p*q 且 p≈q。
func fermatFactor(n *big.Int) (*big.Int, *big.Int) {
	one := big.NewInt(1)
	a := new(big.Int).Sqrt(n)
	a.Add(a, one)
	b2 := new(big.Int).Mul(a, a)
	b2.Sub(b2, n)
	b := new(big.Int).Sqrt(b2)
	for i := 0; i < 100000; i++ {
		b2.Mul(b, b)
		if b2.Cmp(new(big.Int).Mul(a, a)) == 0 || new(big.Int).Mul(b, b).Cmp(new(big.Int).Sub(new(big.Int).Mul(a, a), n)) == 0 {
			// 检查 a-b 和 a+b
			p := new(big.Int).Sub(a, b)
			q := new(big.Int).Add(a, b)
			if new(big.Int).Mul(p, q).Cmp(n) == 0 {
				return p, q
			}
		}
		a.Add(a, one)
		b2.Mul(a, a)
		b2.Sub(b2, n)
		b.Sqrt(b2)
		if new(big.Int).Mul(b, b).Cmp(b2) != 0 {
			continue
		}
	}
	return nil, nil
}

// ── 注册新求解器 ──────────────────────────────────────

func init() {
	// 覆盖原有 morse 注册（用更完整的版本）
	RegisterSolver(SolverEntry{Name: "morse_complete", Category: CategoryMiscS, Priority: 60, Solver: solveMorseComplete})
	// 覆盖原有 hash_crack 注册（用更大字典版本）
	RegisterSolver(SolverEntry{Name: "hash_crack_expanded", Category: CategoryCryptoS, Priority: 32, Solver: solveHashCrackExpanded})
	// 覆盖原有 rsa_fermat 注册（用更完整版本）
	RegisterSolver(SolverEntry{Name: "rsa_small_exp_complete", Category: CategoryCryptoS, Priority: 40, Solver: solveRSASmallExpComplete})
}

func solveMorseComplete(ctx context.Context, text string, attachments map[string]string) []string {
	return tryMorseComplete(text)
}

func solveHashCrackExpanded(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHashCrackExpanded(text)
}

func solveRSASmallExpComplete(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRSASmallExponentComplete(text, attachments)
}
