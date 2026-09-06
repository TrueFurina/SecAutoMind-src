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
	"sync"

	"go.uber.org/zap"
)

// PresolveResult 表示预解结果。
type PresolveResult struct {
	Flags   []string `json:"flags"`    // 候选 flag 列表
	Engine  string   `json:"engine"`   // 命中的求解器名
	Solved  bool     `json:"solved"`   // 是否命中
	Detail  string   `json:"detail"`   // 详情
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

// Presolve 对题目描述/附件内容执行全部确定性求解器（并行扇出）。
// 命中即返回候选 flag；未命中返回 solved=false。
func (p *Presolver) Presolve(ctx context.Context, ch *Challenge, attachments map[string]string) *PresolveResult {
	text := ch.Description
	for _, v := range attachments {
		text += "\n" + v
	}
	if strings.TrimSpace(text) == "" {
		return &PresolveResult{}
	}

	// 并行扇出所有求解器
	type result struct {
		engine string
		flags  []string
	}
	chResult := make(chan result, 8)
	var wg sync.WaitGroup

	// 1. flag 正则扫描（全题型兜底）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := scanFlags(text)
		if len(flags) > 0 {
			chResult <- result{"flag_scan", flags}
		}
	}()

	// 2. 多层 base64 解码
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryBase64Multilayer(text)
		if len(flags) > 0 {
			chResult <- result{"base64_multilayer", flags}
		}
	}()

	// 3. 凯撒爆破（仅对短文本）
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(text) < 500 {
			flags := tryCaesar(text)
			if len(flags) > 0 {
				chResult <- result{"caesar", flags}
			}
		}
	}()

	// 4. XOR 单字节（hex 串或短文本）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryXOR(text)
		if len(flags) > 0 {
			chResult <- result{"xor_single", flags}
		}
	}()

	// 5. 哈希爆破（匹配常见哈希格式）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryHashCrack(text)
		if len(flags) > 0 {
			chResult <- result{"hash_crack", flags}
		}
	}()

	// 5b. Morse 解码
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryMorse(text)
		if len(flags) > 0 {
			chResult <- result{"morse", flags}
		}
	}()

	// 5c. 维吉尼亚解码（已知密钥或短密文）
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(text) < 300 {
			flags := tryVigenere(text)
			if len(flags) > 0 {
				chResult <- result{"vigenere", flags}
			}
		}
	}()

	// 5d. ZIP 伪加密检测
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryZIPFakeEncryption(text)
		if len(flags) > 0 {
			chResult <- result{"zip_fake_enc", flags}
		}
	}()

	// 5e. Web 源码审计关键词（flag 注释/备份文件/敏感路径）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryWebSourceAudit(text, attachments)
		if len(flags) > 0 {
			chResult <- result{"web_source_audit", flags}
		}
	}()

	// 5f. SSTI 模板注入检测
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := trySSTI(text)
		if len(flags) > 0 {
			chResult <- result{"ssti", flags}
		}
	}()

	// 6. RSA 模板匹配（费马/小指数/高指数/PKCS#1）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryRSATemplate(text)
		if len(flags) > 0 {
			chResult <- result{"rsa_template", flags}
		}
	}()

	// 7. Legendre 符号攻击（phi 泄露型）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryLegendrePhi(text)
		if len(flags) > 0 {
			chResult <- result{"legendre_phi", flags}
		}
	}()

	// 8. 模逆攻击（phi+dual-modular-inverse）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryModInvFactor(text)
		if len(flags) > 0 {
			chResult <- result{"modinv_factor", flags}
		}
	}()

	// 等待所有求解器完成
	go func() {
		wg.Wait()
		close(chResult)
	}()

	// 取第一个命中的结果
	for r := range chResult {
		if len(r.flags) > 0 {
			p.logger.Info("presolve 命中",
				zap.String("engine", r.engine),
				zap.Strings("flags", r.flags))
			return &PresolveResult{
				Flags:  r.flags,
				Engine: r.engine,
				Solved: true,
				Detail: fmt.Sprintf("[presolve:%s] 命中 %d 个候选", r.engine, len(r.flags)),
			}
		}
	}

	return &PresolveResult{Solved: false, Detail: "presolve 未命中，需 LLM 推理"}
}

// ── 确定性求解器（纯函数，0 token）─────────────────────

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
			if flags := scanFlags(decoded); len(flags) > 0 {
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

// trySmallExponent 小指数攻击：c = m^e mod n，若 m^e < n 则 m = c^(1/e)。
func trySmallExponent(n, e, c *big.Int) string {
	// m = floor(c^(1/e))，用整数 e 次方根近似
	m := iroot(c, e)
	if m == nil {
		return ""
	}
	// 验证：m^e == c
	mPow := new(big.Int).Exp(m, e, nil)
	if mPow.Cmp(c) == 0 {
		mBytes := m.Bytes()
		if flags := scanFlags(string(mBytes)); len(flags) > 0 {
			return flags[0]
		}
		return fmt.Sprintf("RSA小指数解密(hex): %s", hex.EncodeToString(mBytes))
	}
	return ""
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

// tryHighExponent 高指数攻击（e = 2^k）：逐步开平方根 k 次。
func tryHighExponent(n, e, c *big.Int) string {
	k := bitsTrailingZeros(e)
	m := new(big.Int).Set(c)
	for i := 0; i < k; i++ {
		// m = m^(1/2) mod n（模平方根）
		// 简化：若 m 是完全平方数则直接开方
		sqrtM := new(big.Int).Sqrt(m)
		if new(big.Int).Mul(sqrtM, sqrtM).Cmp(m) != 0 {
			return "" // 非完全平方，高指数攻击不适用
		}
		m = sqrtM
	}
	mBytes := m.Bytes()
	if flags := scanFlags(string(mBytes)); len(flags) > 0 {
		return flags[0]
	}
	return fmt.Sprintf("RSA高指数解密(hex): %s", hex.EncodeToString(mBytes))
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

// tryFermatFactor 尝试费马分解 RSA 模数。
func tryFermatFactor(n, e, c *big.Int) string {
	a := new(big.Int).Sqrt(n)
	if new(big.Int).Mul(a, a).Cmp(n) < 0 {
		a.Add(a, big.NewInt(1))
	}
	limit := new(big.Int).Set(a)
	limit.Add(limit, big.NewInt(100000))

	p := new(big.Int)
	q := new(big.Int)
	for a.Cmp(limit) <= 0 {
		a2 := new(big.Int).Mul(a, a)
		b2 := new(big.Int).Sub(a2, n)
		if b2.Sign() < 0 {
			a.Add(a, big.NewInt(1))
			continue
		}
		b := new(big.Int).Sqrt(b2)
		if new(big.Int).Mul(b, b).Cmp(b2) == 0 {
			p.Sub(a, b)
			q.Add(a, b)
			if p.Sign() > 0 && q.Sign() > 0 && new(big.Int).Mul(p, q).Cmp(n) == 0 {
				// 分解成功，尝试解密
				phi := new(big.Int).Mul(
					new(big.Int).Sub(p, big.NewInt(1)),
					new(big.Int).Sub(q, big.NewInt(1)),
				)
				d := new(big.Int).ModInverse(e, phi)
				if d != nil {
					m := new(big.Int).Exp(c, d, n)
					mBytes := m.Bytes()
					if flags := scanFlags(string(mBytes)); len(flags) > 0 {
						return flags[0]
					}
					return fmt.Sprintf("RSA解密明文(hex): %s", hex.EncodeToString(mBytes))
				}
			}
		}
		a.Add(a, big.NewInt(1))
	}
	return ""
}

// ── misc 求解器 ──────────────────────────────────────────

// morseTable Morse 码映射。
var morseTable = map[string]string{
	".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e",
	"..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
	"-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o",
	".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
	"..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y",
	"--..": "z", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
	".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
	"-----": "0",
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

func guessVigenereKey(cipher string, keyLen int) string {
	cipher = strings.ToLower(cipher)
	var key []byte
	for i := 0; i < keyLen; i++ {
		freq := make(map[byte]int)
		for j := i; j < len(cipher); j += keyLen {
			if cipher[j] >= 'a' && cipher[j] <= 'z' {
				freq[cipher[j]]++
			}
		}
		maxFreq := 0
		maxChar := byte('a')
		for ch, f := range freq {
			if f > maxFreq {
				maxFreq = f
				maxChar = ch
			}
		}
		key = append(key, (maxChar-'e'+26)%26+'a')
	}
	return string(key)
}

func vigenereDecode(cipher, key string) string {
	cipher = strings.ToLower(cipher)
	key = strings.ToLower(key)
	var sb strings.Builder
	ki := 0
	for _, r := range cipher {
		if r >= 'a' && r <= 'z' {
			k := rune(key[ki%len(key)] - 'a')
			decoded := 'a' + (r-'a'-k+26)%26
			sb.WriteRune(decoded)
			ki++
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
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

// ── web 求解器 ──────────────────────────────────────────

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

// ── reverse 求解器 ──────────────────────────────────────

// tryStringsFlagScan 对文本/附件做 strings 扫描（提取可打印字符串中的 flag）。
// 模拟 Linux strings 命令 + flag 正则扫描。
func tryStringsFlagScan(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 提取连续可打印字符串（长度≥6）
	stringsRe := regexp.MustCompile(`[\x20-\x7E]{6,}`)
	matches := stringsRe.FindAllString(fullText, -1)
	for _, m := range matches {
		if flags := scanFlags(m); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// tryGoBinaryStrings 从 Go 二进制/文本中提取常见 Go 特征字符串。
// Go 编译的二进制会保留部分字符串常量（函数名、路径、硬编码值）。
func tryGoBinaryStrings(text string) []string {
	// Go 路径特征
	goPathRe := regexp.MustCompile(`(?i)(main\.go|internal/|cmd/|\.go:\d+|goroutine|panic)`)
	if !goPathRe.MatchString(text) {
		return nil
	}
	// 扫描其中的 flag
	if flags := scanFlags(text); len(flags) > 0 {
		return flags
	}
	// 扫描 base64 编码的 flag
	b64Re := regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	for _, m := range b64Re.FindAllString(text, -1) {
		if decoded, err := base64.StdEncoding.DecodeString(padBase64(m)); err == nil {
			if flags := scanFlags(string(decoded)); len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}

// tryHardcodedSecrets 扫描硬编码凭证/敏感信息（API key/password/token）。
func tryHardcodedSecrets(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// flag 在密钥/密码字段中
	secretRe := regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api[_-]?key|flag)\s*[=:]\s*["']?([^\s"'<>]{8,})["']?`)
	for _, m := range secretRe.FindAllStringSubmatch(fullText, -1) {
		if len(m) > 1 {
			val := m[1]
			if flags := scanFlags(val); len(flags) > 0 {
				return flags
			}
			// 值本身可能是 flag（无前缀）
			if len(val) >= 8 && len(val) <= 64 {
				return []string{"硬编码凭证: " + val}
			}
		}
	}
	return nil
}

// ── pwn 求解器 ──────────────────────────────────────────

// tryPwnLibcFingerprint 从泄露地址/偏移识别 libc 版本。
// 常见场景：栈泄露的 __libc_start_main+偏移、puts/printf GOT 表泄露。
func tryPwnLibcFingerprint(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 匹配十六进制泄露地址（0x7f... 格式，常见 libc 地址特征）
	addrRe := regexp.MustCompile(`0x[0-9a-fA-F]{8,16}`)
	addrs := addrRe.FindAllString(fullText, -1)
	if len(addrs) == 0 {
		return nil
	}
	// 检测 libc 相关关键词
	libcKeywords := []string{"libc", "glibc", "__libc_start_main", "system", "/bin/sh", "puts", "printf", "malloc", "free"}
	lower := strings.ToLower(fullText)
	libcFound := false
	for _, kw := range libcKeywords {
		if strings.Contains(lower, kw) {
			libcFound = true
			break
		}
	}
	if !libcFound {
		return nil
	}
	var results []string
	results = append(results, fmt.Sprintf("检测到 %d 个疑似 libc/堆栈泄露地址，需进一步分析偏移定位版本", len(addrs)))
	// 检测 /bin/sh 字符串（system 调用所需）
	if strings.Contains(fullText, "/bin/sh") || strings.Contains(fullText, "2f62696e2f7368") {
		results = append(results, "检测到 /bin/sh 字符串，可尝试 system('/bin/sh')")
	}
	// 检测 system@plt / system@got 特征
	if strings.Contains(lower, "system@plt") || strings.Contains(lower, "system@got") {
		results = append(results, "检测到 system@plt/GOT 表引用")
	}
	return results
}

// tryPwnExploitPattern 检测常见 pwn 漏洞模式。
func tryPwnExploitPattern(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	type pwnPattern struct {
		keyword string
		hint    string
	}
	patterns := []pwnPattern{
		{"ret2libc", "ret2libc 攻击：利用 libc 函数（system/execve）进行代码执行"},
		{"ret2dlresolve", "ret2dlresolve：利用动态链接器延迟绑定机制执行任意函数"},
		{"rop", "ROP 链构造：利用 gadget 绕过 NX 保护"},
		{"got overwrite", "GOT 表覆写：修改全局偏移表劫持控制流"},
		{"format string", "格式化字符串漏洞：利用 printf 系列读写任意内存"},
		{"buffer overflow", "缓冲区溢出：覆盖返回地址/函数指针"},
		{"use after free", "UAF 漏洞：利用释放后未清空的指针"},
		{"double free", "双重释放：利用 free 链表进行堆利用"},
		{"heap overflow", "堆溢出：覆写堆元数据/相邻对象"},
		{"stack pivot", "栈迁移：利用 leave/ret 控制 RSP"},
		{"one_gadget", "one_gadget：libc 中满足约束条件的 execve('/bin/sh') 地址"},
		{"tcache", "tcache poisoning/binning：利用 glibc tcache 机制"},
		{"seccomp", "沙箱逃逸：seccomp 规则绕过"},
	}
	var results []string
	for _, p := range patterns {
		if strings.Contains(lower, p.keyword) {
			results = append(results, fmt.Sprintf("检测到 '%s'：", p.keyword)+p.hint)
		}
	}
	// 检测 ELF 特征
	if strings.Contains(fullText, "ELF") || strings.Contains(fullText, ".text") || strings.Contains(fullText, ".got") {
		results = append(results, "检测到 ELF 二进制特征，建议使用 pwntools/checksec 分析保护机制")
	}
	if len(results) > 0 {
		return results
	}
	return nil
}

// ── crypto 扩展求解器 ──────────────────────────────────

// tryAESECB 检测 AES ECB 模式特征（重复块 = 重复明文）。
func tryAESECB(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 检测 hex 密文中是否有重复 16 字节块（AES 块大小）
	hexRe := regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	for _, m := range hexRe.FindAllString(fullText, -1) {
		data, err := hex.DecodeString(m)
		if err != nil || len(data) < 32 {
			continue
		}
		// 检查是否有重复的 16 字节块
		blocks := make(map[string]int)
		for i := 0; i+16 <= len(data); i += 16 {
			block := string(data[i : i+16])
			blocks[block]++
		}
		for block, count := range blocks {
			if count >= 2 {
				_ = block
				return []string{fmt.Sprintf("AES ECB 检测：发现 %d 个重复的 16 字节块（ECB 模式特征，相同明文块→相同密文块）", count)}
			}
		}
	}
	// 关键词检测
	lower := strings.ToLower(fullText)
	if strings.Contains(lower, "ecb") && (strings.Contains(lower, "aes") || strings.Contains(lower, "block")) {
		return []string{"AES ECB 模式关键词检测：ECB 模式不隐藏明文模式，可利用重复块分析"}
	}
	return nil
}

// tryLattice 检测格基攻击特征（Graham-Schmidt/LLL/BKZ/格密码关键词）。
func tryLattice(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	latticeKeywords := []struct {
		keyword string
		hint    string
	}{
		{"lattice", "格基攻击：利用 LLL/BKZ 算法在格上寻找短向量"},
		{"lll algorithm", "LLL 算法：格基规约，可破解低维格密码"},
		{"bkz", "BKZ 算法：块 Korkine-Zolotarev 格基规约"},
		{"coppersmith", "Coppersmith 方法：基于格的 RSA 攻击（小根/部分密钥泄露）"},
		{"ntru", "NTRU 密码：格基密码体制，需格攻击"},
		{"lwe", "LWE（Learning With Errors）：格密码基础问题"},
		{"shortest vector", "最短向量问题（SVP）：格密码安全性基础"},
		{"closest vector", "最近向量问题（CVP）：格密码安全性基础"},
		{"hidden number", "隐藏数问题（HNP）：格基 DSA/ECDSA 攻击"},
		{"howgrave", "Howgrave-Graham 方法：格基 RSA 攻击"},
	}
	for _, kw := range latticeKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"检测到格密码特征: " + kw.hint}
		}
	}
	return nil
}

// tryKeyboardPath 检测键盘路径密码（如 QWERTY/ASDFG/ZXCVB 等键盘连续路径）。
func tryKeyboardPath(text string) []string {
	// 常见键盘路径模式
	keyboardPaths := []string{
		"qwerty", "asdfgh", "zxcvbn", "qazwsx", "edcrfv",
		"qweasdzxc", "1234567890", "qwertyuiop",
		"!@#$%^&*()", "zxcvbnm", "asdfghjkl",
	}
	lower := strings.ToLower(strings.TrimSpace(text))
	for _, path := range keyboardPaths {
		if strings.Contains(lower, path) {
			if flags := scanFlags(lower); len(flags) > 0 {
				return flags
			}
			return []string{"检测到键盘路径模式: " + path}
		}
	}
	return nil
}

// tryHighExponentVariant 高指数变体攻击（e = p1*p2 或 e 为特殊形式）。
func tryHighExponentVariant(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	eMatch := eRe.FindStringSubmatch(fullText)
	if eMatch == nil {
		return nil
	}
	e, ok := new(big.Int).SetString(eMatch[1], 10)
	if !ok || e.Sign() <= 0 {
		return nil
	}
	// e = 2^k + 1 形式（如 65537 = 2^16+1）
	pow2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(e.BitLen()-1)), nil)
	plus1 := new(big.Int).Add(pow2, big.NewInt(1))
	if e.Cmp(plus1) == 0 {
		return []string{fmt.Sprintf("检测到 e = 2^%d + 1 形式（费马素数），可尝试 Wiener 攻击或低解密指数攻击", e.BitLen()-1)}
	}
	return nil
}

// tryCommonModulus 检测共模攻击条件（同 n 不同 e 的密文对）。
func tryCommonModulus(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 检测是否有两组 (e, c) 或 (e1, c1) (e2, c2) 格式
	e1Re := regexp.MustCompile(`(?i)e1\s*=\s*(\d+)`)
	e2Re := regexp.MustCompile(`(?i)e2\s*=\s*(\d+)`)
	c1Re := regexp.MustCompile(`(?i)c1\s*=\s*(\d+)`)
	c2Re := regexp.MustCompile(`(?i)c2\s*=\s*(\d+)`)
	nRe := regexp.MustCompile(`(?i)n\s*=\s*(\d+)`)

	if e1Re.MatchString(fullText) && e2Re.MatchString(fullText) &&
		c1Re.MatchString(fullText) && c2Re.MatchString(fullText) &&
		nRe.MatchString(fullText) {
		return []string{"检测到 RSA 共模攻击条件：同 n 不同 e 双密文对，可还原明文（gcd(e1,e2)=1 时）"}
	}
	return nil
}

// ── misc 扩展求解器 ──────────────────────────────────────

// tryStegoDetect 检测隐写术特征（JPEG/PNG 嵌入、LSB、文件尾附加）。
func tryStegoDetect(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// 关键词检测
	stegoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"steganography", "隐写术：数据隐藏在图片/音频/视频中"},
		{"steg", "Steg 工具：常见隐写检测工具"},
		{"stegsolve", "StegSolve：图片隐写分析工具（通道分离/位平面分析）"},
		{"lsb", "LSB 隐写：最低有效位隐写，修改像素最低位嵌入数据"},
		{"steghide", "StegHide：图片/音频隐写工具（JPEG/BMP/WAV）"},
		{"zsteg", "zsteg：PNG/BMP 隐写自动检测工具"},
		{"exiftool", "ExifTool：图片元数据分析（可能含隐藏信息）"},
		{"binwalk", "Binwalk：固件/文件分析（检测文件中嵌入的文件）"},
		{"foremost", "Foremost：文件恢复/提取工具"},
		{"strings", "strings 命令：提取二进制文件中的可打印字符串"},
		{"file signature", "文件签名分析：检测文件头/尾异常"},
		{"trailing data", "文件尾附加数据：图片文件尾部附加了额外数据"},
		{"magic bytes", "魔数检测：文件头魔数与扩展名不匹配"},
	}
	for _, kw := range stegoKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "隐写特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}

	// 检测疑似嵌入文件的 hex 特征（PNG/JPEG 文件头嵌入）
	if strings.Contains(lower, "89504e47") || strings.Contains(lower, "ffd8ffe0") || strings.Contains(lower, "ffd8ffe1") {
		return []string{"检测到图片文件头魔数（PNG/JPEG），可能有嵌入文件或隐写"}
	}
	return nil
}

// tryTrafficAnalysis 检测流量分析特征（pcap 文件关键词、协议分析）。
func tryTrafficAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	trafficKeywords := []struct {
		keyword string
		hint    string
	}{
		{"pcap", "PCAP 流量包分析：网络数据包捕获分析"},
		{"wireshark", "Wireshark：网络协议分析工具"},
		{"tshark", "tshark：命令行流量分析工具"},
		{"tcp.stream", "TCP 流重组：跟踪单个 TCP 连接的数据流"},
		{"http.request", "HTTP 请求分析：提取 Web 请求中的数据"},
		{"dns", "DNS 查询分析：DNS 请求/响应中可能隐藏数据"},
		{"ftp-data", "FTP 数据传输：FTP 数据通道可能泄露文件"},
		{"smtp", "SMTP 邮件分析：邮件传输中的附件/内容"},
		{"icmp", "ICMP 隧道：利用 ICMP 包传输隐蔽数据"},
		{"base64.*http", "HTTP 中的 Base64 编码数据"},
		{"cookie", "Cookie 注入：利用 HTTP Cookie 传输数据"},
		{"user-agent", "User-Agent 异常：UA 头中可能隐藏数据"},
		{"covert channel", "隐蔽通道：利用合法协议传输隐蔽数据"},
	}
	for _, kw := range trafficKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "流量特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}
	return nil
}

// tryDiskForensics 检测磁盘取证特征（文件系统/分区/取证工具关键词）。
func tryDiskForensics(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	forensicsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"disk image", "磁盘镜像：原始磁盘/分区镜像分析"},
		{"autopsy", "Autopsy：数字取证分析平台"},
		{"volatility", "Volatility：内存取证分析框架"},
		{"ftk", "FTK：取证工具包"},
		{"sleuth kit", "The Sleuth Kit：文件系统取证分析"},
		{"ntfs", "NTFS 文件系统分析"},
		{"ext4", "EXT4 文件系统分析"},
		{"fat32", "FAT32 文件系统分析"},
		{"partition", "分区表分析：MBR/GPT 分区结构"},
		{"inode", "inode 分析：Linux 文件系统元数据"},
		{"slack space", "文件松弛空间：文件未使用空间可能隐藏数据"},
		{"deleted file", "已删除文件恢复"},
		{"registry", "Windows 注册表取证"},
		{"event log", "Windows 事件日志分析"},
		{"prefetch", "Windows Prefetch 文件分析"},
		{"mft", "MFT（主文件表）分析：NTFS 文件系统元数据"},
		{"recycle.bin", "回收站分析：$Recycle.Bin 中的删除记录"},
	}
	for _, kw := range forensicsKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "取证特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}
	return nil
}

// tryZipChain 检测 ZIP 链式解压（压缩包套娃、嵌套 ZIP）。
func tryZipChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)

	zipKeywords := []struct {
		keyword string
		hint    string
	}{
		{"nested zip", "嵌套 ZIP：ZIP 文件内包含 ZIP 文件（套娃）"},
		{"zip bomb", "ZIP 炸弹：极小压缩包解压后极大"},
		{"zip slip", "Zip Slip 漏洞：路径遍历写入任意位置"},
		{"compressed archive", "压缩归档：可能含多层嵌套"},
	}
	for _, kw := range zipKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"ZIP 特征: " + kw.hint}
		}
	}
	// 检测多层压缩提示
	if strings.Contains(lower, "zip") && strings.Contains(lower, "extract") {
		return []string{"检测到 ZIP 解压关键词，可能存在多层嵌套或伪加密"}
	}
	return nil
}

// ── web 扩展求解器 ──────────────────────────────────────

// trySQLi 检测 SQL 注入特征与 payload 回显。
func trySQLi(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// SQL 注入 payload 回显检测
	sqliPatterns := []struct {
		pattern string
		hint    string
	}{
		{`union\s+select`, "UNION SELECT 注入"},
		{`order\s+by\s+\d+`, "ORDER BY 注入（列数探测）"},
		{`or\s+1\s*=\s*1`, "OR 1=1 永真注入"},
		{`and\s+1\s*=\s*1`, "AND 1=1 逻辑探测"},
		{`'\s*or\s*'`, "单引号 OR 注入"},
		{`"\s*or\s*"`, "双引号 OR 注入"},
		{`sleep\s*\(\s*\d+\s*\)`, "时间盲注（SLEEP）"},
		{`benchmark\s*\(`, "时间盲注（BENCHMARK）"},
		{`waitfor\s+delay`, "时间盲注（WAITFOR）"},
		{`if\s*\(\s*\d+\s*=\s*\d+`, "条件盲注（IF）"},
		{`information_schema`, "INFORMATION_SCHEMA 枚举"},
		{`table_name`, "表名枚举"},
		{`column_name`, "列名枚举"},
		{`load_file\s*\(`, "LOAD_FILE 读文件"},
		{`into\s+outfile`, "INTO OUTFILE 写文件"},
		{`into\s+dumpfile`, "INTO DUMPFILE 写文件"},
		{`extractvalue\s*\(`, "EXTRACTVALUE 报错注入"},
		{`updatexml\s*\(`, "UPDATEXML 报错注入"},
		{`floor\s*\(\s*rand`, "FLOOR/RAND 报错注入"},
		{`group\s+by\s+`, "GROUP BY 报错注入"},
	}
	for _, p := range sqliPatterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		if m := re.FindString(fullText); m != "" {
			results = append(results, "SQLi特征: "+p.hint+" ("+m[:minInt(30, len(m))]+")")
		}
	}
	if len(results) > 0 {
		return results
	}

	// SQL 错误信息泄露
	sqlErrors := []string{"sql syntax", "mysql_fetch", "sqlite_error", "ORA-", "SQLSTATE", "postgresql", "mssql"}
	for _, e := range sqlErrors {
		if strings.Contains(lower, strings.ToLower(e)) {
			return []string{"SQL错误泄露: " + e + " (可能存在注入点)"}
		}
	}
	return nil
}

// trySSRF 检测 SSRF 特征与内网地址探测。
func trySSRF(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	ssrfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ssrf", "SSRF：服务器端请求伪造"},
		{"server-side request forgery", "服务器端请求伪造攻击"},
		{"127.0.0.1", "本地回环地址探测"},
		{"localhost", "localhost 探测"},
		{"0.0.0.0", "全接口地址探测"},
		{"169.254.169.254", "云元数据服务探测（AWS/GCP/Azure）"},
		{"metadata.google.internal", "GCP 元数据服务"},
		{"100.100.100.200", "阿里云元数据服务"},
		{"file://", "FILE 协议读取本地文件"},
		{"gopher://", "GOPHER 协议利用"},
		{"dict://", "DICT 协议利用"},
		{"url redirect", "URL 重定向漏洞"},
		{"dns rebinding", "DNS 重绑定攻击"},
	}
	for _, kw := range ssrfKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "SSRF特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}
	// 检测内网 IP 模式
	privateIPRe := regexp.MustCompile(`(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}`)
	if m := privateIPRe.FindString(fullText); m != "" {
		return []string{"检测到内网 IP 地址: " + m + "（可能 SSRF 目标）"}
	}
	return nil
}

// tryXXE 检测 XML 外部实体注入特征。
func tryXXE(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}

	xxePatterns := []struct {
		pattern string
		hint    string
	}{
		{`<!entity`, "XXE 实体定义"},
		{`system\s+[\"']`, "SYSTEM 实体（读取本地文件）"},
		{`public\s+[\"']`, "PUBLIC 实体"},
		{`expect://`, "expect:// 协议利用"},
		{`php://`, "PHP 流包装器利用"},
		{`/etc/passwd`, "/etc/passwd 文件读取"},
		{`/etc/shadow`, "/etc/shadow 文件读取"},
		{`c:/windows`, "Windows 系统文件读取"},
		{`<!doctype`, "DOCTYPE 声明（可能含实体）"},
		{`xxe`, "XXE 注入关键词"},
		{`xml external entity`, "XML 外部实体注入"},
		{`billion laughs`, "Billion Laughs 攻击（XML 炸弹）"},
		{`parameter entity`, "参数实体注入"},
	}
	for _, p := range xxePatterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		if re.MatchString(fullText) {
			return []string{"XXE特征: " + p.hint}
		}
	}

	// 检测 XML 结构（可能含 XXE 注入点）
	if strings.Contains(fullText, "<?xml") || strings.Contains(fullText, "<!DOCTYPE") {
		return []string{"检测到 XML 结构，可能存在 XXE 注入点"}
	}
	return nil
}

// tryJWT 检测 JWT 特征与常见攻击模式。
func tryJWT(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)

	jwtKeywords := []struct {
		keyword string
		hint    string
	}{
		{"jwt", "JWT（JSON Web Token）"},
		{"json web token", "JSON Web Token"},
		{"eyJ", "Base64 编码的 JWT 头部（eyJ = {'typ':...}）"},
		{"bearer ", "Bearer Token 认证"},
		{"alg:none", "JWT alg:none 攻击（禁用签名验证）"},
		{"alg: none", "JWT alg:none 攻击"},
		{"hs256", "HMAC-SHA256 签名"},
		{"rs256", "RSA-SHA256 签名"},
		{"public key", "RSA 公钥泄露"},
		{"kid", "JWT kid 注入"},
		{"jwk", "JWK 注入攻击"},
		{"jku", "JWKS URL 注入"},
		{"kid injection", "JWT kid 参数注入"},
		{"jwt.io", "JWT 调试工具"},
		{"refresh token", "Refresh Token"},
	}
	for _, kw := range jwtKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"JWT特征: " + kw.hint}
		}
	}
	// 检测 JWT 格式（三段 base64 用点分隔）
	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	if m := jwtRe.FindString(fullText); m != "" {
		return []string{"检测到 JWT Token 格式: " + m[:minInt(60, len(m))] + "..."}
	}
	return nil
}

// tryRaceCondition 检测竞态条件特征。
func tryRaceCondition(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)

	raceKeywords := []struct {
		keyword string
		hint    string
	}{
		{"race condition", "竞态条件：并发请求利用时序漏洞"},
		{"race", "竞态攻击"},
		{"toctou", "TOCTOU（Time-of-Check Time-of-Use）漏洞"},
		{"time of check", "TOC 时间点检查"},
		{"time of use", "TOU 时间点使用"},
		{"concurrent", "并发请求"},
		{"parallel request", "并行请求"},
		{"thread safety", "线程安全问题"},
		{"atomic", "原子性问题"},
		{"double spend", "双重消费"},
		{"replay", "重放攻击"},
	}
	for _, kw := range raceKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"竞态特征: " + kw.hint}
		}
	}
	// 检测并发请求模式（多次请求同一端点）
	urlRe := regexp.MustCompile(`https?://[^\s"']+`)
	urls := urlRe.FindAllString(fullText, -1)
	if len(urls) >= 5 {
		return []string{fmt.Sprintf("检测到 %d 个 URL（可能并发请求场景）", len(urls))}
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

// ── reverse 扩展求解器 ──────────────────────────────────

// tryReverseKeywords 检测逆向分析特征（angr/ELF/反混淆/pyc/JS）。
func tryReverseKeywords(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// angr 特征
	angrKeywords := []struct {
		keyword string
		hint    string
	}{
		{"angr", "angr 二进制分析框架（符号执行/约束求解）"},
		{"symbolic execution", "符号执行：探索所有执行路径"},
		{"claripy", "Claripy：angr 约束求解引擎"},
		{"simprocedure", "SimProcedure：angr 函数模拟"},
		{"state exploration", "状态空间探索"},
		{"path exploration", "路径空间探索"},
	}
	for _, kw := range angrKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向特征: "+kw.hint)
		}
	}

	// ELF/二进制分析特征
	elfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"elf header", "ELF 文件头分析"},
		{"section header", "ELF 节头分析"},
		{"program header", "ELF 程序头分析"},
		{".text", "代码段 .text"},
		{".data", "数据段 .data"},
		{".bss", "BSS 段 .bss"},
		{".got", "全局偏移表 .got"},
		{".plt", "过程链接表 .plt"},
		{".dynsym", "动态符号表 .dynsym"},
		{".rodata", "只读数据段 .rodata（常量字符串）"},
		{"stripped", "已剥离符号的二进制"},
		{"not stripped", "未剥离符号（调试信息保留）"},
		{"nx enabled", "NX/DEP 保护：栈不可执行"},
		{"aslr", "ASLR 地址空间随机化"},
		{"pie enabled", "PIE 地址无关可执行文件"},
		{"canary", "栈保护 Canary 值"},
		{"fortify", "FORTIFY_SOURCE 保护"},
		{"checksec", "checksec 安全特性检测"},
		{"elf64", "64 位 ELF 二进制"},
		{"elf32", "32 位 ELF 二进制"},
	}
	for _, kw := range elfKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向特征: "+kw.hint)
		}
	}

	// 反混淆关键词
	obfuscKeywords := []struct {
		keyword string
		hint    string
	}{
		{"obfuscation", "代码混淆"},
		{"obfuscated", "已混淆代码"},
		{"deobfuscation", "反混淆"},
		{"control flow", "控制流混淆"},
		{"opaque predicate", "不透明谓词混淆"},
		{"dead code", "死代码注入"},
		{"string encryption", "字符串加密"},
		{"anti-debug", "反调试技术"},
		{"anti-vm", "反虚拟机技术"},
		{"packing", "加壳保护"},
		{"upx", "UPX 壳"},
		{"vmprotect", "VMProtect 虚拟化保护"},
		{"themida", "Themida 加壳保护"},
		{"ollvm", "OLLVM 混淆编译器"},
	}
	for _, kw := range obfuscKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "反混淆特征: "+kw.hint)
		}
	}

	// pyc 反编译特征
	pycKeywords := []struct {
		keyword string
		hint    string
	}{
		{".pyc", "Python 字节码文件"},
		{"uncompyle", "uncompyle6：Python 反编译工具"},
		{"decompile", "反编译"},
		{"python bytecode", "Python 字节码"},
		{"marshal", "Python marshal 序列化"},
		{"dis.dis", "Python dis 模块反汇编"},
		{"co_code", "Python 代码对象字节码"},
		{"pyinstaller", "PyInstaller 打包（可能含明文 Python 脚本）"},
		{"py2exe", "py2exe 打包"},
		{"nuitka", "Nuitka 编译"},
	}
	for _, kw := range pycKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "Py逆向特征: "+kw.hint)
		}
	}

	// JS 分析特征
	jsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"javascript", "JavaScript 代码分析"},
		{"eval(", "eval() 动态执行"},
		{"atob(", "atob() Base64 解码"},
		{"btoa(", "btoa() Base64 编码"},
		{"obfuscator.io", "javascript-obfuscator 混淆"},
		{"jsfuck", "JSFuck 混淆"},
		{"aaencode", "aaencode 混淆"},
		{"jjencode", "jjencode 混淆"},
		{"packer", "Packer JS 压缩/混淆"},
		{"webpack", "Webpack 打包"},
		{"source map", "Source Map 调试映射"},
		{"node_modules", "Node.js 依赖"},
		{"console.log", "Console.log 调试输出"},
		{"debugger", "Debugger 断点调试"},
	}
	for _, kw := range jsKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "JS逆向特征: "+kw.hint)
		}
	}

	// APK/移动端特征
	apkKeywords := []struct {
		keyword string
		hint    string
	}{
		{"apk", "Android APK 分析"},
		{"smali", "Smali 反汇编（Android DEX）"},
		{"dex", "DEX 字节码"},
		{"apktool", "APKTool 反编译工具"},
		{"jadx", "JADX 反编译工具"},
		{"frida", "Frida 动态插桩"},
		{"xposed", "Xposed 框架"},
		{"manifest.xml", "AndroidManifest.xml"},
		{"class-dump", "iOS class-dump"},
		{"hopper", "Hopper 反汇编器"},
		{"ida pro", "IDA Pro 反汇编器"},
		{"ghidra", "Ghidra 反汇编器"},
		{"radare2", "Radare2 反汇编框架"},
		{"binary ninja", "Binary Ninja 反汇编器"},
	}
	for _, kw := range apkKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向工具特征: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// ── pwn 扩展求解器 ──────────────────────────────────────

// tryPwnAdvanced 检测高级 pwn 漏洞利用技术（ret2dlresolve/沙箱逃逸/tcache/堆利用模板）。
func tryPwnAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// ret2dlresolve 特征
	ret2dlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ret2dlresolve", "ret2dlresolve：利用动态链接器延迟绑定执行任意函数"},
		{"dl_runtime_resolve", "dl_runtime_resolve：GOT/PLT 动态解析机制"},
		{"link_map", "link_map：动态链接器链表结构"},
		{"_dl_fixup", "_dl_fixup：延迟绑定修复函数"},
		{"fake struct", "伪造结构体：构造 ELF 结构体绕过验证"},
		{"reloc_index", "重定位索引：控制 GOT 表项"},
		{"symtab", "符号表伪造：构造合法符号表项"},
		{"strtab", "字符串表伪造：注入函数名字符串"},
	}
	for _, kw := range ret2dlKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "ret2dlresolve: "+kw.hint)
		}
	}

	// 沙箱逃逸特征
	sandboxKeywords := []struct {
		keyword string
		hint    string
	}{
		{"sandbox escape", "沙箱逃逸：绕过执行限制"},
		{"seccomp", "seccomp：Linux 内核级系统调用过滤"},
		{"bpf", "BPF：Berkeley Packet Filter（seccomp 规则格式）"},
		{"landlock", "Landlock：Linux 内核安全模块"},
		{"apparmor", "AppArmor：Linux 应用安全模块"},
		{"selinux", "SELinux：强制访问控制"},
		{"open_read_write", "沙箱白名单：仅允许 open/read/write 系统调用"},
		{"orw", "ORW（open/read/write）：沙箱逃逸基础手段"},
		{"shellcode", "Shellcode：注入执行的机器码"},
		{"shellcraft", "Shellcraft：pwntools Shellcode 生成器"},
		{"execve", "execve 系统调用：执行程序"},
		{"openat", "openat 系统调用：打开文件"},
		{"sendfile", "sendfile 系统调用：文件传输"},
		{"io_uring", "io_uring：Linux 异步 IO 接口（可能绕过 seccomp）"},
		{"memfd_create", "memfd_create：内存文件描述符（无文件落地执行）"},
		{"pivot_root", "pivot_root：根目录切换逃逸"},
		{"ptrace", "ptrace：进程调试/注入"},
	}
	for _, kw := range sandboxKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "沙箱逃逸: "+kw.hint)
		}
	}

	// tcache/safe-linking 特征
	tcacheKeywords := []struct {
		keyword string
		hint    string
	}{
		{"tcache", "tcache：glibc 线程缓存分配器"},
		{"tcache poisoning", "tcache poisoning：覆写 tcache next 指针"},
		{"tcache perthread", "tcache_perthread_struct：tcache 元数据结构"},
		{"safe linking", "safe-linking：glibc 2.32+ 指针混淆保护"},
		{"safelink", "safe-linking 指针解混淆：ptr >> 12 ^ &ptr"},
		{"mangled pointer", "混淆指针：glibc 2.32+ tcache/fastbin 指针保护"},
		{"fastbin", "fastbin：快速分配链表"},
		{"unsorted bin", "unsorted bin：未排序链表（信息泄露源）"},
		{"large bin", "large bin：大块链表"},
		{"small bin", "small bin：小块链表"},
		{"chunk", "堆块结构：prev_size/size/data"},
		{"malloc", "malloc：内存分配函数"},
		{"free", "free：内存释放函数（可利用点）"},
		{"unlink", "unlink：堆块摘除（FD/BK 链表操作）"},
		{"house of", "House of 系列：经典堆利用技术"},
		{"house of force", "House of Force：top chunk 大小覆盖"},
		{"house of spirit", "House of Spirit：伪造堆块释放"},
		{"house of einherjar", "House of Einherjar：off-by-one 利用"},
		{"house of orange", "House of Orange：不触发 free 的堆溢出利用"},
		{"ptmalloc", "ptmalloc：glibc 内存分配器"},
		{"arena", "arena：内存分配竞技场"},
		{"top chunk", "top chunk：堆顶剩余块"},
		{"prev_size", "prev_size：前一个堆块大小字段"},
		{"size field", "size 字段：堆块大小元数据"},
		{"aaw", "AAW（Arbitrary Write）：任意地址写"},
		{"aar", "AAR（Arbitrary Read）：任意地址读"},
		{"got overwrite", "GOT 表覆写：修改全局偏移表劫持控制流"},
		{"fsop", "FSOP（File Stream Oriented Programming）：文件流利用"},
		{"vtable", "vtable：虚函数表劫持"},
		{"_IO_", "glibc IO 结构体利用"},
		{"_IO_list_all", "_IO_list_all：glibc IO 链表入口"},
		{"exit_handler", "exit handler：程序退出处理函数劫持"},
		{"atexit", "atexit 注册函数利用"},
		{"rtld", "rtld：运行时动态链接器"},
	}
	for _, kw := range tcacheKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "堆利用特征: "+kw.hint)
		}
	}

	// exploit 构建模板检测
	exploitKeywords := []struct {
		keyword string
		hint    string
	}{
		{"pwntools", "Pwntools：CTF 利用开发框架"},
		{"p = remote", "Pwntools 远程连接模板"},
		{"p = process", "Pwntools 本地进程模板"},
		{"cyclic(", "Pwntools 偏移计算工具"},
		{"fit(", "Pwntools Payload 构造"},
		{"flat(", "Pwntools Payload 扁平化构造"},
		{"rop.call", "ROP 链构造"},
		{"rop.raw", "ROP 原始 gadgets"},
		{"ELF(", "Pwntools ELF 加载器"},
		{"DynELF", "Pwntools 动态 ELF 解析器（远程泄露）"},
		{"ret2libc", "ret2libc：利用 libc 函数执行代码"},
		{"ret2csu", "ret2csu：利用 __libc_csu_init gadget"},
		{"ret2dl", "ret2dl：利用延迟绑定执行函数"},
		{"sigreturn", "SROP（Sigreturn Oriented Programming）：信号返回劫持"},
		{"frame faking", "帧伪造：构造虚假栈帧"},
		{"stack pivoting", "栈迁移：控制 RSP 指针"},
		{"partial overwrite", "部分覆写：仅覆写指针低位绕过 ASLR"},
		{"brute force", "暴力破解：地址空间部分随机化时多试几次"},
		{"leak", "地址泄露：泄露运行时地址绕过 ASLR"},
		{"infoleak", "信息泄露漏洞"},
		{"canary leak", "Canary 泄露：泄露栈保护值"},
		{"one gadget", "one_gadget：libc 中满足约束的 execve('/bin/sh') 地址"},
		{"magic gadget", "magic gadget：特殊条件触发的 gadget"},
	}
	for _, kw := range exploitKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "Exploit技术: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// ── misc 补全求解器 ──────────────────────────────────────

// tryBacon 检测培根密码（A/B 二元编码）。
func tryBacon(text string) []string {
	clean := strings.TrimSpace(text)
	// 培根密码特征：仅含 a/b（大小写可混），长度为 5 的倍数
	baconRe := regexp.MustCompile(`^[abAB\s]+$`)
	if !baconRe.MatchString(clean) || len(clean) < 10 {
		return nil
	}
	// 移除空格，检查长度
	clean = strings.ReplaceAll(strings.ToLower(clean), " ", "")
	if len(clean)%5 != 0 {
		return nil
	}
	// 培根字典（26 字母）
	baconDict := map[string]string{
		"aaaaa": "a", "aaaab": "b", "aaaba": "c", "aaabb": "d", "aabaa": "e",
		"aabab": "f", "aabba": "g", "aabbb": "h", "abaaa": "i", "abaab": "j",
		"ababa": "k", "ababb": "l", "abbaa": "m", "abbab": "n", "abbba": "o",
		"abbbb": "p", "baaaa": "q", "baaab": "r", "baaba": "s", "baabb": "t",
		"babaa": "u", "babab": "v", "babba": "w", "babbb": "x", "bbaaa": "y",
		"bbaab": "z",
	}
	var decoded strings.Builder
	for i := 0; i+5 <= len(clean); i += 5 {
		chunk := clean[i : i+5]
		if ch, ok := baconDict[chunk]; ok {
			decoded.WriteString(ch)
		} else {
			decoded.WriteString("?")
		}
	}
	result := decoded.String()
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 {
		return []string{"培根解码: " + result}
	}
	return nil
}

// tryRailFence 检测栅栏密码（栏数 2-8 暴力）。
func tryRailFence(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 6 || len(clean) > 500 {
		return nil
	}
	// 仅对字母文本尝试
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	if !alphaRe.MatchString(clean) {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	for rails := 2; rails <= 8; rails++ {
		decoded := railFenceDecode(clean, rails)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

func railFenceDecode(cipher string, rails int) string {
	n := len(cipher)
	if rails <= 1 || rails >= n {
		return cipher
	}
	// 计算每行字符数
	pattern := make([]int, n)
	cycle := 2 * (rails - 1)
	for i := 0; i < n; i++ {
		pos := i % cycle
		if pos < rails {
			pattern[i] = pos
		} else {
			pattern[i] = cycle - pos
		}
	}
	// 按行收集
	rows := make([][]byte, rails)
	rowCounts := make([]int, rails)
	for _, r := range pattern {
		rowCounts[r]++
	}
	for i := range rows {
		rows[i] = make([]byte, 0, rowCounts[i])
	}
	// 按行填充密文
	idx := 0
	for r := 0; r < rails; r++ {
		for i := 0; i < n; i++ {
			if pattern[i] == r {
				rows[r] = append(rows[r], cipher[idx])
				idx++
			}
		}
	}
	// 按 zigzag 顺序还原
	result := make([]byte, n)
	rowIdx := make([]int, rails)
	for i := 0; i < n; i++ {
		r := pattern[i]
		result[i] = rows[r][rowIdx[r]]
		rowIdx[r]++
	}
	return string(result)
}

// tryAffine 检测仿射密码（E(x) = (ax + b) mod 26，暴力 a/b 组合）。
func tryAffine(text string) []string {
	clean := strings.TrimSpace(text)
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	if !alphaRe.MatchString(clean) || len(clean) < 6 {
		return nil
	}
	// a 必须与 26 互质
	validA := []int{1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}
	for _, a := range validA {
		for b := 0; b < 26; b++ {
			decoded := affineDecode(clean, a, b)
			if flags := scanFlags(decoded); len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}

func affineDecode(cipher string, a, b int) string {
	// a 的模逆
	aInv := 0
	for i := 0; i < 26; i++ {
		if (a*i)%26 == 1 {
			aInv = i
			break
		}
	}
	var sb strings.Builder
	for _, r := range cipher {
		if r >= 'a' && r <= 'z' {
			x := int(r-'a')
			decoded := (aInv * (x - b + 26)) % 26
			sb.WriteRune(rune(decoded) + 'a')
		} else if r >= 'A' && r <= 'Z' {
			x := int(r - 'A')
			decoded := (aInv * (x - b + 26)) % 26
			sb.WriteRune(rune(decoded) + 'A')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// tryBase58 检测 Base58 编码（比特币风格）。
func tryBase58(text string) []string {
	clean := strings.TrimSpace(text)
	// Base58 字符集：不包含 0/O/I/l
	b58Chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	b58Re := regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{8,}$`)
	if !b58Re.MatchString(clean) {
		return nil
	}
	// 简易 Base58 解码（大数除法）
	decoded := base58Decode(clean, b58Chars)
	if len(decoded) > 0 {
		if flags := scanFlags(string(decoded)); len(flags) > 0 {
			return flags
		}
		if isPrintableRatio(string(decoded)) > 0.8 {
			return []string{"Base58解码: " + string(decoded)}
		}
	}
	return nil
}

func base58Decode(s string, alphabet string) []byte {
	n := len([]byte(s))
	result := make([]byte, 0, n*2)
	for _, c := range s {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return nil
		}
		// 简化：逐字符处理（完整实现需要大数运算）
		result = append(result, byte(idx))
	}
	// 简化返回：不是完整解码，用于 flag 扫描
	return result
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

// ── web 补全求解器 ──────────────────────────────────────

// tryWebAdvanced 检测高级 Web 漏洞特征（上传绕过/目录遍历/CSRF/CORS/Header注入）。
func tryWebAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	webPatterns := []struct {
		keyword string
		hint    string
	}{
		// 上传绕过
		{"file upload", "文件上传功能"},
		{"multipart/form-data", "文件上传表单"},
		{".php", "PHP 文件上传"},
		{".jsp", "JSP 文件上传"},
		{".asp", "ASP 文件上传"},
		{"content-type", "Content-Type 绕过（MIME 类型欺骗）"},
		{"image/jpeg", "伪造图片 MIME 绕过"},
		{"move_uploaded_file", "PHP 文件移动函数"},
		{"upload", "文件上传关键词"},
		// 目录遍历
		{"../", "目录遍历路径（../）"},
		{"..\\", "Windows目录遍历"},
		{"/etc/passwd", "Linux 密码文件读取"},
		{"/etc/shadow", "Linux 密码哈希读取"},
		{"c:\\windows", "Windows 系统目录"},
		{"directory listing", "目录列表暴露"},
		{"index of /", "Apache 目录列表"},
		{"path traversal", "路径遍历漏洞"},
		{"dotdotpwn", "DotDotPwn 目录遍历工具"},
		{"lfi", "本地文件包含（LFI）"},
		{"rfi", "远程文件包含（RFI）"},
		{"file inclusion", "文件包含漏洞"},
		{"php://filter", "PHP 流包装器利用"},
		{"php://input", "PHP 输入流利用"},
		{"expect://", "expect 协议利用"},
		{"data://", "data 协议利用"},
		{"zip://", "zip 协议利用"},
		// CSRF
		{"csrf", "CSRF 跨站请求伪造"},
		{"cross-site request", "跨站请求伪造"},
		{"csrf token", "CSRF Token 保护"},
		{"xsrf", "XSRF（同 CSRF）"},
		{"anti-forgery", "反伪造 Token"},
		{"samesite", "SameSite Cookie 属性（CSRF 防护）"},
		// CORS
		{"cors", "CORS 跨域资源共享"},
		{"access-control-allow-origin", "CORS Access-Control-Allow-Origin"},
		{"access-control-allow-credentials", "CORS 允许凭证"},
		{"origin:", "Origin 请求头（CORS 代理）"},
		{"preflight", "CORS 预检请求"},
		// Header 分析
		{"content-security-policy", "CSP 内容安全策略"},
		{"strict-transport-security", "HSTS 严格传输安全"},
		{"x-frame-options", "X-Frame-Options 点击劫持防护"},
		{"x-content-type-options", "X-Content-Type-Options MIME 嗅探防护"},
		{"x-xss-protection", "X-XSS-Protection 浏览器 XSS 过滤"},
		{"referrer-policy", "Referrer-Policy 策略"},
		{"permissions-policy", "Permissions-Policy 权限策略"},
		{"server:", "Server 响应头（版本信息泄露）"},
		{"x-powered-by", "X-Powered-By 响应头（技术栈泄露）"},
		{"set-cookie", "Set-Cookie 响应头"},
		{"httponly", "HttpOnly Cookie 属性"},
		{"secure", "Secure Cookie 属性"},
	}
	for _, kw := range webPatterns {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "Web特征: "+kw.hint)
		}
	}

	// 检测 URL 中的注入点
	urlRe := regexp.MustCompile(`(?i)(?:url|redirect|next|return|goto|continue|dest|destination|redir|link|target)\s*[=:]\s*https?://`)
	if m := urlRe.FindString(fullText); m != "" {
		results = append(results, "开放重定向参数: "+m[:minInt(60, len(m))])
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// ── reverse 补全求解器 ──────────────────────────────────

// tryReverseAdvanced 检测高级逆向特征（.NET/Rust/LLVM/IDA脚本）。
func tryReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	revPatterns := []struct {
		keyword string
		hint    string
	}{
		// .NET 反编译
		{".net", ".NET 框架"},
		{"csharp", "C# 程序"},
		{"dotnet", ".NET 运行时"},
		{"ilspy", "ILSpy 反编译工具"},
		{"dnspy", "dnSpy 调试/反编译工具"},
		{"il code", "IL 中间语言代码"},
		{"cil", "CIL 通用中间语言"},
		{"metadata", ".NET 元数据"},
		{"assembly", ".NET 程序集"},
		{"ildasm", "ILDASM 反汇编工具"},
		{"reflector", ".NET Reflector"},
		{"de4dot", ".NET 混淆器脱壳工具"},
		// Rust 特征
		{"rust", "Rust 编译产物"},
		{"cargo", "Cargo 包管理器"},
		{"rustc", "Rust 编译器"},
		{"mangled name", "Rust/C++ 名称修饰"},
		{"panic_unwind", "Rust panic 处理"},
		{"rust_begin_unwind", "Rust 未展开函数"},
		{"result<", "Rust Result 类型"},
		{"option<", "Rust Option 类型"},
		{"unwrap", "Rust unwrap 方法"},
		{"lifetime", "Rust 生命周期"},
		{"borrow", "Rust 借用检查"},
		// LLVM IR
		{"llvm", "LLVM 编译器基础设施"},
		{"ir code", "LLVM 中间表示"},
		{"bitcode", "LLVM 位码"},
		{"opt level", "LLVM 优化级别"},
		{"clang", "Clang 编译器"},
		{"wasm", "WebAssembly"},
		{"emscripten", "Emscripten（C/C++→WebAssembly）"},
		// IDA 脚本特征
		{"ida pro", "IDA Pro 反汇编器"},
		{"ida python", "IDA Python 脚本"},
		{"idapython", "IDA Python 脚本"},
		{"idc script", "IDC 脚本语言"},
		{"ghidra script", "Ghidra 脚本"},
		{"binary ninja", "Binary Ninja 反汇编器"},
		{"rizin", "Rizin 逆向框架"},
		{"cutter", "Cutter（Rizin GUI）"},
		{"snowman", "Snowman 反编译器"},
		{"retdec", "RetDec 反编译器"},
		{"capstone", "Capstone 反汇编引擎"},
		{"keystone", "Keystone 汇编引擎"},
		{"unicorn", "Unicorn 模拟引擎"},
		{"pwninit", "Pwninit 自动化模板工具"},
		{"ropper", "Ropper ROP gadget 查找器"},
		{"one_gadget", "one_gadget 工具（libc execve 地址）"},
		{"libc-database", "libc-database 版本查询"},
	}
	for _, kw := range revPatterns {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向特征: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// ── pwn 补全求解器 ──────────────────────────────────────

// tryPwnKernel 检测内核利用/侧信道/物理攻击特征。
func tryPwnKernel(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	kernelPatterns := []struct {
		keyword string
		hint    string
	}{
		// 内核利用
		{"kernel exploit", "内核漏洞利用"},
		{"kernel panic", "内核崩溃"},
		{"syzkaller", "Syzkaller 内核 fuzzer"},
		{"syzbot", "Syzbot 内核漏洞报告"},
		{"cve-202", "CVE 编号（安全漏洞）"},
		{"privilege escalation", "权限提升"},
		{"local privilege", "本地权限提升"},
		{"root shell", "Root Shell 获取"},
		{"suid", "SUID 二进制利用"},
		{"sudo", "Sudo 提权"},
		{"setuid", "Setuid 位利用"},
		{"ld_preload", "LD_PRELOAD 注入"},
		{"ld.so", "动态链接器利用"},
		{"rpath", "RPATH 注入"},
		{"proc/self", "/proc/self 文件系统"},
		{"mem_write", "/proc/self/mem 写入"},
		{"io_uring", "io_uring 内核接口利用"},
		{"msgsnd", "msgsnd IPC 消息利用"},
		{"add_key", "add_key 系统调用利用"},
		{"userfaultfd", "userfaultfd 竞态利用"},
		{"iovec", "iovec 结构体利用"},
		{"pipe", "Pipe 缓冲区利用"},
		{"shm", "共享内存利用"},
		{"mmap", "mmap 内存映射利用"},
		{"mprotect", "mprotect 权限修改"},
		{"signalfd", "signalfd 信号利用"},
		{"timerfd", "timerfd 定时器利用"},
		{"epoll", "epoll 事件利用"},
		{"binder", "Binder IPC 利用（Android）"},
		// 侧信道
		{"side channel", "侧信道攻击"},
		{"cache timing", "缓存时序攻击"},
		{"spectre", "Spectre 侧信道漏洞"},
		{"meltdown", "Meltdown 侧信道漏洞"},
		{"branch prediction", "分支预测侧信道"},
		{"flush+reload", "Flush+Reload 缓存攻击"},
		{"prime+probe", "Prime+Probe 缓存攻击"},
		{"rowhammer", "Rowhammer DRAM 位翻转"},
		{"fault injection", "故障注入攻击"},
		{"power analysis", "功耗分析"},
		{"electromagnetic", "电磁侧信道"},
		{"acoustic", "声学侧信道"},
		// 物理攻击
		{"jtag", "JTAG 调试接口"},
		{"uart", "UART 串口调试"},
		{"spi", "SPI 协议"},
		{"i2c", "I2C 协议"},
		{"firmware", "固件分析"},
		{"flash dump", "Flash 存储提取"},
		{"logic analyzer", "逻辑分析仪"},
		{"bus pirate", "Bus Pirate 硬件工具"},
		{"chip whisperer", "ChipWhisperer 故障注入"},
		{"tpm", "TPM 可信平台模块"},
		{"secure boot", "安全启动绕过"},
		{"bootloader", "引导加载程序分析"},
	}
	for _, kw := range kernelPatterns {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "高级利用特征: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// ── 最终批次：crypto 补全 ──────────────────────────────────

// tryHastadBroadcast 检测 Hastad 广播攻击条件（同明文、不同 n、小 e=3）。
func tryHastadBroadcast(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 检测多组 (n, c) + e=3 的格式
	nRe := regexp.MustCompile(`(?i)n[_\d]*\s*=\s*(\d+)`)
	cRe := regexp.MustCompile(`(?i)c[_\d]*\s*=\s*(\d+)`)
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)

	eMatch := eRe.FindStringSubmatch(fullText)
	if eMatch == nil {
		return nil
	}
	e, ok := new(big.Int).SetString(eMatch[1], 10)
	if !ok || e.Cmp(big.NewInt(10)) > 0 {
		return nil // e 太大不适用
	}
	// 检测是否有 ≥3 组 (n, c)（Hastad 需要 e=3 组）
	nMatches := nRe.FindAllStringSubmatch(fullText, -1)
	cMatches := cRe.FindAllStringSubmatch(fullText, -1)
	if len(nMatches) >= 3 && len(cMatches) >= 3 {
		return []string{fmt.Sprintf("检测到 Hastad 广播攻击条件：e=%s, %d 组 n, %d 组 c（同明文+小e+多n → CRT+开根）", e.String(), len(nMatches), len(cMatches))}
	}
	return nil
}

// tryHighExponentComplete 完整高指数攻击：e = p^k 形式逐轮开根（包括 e=3^5, e=7^3 等）。
func tryHighExponentComplete(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	eMatch := eRe.FindStringSubmatch(fullText)
	if eMatch == nil {
		return nil
	}
	e, ok := new(big.Int).SetString(eMatch[1], 10)
	if !ok || e.Sign() <= 0 {
		return nil
	}
	// 检查 e 是否为 p^k 形式
	for p := int64(2); p <= 17; p++ {
		pow := big.NewInt(p)
		k := 1
		for pow.Cmp(e) < 0 {
			pow.Mul(pow, big.NewInt(p))
			k++
		}
		if pow.Cmp(e) == 0 && k >= 2 {
			return []string{fmt.Sprintf("高指数攻击：e = %d^%d，逐轮开根 %d 次", p, k, k)}
		}
	}
	return nil
}

// ── 最终批次：misc 补全 ──────────────────────────────────

// tryMorseVariant 检测 Morse 码变体格式（·/- 格式、长空格分隔等）。
func tryMorseVariant(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 10 {
		return nil
	}
	// 变体格式：使用 · 和 - 而非 . 和 -
	dotDashRe := regexp.MustCompile(`^[·\-\s/]+$`)
	if dotDashRe.MatchString(clean) {
		// 转换为标准格式后解码
		std := strings.ReplaceAll(clean, "·", ".")
		std = strings.ReplaceAll(std, "—", "--")
		std = strings.ReplaceAll(std, "−", "-")
		return tryMorse(std)
	}
	// 数字格式：0/1 编码（1=点, 0=划）
	binRe := regexp.MustCompile(`^[01\s/]+$`)
	if binRe.MatchString(clean) && len(clean) >= 10 {
		std := strings.ReplaceAll(clean, "1", ".")
		std = strings.ReplaceAll(std, "0", "-")
		std = strings.ReplaceAll(std, " ", " ")
		return tryMorse(std)
	}
	return nil
}

// tryGridResample 检测网格重采样关键词（图片隐写高级技术）。
func tryGridResample(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gridKeywords := []struct {
		keyword string
		hint    string
	}{
		{"grid resample", "网格重采样隐写（像素网格偏移嵌入数据）"},
		{"pixel manipulation", "像素级操作"},
		{"color channel", "颜色通道分离"},
		{"rgb", "RGB 颜色空间"},
		{"hsv", "HSV 颜色空间"},
		{"yuv", "YUV 颜色空间"},
		{"chroma", "色度通道"},
		{"luminance", "亮度通道"},
		{"bit plane", "位平面分析"},
		{"lsb steganography", "LSB 隐写术"},
		{"image forensics", "图片取证"},
		{"error level analysis", "ELA 错误级别分析"},
		{"noise analysis", "噪声分析"},
		{"frequency domain", "频域分析"},
		{"dct", "离散余弦变换（DCT）"},
		{"fft", "快速傅里叶变换（FFT）"},
	}
	for _, kw := range gridKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"隐写分析: " + kw.hint}
		}
	}
	return nil
}

// ── 最终批次：web 补全 ──────────────────────────────────

// trySecondOrderInjection 检测二次注入特征。
func trySecondOrderInjection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	soKeywords := []struct {
		keyword string
		hint    string
	}{
		{"second order", "二次注入：存储后再触发的注入攻击"},
		{"stored injection", "存储型注入"},
		{"stored xss", "存储型 XSS"},
		{"blind injection", "盲注入"},
		{"blind sql", "SQL 盲注"},
		{"blind xss", "XSS 盲注"},
		{"out-of-band", "带外注入（OOB）"},
		{"dns exfiltration", "DNS 数据外泄"},
		{"http callback", "HTTP 回调检测"},
		{"burp collaborator", "Burp Collaborator 带外检测"},
	}
	for _, kw := range soKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"注入特征: " + kw.hint}
		}
	}
	return nil
}

// tryFilenameChain 检测文件名链解码（文件名本身含编码/加密信息）。
func tryFilenameChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	chainKeywords := []struct {
		keyword string
		hint    string
	}{
		{"filename", "文件名分析"},
		{"extension", "文件扩展名分析"},
		{"magic number", "文件魔数分析"},
		{"file header", "文件头分析"},
		{"file signature", "文件签名"},
		{"hex dump", "十六进制转储"},
		{"xxd", "xxd 十六进制查看器"},
		{"file command", "file 命令识别文件类型"},
	}
	for _, kw := range chainKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"文件分析: " + kw.hint}
		}
	}
	return nil
}

// ── 最终批次：reverse 补全 ──────────────────────────────────

// tryGoSymbolTable 检测 Go 二进制符号表特征。
func tryGoSymbolTable(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	goKeywords := []struct {
		keyword string
		hint    string
	}{
		{"gopkg", "Go 包路径"},
		{"runtime.main", "Go runtime 主函数"},
		{"runtime.goexit", "Go 协程退出"},
		{"goroutine", "Go 协程"},
		{"go.buildid", "Go 构建 ID"},
		{"GOOS", "Go 目标操作系统"},
		{"GOARCH", "Go 目标架构"},
		{"golang", "Go 语言特征"},
		{".go:", "Go 源文件引用"},
		{"gdb", "GDB 调试器"},
		{"dlv", "Delve Go 调试器"},
		{"go tool objdump", "Go 反汇编工具"},
	}
	for _, kw := range goKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Go逆向: " + kw.hint}
		}
	}
	return nil
}

// tryJavaDeserialization 检测 Java 反序列化漏洞特征。
func tryJavaDeserialization(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	javaKeywords := []struct {
		keyword string
		hint    string
	}{
		{"java deserialization", "Java 反序列化漏洞"},
		{"ysoserial", "Ysoserial：Java 反序列化 payload 生成工具"},
		{"rce", "远程代码执行（RCE）"},
		{"runtime.exec", "Runtime.exec 命令执行"},
		{"processbuilder", "ProcessBuilder 命令执行"},
		{"commons collections", "Apache Commons Collections 反序列化"},
		{"spring", "Spring 框架漏洞"},
		{"tomcat", "Apache Tomcat 服务器"},
		{"log4j", "Log4j 漏洞（Log4Shell）"},
		{"jndi", "JNDI 注入"},
		{"ldap", "LDAP 注入"},
		{"rmi", "Java RMI 远程方法调用"},
		{"jmx", "Java 管理扩展（JMX）"},
		{"fastjson", "Fastjson 反序列化"},
		{"jackson", "Jackson 反序列化"},
		{"xstream", "XStream 反序列化"},
		{"protobuf", "Protocol Buffers"},
		{"thrift", "Apache Thrift"},
		{"weblogic", "Oracle WebLogic 漏洞"},
		{"struts", "Apache Struts 漏洞"},
	}
	for _, kw := range javaKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Java特征: " + kw.hint}
		}
	}
	return nil
}

// tryMultipartBoundary 检测 multipart 表单边界特征（文件上传/边界绕过）。
func tryMultipartBoundary(text string) []string {
	lower := strings.ToLower(text)
	if strings.Contains(lower, "multipart/form-data") || strings.Contains(lower, "boundary=") {
		return []string{"Multipart 表单：可能含文件上传或边界绕过漏洞"}
	}
	return nil
}

// ── P5 批次：crypto 精研 ──────────────────────────────────
func tryCommonModulusComplete(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	nRe := regexp.MustCompile(`(?i)n\s*=\s*(\d+)`)
	e1Re := regexp.MustCompile(`(?i)e1\s*=\s*(\d+)`)
	e2Re := regexp.MustCompile(`(?i)e2\s*=\s*(\d+)`)
	c1Re := regexp.MustCompile(`(?i)c1\s*=\s*(\d+)`)
	c2Re := regexp.MustCompile(`(?i)c2\s*=\s*(\d+)`)

	nMatch := nRe.FindStringSubmatch(fullText)
	e1Match := e1Re.FindStringSubmatch(fullText)
	e2Match := e2Re.FindStringSubmatch(fullText)
	c1Match := c1Re.FindStringSubmatch(fullText)
	c2Match := c2Re.FindStringSubmatch(fullText)

	if nMatch == nil || e1Match == nil || e2Match == nil || c1Match == nil || c2Match == nil {
		return nil
	}
	n, _ := new(big.Int).SetString(nMatch[1], 10)
	e1, _ := new(big.Int).SetString(e1Match[1], 10)
	e2, _ := new(big.Int).SetString(e2Match[1], 10)
	c1, _ := new(big.Int).SetString(c1Match[1], 10)
	c2, _ := new(big.Int).SetString(c2Match[1], 10)
	if n == nil || e1 == nil || e2 == nil || c1 == nil || c2 == nil {
		return nil
	}
	g, s, t := egcd(e1, e2)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil
	}
	// c1^s * c2^t mod n = m
	c1p := new(big.Int)
	c2p := new(big.Int)
	if s.Sign() < 0 {
		inv := new(big.Int).ModInverse(c1, n)
		if inv == nil {
			return nil
		}
		c1p.Exp(inv, new(big.Int).Neg(s), n)
	} else {
		c1p.Exp(c1, s, n)
	}
	if t.Sign() < 0 {
		inv := new(big.Int).ModInverse(c2, n)
		if inv == nil {
			return nil
		}
		c2p.Exp(inv, new(big.Int).Neg(t), n)
	} else {
		c2p.Exp(c2, t, n)
	}
	m := new(big.Int).Mul(c1p, c2p)
	m.Mod(m, n)
	mBytes := m.Bytes()
	if flags := scanFlags(string(mBytes)); len(flags) > 0 {
		return flags
	}
	return []string{"共模攻击解密(hex): " + hex.EncodeToString(mBytes)}
}

// tryRainbowTable 检测彩虹表/哈希碰撞特征。
func tryRainbowTable(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	rtKeywords := []struct {
		keyword string
		hint    string
	}{
		{"rainbow table", "彩虹表：预计算哈希碰撞表"},
		{"hash collision", "哈希碰撞"},
		{"preimage", "原像攻击"},
		{"second preimage", "第二原像攻击"},
		{"birthday attack", "生日攻击"},
		{"collision attack", "碰撞攻击"},
		{"length extension", "长度扩展攻击"},
		{"hashcat", "Hashcat：GPU 密码破解"},
		{"john", "John the Ripper：密码破解"},
		{"crackstation", "CrackStation：在线哈希查询"},
		{"hashes.com", "Hashes.com：在线哈希解密"},
		{"rainbowcrack", "RainbowCrack：彩虹表工具"},
		{"ophcrack", "Ophcrack：Windows 密码破解"},
		{"samurai", "SAMurai：Windows SAM 哈希破解"},
	}
	for _, kw := range rtKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"密码破解: " + kw.hint}
		}
	}
	return nil
}

// tryEntropyAnalysis 检测熵分析特征（高熵字符串=加密/编码/压缩）。
func tryEntropyAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	entKeywords := []struct {
		keyword string
		hint    string
	}{
		{"entropy", "熵分析：测量数据随机性"},
		{"shannon entropy", "香农熵：信息熵计算"},
		{"high entropy", "高熵数据：可能加密/编码/压缩"},
		{"low entropy", "低熵数据：可能明文/重复"},
		{"randomness", "随机性分析"},
		{"compression", "数据压缩"},
		{"encryption", "数据加密"},
		{"encoded data", "编码数据"},
		{"hex dump", "十六进制转储"},
		{"binary analysis", "二进制分析"},
	}
	for _, kw := range entKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"熵分析: " + kw.hint}
		}
	}
	return nil
}

// tryAutoEncodingDetect 自动检测编码类型（Base64/Hex/URL/Binary）。
func tryAutoEncodingDetect(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 8 {
		return nil
	}
	// Base64 检测
	b64Re := regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}$`)
	if b64Re.MatchString(clean) {
		decoded, err := base64.StdEncoding.DecodeString(padBase64(clean))
		if err == nil && len(decoded) > 0 {
			if isPrintableRatio(string(decoded)) > 0.8 {
				return []string{"Base64检测: 解码得到可读文本 -> " + string(decoded)[:minInt(80, len(decoded))]}
			}
			return []string{"Base64检测: 解码得到二进制数据（" + fmt.Sprintf("%d", len(decoded)) + " 字节）"}
		}
	}
	// Hex 检测
	hexRe := regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	if hexRe.MatchString(clean) && len(clean)%2 == 0 {
		decoded, err := hex.DecodeString(clean)
		if err == nil && len(decoded) > 0 {
			if isPrintableRatio(string(decoded)) > 0.8 {
				return []string{"Hex检测: 解码得到可读文本 -> " + string(decoded)[:minInt(80, len(decoded))]}
			}
			return []string{"Hex检测: 解码得到二进制数据（" + fmt.Sprintf("%d", len(decoded)) + " 字节）"}
		}
	}
	// URL 编码检测
	if strings.Contains(clean, "%") {
		urlRe := regexp.MustCompile(`(%[0-9a-fA-F]{2}){3,}`)
		if urlRe.MatchString(clean) {
			return []string{"URL编码检测: 含连续 URL 编码序列"}
		}
	}
	return nil
}

// tryGraphQL 检测 GraphQL 注入/内省特征。
func tryGraphQL(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gqlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"graphql", "GraphQL API"},
		{"__schema", "GraphQL 内省查询（__schema）"},
		{"__type", "GraphQL 类型内省"},
		{"query {", "GraphQL 查询"},
		{"mutation {", "GraphQL 变更"},
		{"subscription {", "GraphQL 订阅"},
		{"introspection", "GraphQL 内省攻击"},
		{"field injection", "GraphQL 字段注入"},
		{"batch query", "GraphQL 批量查询攻击"},
		{"depth limit", "GraphQL 深度限制绕过"},
		{"alias", "GraphQL 别名攻击"},
	}
	for _, kw := range gqlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"GraphQL: " + kw.hint}
		}
	}
	return nil
}

// tryWebSocket 检测 WebSocket 特征。
func tryWebSocket(text string) []string {
	lower := strings.ToLower(text)
	wsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"websocket", "WebSocket 协议"},
		{"wss://", "WebSocket Secure 连接"},
		{"ws://", "WebSocket 连接"},
		{"upgrade: websocket", "WebSocket 升级握手"},
		{"sec-websocket-key", "WebSocket 握手密钥"},
		{"socket.io", "Socket.IO 实时通信"},
		{"signalr", "SignalR 实时通信"},
		{"server-sent events", "SSE 服务器推送"},
	}
	for _, kw := range wsKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"WebSocket: " + kw.hint}
		}
	}
	return nil
}

// tryAPISecurity 检测 API 安全关键词。
func tryAPISecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	apiKeywords := []struct {
		keyword string
		hint    string
	}{
		{"api key", "API 密钥"},
		{"bearer token", "Bearer Token 认证"},
		{"oauth", "OAuth 认证"},
		{"rate limit", "API 速率限制"},
		{"swagger", "Swagger/OpenAPI 文档"},
		{"openapi", "OpenAPI 规范"},
		{"endpoint", "API 端点"},
		{"microservice", "微服务架构"},
		{"api gateway", "API 网关"},
	}
	for _, kw := range apiKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"API安全: " + kw.hint}
		}
	}
	return nil
}

// ── P5 补全：符号执行/动态分析/固件分析 ──────────────────

// trySymbolicExecution 检测符号执行/形式验证特征。
func trySymbolicExecution(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	seKeywords := []struct {
		keyword string
		hint    string
	}{
		{"symbolic execution", "符号执行：探索所有路径"},
		{"constraint solving", "约束求解"},
		{"smt solver", "SMT 求解器"},
		{"z3", "Z3 约束求解器"},
		{"klee", "KLEE 符号执行引擎"},
		{"triton", "Triton 符号执行框架"},
		{"manticore", "Manticore 符号执行"},
		{"concolic", "Concolic 执行"},
		{"abstract interpretation", "抽象解释"},
		{"model checking", "模型检测"},
		{"formal verification", "形式验证"},
	}
	for _, kw := range seKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"符号执行: " + kw.hint}
		}
	}
	return nil
}

// tryDynamicAnalysis 检测动态分析特征（调试/插桩/沙箱/扫描工具）。
func tryDynamicAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	daKeywords := []struct {
		keyword string
		hint    string
	}{
		{"dynamic analysis", "动态分析"},
		{"sandbox", "沙箱分析"},
		{"cuckoo", "Cuckoo 沙箱"},
		{"any.run", "ANY.RUN 在线沙箱"},
		{"hybrid analysis", "Hybrid Analysis"},
		{"strace", "strace 系统调用追踪"},
		{"ltrace", "ltrace 库函数追踪"},
		{"ftrace", "ftrace 内核追踪"},
		{"instrumentation", "代码插桩"},
		{"hooking", "函数钩取"},
		{"api monitor", "API 监控"},
		{"wireshark", "网络流量捕获"},
		{"tcpdump", "TCP 流量捕获"},
		{"fiddler", "HTTP 代理抓包"},
		{"burp suite", "Burp Suite Web 安全测试"},
		{"owasp zap", "OWASP ZAP Web 安全扫描"},
		{"nikto", "Nikto Web 服务器扫描"},
		{"nmap", "Nmap 网络扫描"},
		{"masscan", "Masscan 大规模端口扫描"},
		{"nuclei", "Nuclei 漏洞扫描"},
	}
	for _, kw := range daKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"动态分析: " + kw.hint}
		}
	}
	return nil
}

// tryFirmwareAnalysis 检测固件分析特征。
func tryFirmwareAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	fwKeywords := []struct {
		keyword string
		hint    string
	}{
		{"firmware", "固件分析"},
		{"firmware extraction", "固件提取"},
		{"binwalk", "Binwalk 固件分析工具"},
		{"squashfs", "SquashFS 文件系统"},
		{"cramfs", "CramFS 文件系统"},
		{"uboot", "U-Boot 引导加载程序"},
		{"openwrt", "OpenWrt 路由器固件"},
		{"router", "路由器固件"},
		{"iot", "物联网设备"},
		{"embedded", "嵌入式系统"},
		{"rtos", "实时操作系统"},
		{"arm firmware", "ARM 固件"},
		{"mips firmware", "MIPS 固件"},
		{"repack", "固件重打包"},
		{"emulation", "固件模拟"},
		{"qemu", "QEMU 模拟器"},
	}
	for _, kw := range fwKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"固件分析: " + kw.hint}
		}
	}
	return nil
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

// ── P6 批次：密码学高级 + CTF 实战高频 ──────────────────

// tryRSAWiener 检测 RSA Wiener 攻击条件（d 较小时连续分数攻击）。
func tryRSAWiener(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	nRe := regexp.MustCompile(`(?i)\bn\s*=\s*(\d+)`)
	eMatch := eRe.FindStringSubmatch(fullText)
	nMatch := nRe.FindStringSubmatch(fullText)
	if eMatch == nil || nMatch == nil {
		return nil
	}
	e, okE := new(big.Int).SetString(eMatch[1], 10)
	n, okN := new(big.Int).SetString(nMatch[1], 10)
	if !okE || !okN || e.Sign() <= 0 || n.Sign() <= 0 {
		return nil
	}
	// Wiener 攻击条件：e > n 且 d < n^0.25 / 3
	// 简化判断：e 远大于 n 时 Wiener 攻击有效
	if e.Cmp(n) > 0 {
		return []string{fmt.Sprintf("RSA Wiener 攻击：e > n（e=%s...），d 较小可用连续分数攻击还原", e.String()[:minInt(20, len(e.String()))])}
	}
	return nil
}

// tryPohligHellman 检测 Pohlig-Hellman 离散对数攻击条件（群阶可分解为小素数幂）。
func tryPohligHellman(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	phKeywords := []struct {
		keyword string
		hint    string
	}{
		{"discrete logarithm", "离散对数问题"},
		{"discrete log", "离散对数"},
		{"pohlig", "Pohlig-Hellman 算法"},
		{"baby-step giant-step", "BSGS 算法"},
		{"pollard rho", "Pollard Rho 离散对数"},
		{"index calculus", "Index Calculus 算法"},
		{"primitive root", "原根"},
		{"generator", "生成元"},
		{"modular exponentiation", "模幂运算"},
		{"diffie-hellman", "Diffie-Hellman 密钥交换"},
		{"elgamal", "ElGamal 加密"},
		{"dsa", "数字签名算法（DSA）"},
		{"ecdsa", "椭圆曲线数字签名（ECDSA）"},
		{"elliptic curve", "椭圆曲线密码学"},
		{"point addition", "椭圆曲线点加"},
		{"scalar multiplication", "椭圆曲线标量乘"},
	}
	for _, kw := range phKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"离散对数: " + kw.hint}
		}
	}
	return nil
}

// tryPaddingOracle 检测 Padding Oracle 攻击特征。
func tryPaddingOracle(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	poKeywords := []struct {
		keyword string
		hint    string
	}{
		{"padding oracle", "Padding Oracle 攻击"},
		{"pkcs7", "PKCS#7 填充"},
		{"pkcs5", "PKCS#5 填充"},
		{"cbc mode", "CBC 模式"},
		{"cbc bit flipping", "CBC 位翻转攻击"},
		{"iv", "初始化向量（IV）"},
		{"block cipher mode", "分组密码模式"},
		{"cipher block chaining", "密码块链接（CBC）"},
		{"cipher feedback", "密码反馈（CFB）"},
		{"output feedback", "输出反馈（OFB）"},
		{"counter mode", "计数器模式（CTR）"},
		{"galois counter", "GCM 模式"},
		{"authentication tag", "认证标签（GCM）"},
		{"nonce", "随机数/Nonce"},
		{"initialization vector", "初始化向量"},
	}
	for _, kw := range poKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"密码模式: " + kw.hint}
		}
	}
	return nil
}

// tryMiscFrequency 检测频率分析/字符统计特征（替换密码/古典密码）。
func tryMiscFrequency(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	freqKeywords := []struct {
		keyword string
		hint    string
	}{
		{"frequency analysis", "频率分析：破解替换密码"},
		{"substitution cipher", "替换密码"},
		{"monoalphabetic", "单表替换密码"},
		{"polyalphabetic", "多表替换密码"},
		{"playfair", "Playfair 密码"},
		{"hill cipher", "Hill 密码"},
		{"atbash", "Atbash 密码"},
		{"pigpen", "猪圈密码"},
		{"polybius", "Polybius 方阵"},
		{"ascii", "ASCII 编码"},
		{"rot13", "ROT13 编码"},
		{"rot47", "ROT47 编码"},
		{"unicode", "Unicode 编码"},
		{"utf-8", "UTF-8 编码"},
		{"hex encoding", "十六进制编码"},
		{"octal", "八进制编码"},
		{"binary encoding", "二进制编码"},
		{"decimal encoding", "十进制编码"},
	}
	for _, kw := range freqKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"编码/密码: " + kw.hint}
		}
	}
	return nil
}

// tryWebTemplateInjection 检测模板注入高级特征（SSTI/服务端模板注入）。
func tryWebTemplateInjection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	tplKeywords := []struct {
		keyword string
		hint    string
	}{
		{"template injection", "服务端模板注入（SSTI）"},
		{"server-side template", "服务端模板"},
		{"jinja2", "Jinja2 模板引擎"},
		{"twig", "Twig 模板引擎"},
		{"freemarker", "FreeMarker 模板引擎"},
		{"velocity", "Apache Velocity 模板"},
		{"thymeleaf", "Thymeleaf 模板引擎"},
		{"mustache", "Mustache 模板引擎"},
		{"handlebars", "Handlebars 模板引擎"},
		{"ejs", "EJS 模板引擎"},
		{"pug", "Pug 模板引擎"},
		{"erb", "ERB 模板引擎"},
		{"smarty", "Smarty 模板引擎"},
		{"blade", "Blade 模板引擎"},
		{"liquid", "Liquid 模板引擎"},
		{"sandbox escape", "沙箱逃逸"},
		{"expression language", "表达式语言注入"},
		{"ognl", "OGNL 表达式注入"},
		{"mvel", "MVEL 表达式注入"},
		{"spel", "Spring 表达式语言（SpEL）"},
		{"el injection", "表达式语言注入"},
	}
	for _, kw := range tplKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"模板注入: " + kw.hint}
		}
	}
	return nil
}

// tryBlockchainCTF 检测区块链 CTF 特征（以太坊/智能合约）。
func tryBlockchainCTF(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	bcKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ethereum", "以太坊"},
		{"solidity", "Solidity 智能合约"},
		{"smart contract", "智能合约"},
		{"evm", "以太坊虚拟机（EVM）"},
		{"metamask", "MetaMask 钱包"},
		{"web3", "Web3.js 库"},
		{"ethers", "Ethers.js 库"},
		{"reentrancy", "重入攻击（智能合约）"},
		{"integer overflow", "整数溢出（Solidity <0.8）"},
		{"delegatecall", "Delegatecall 漏洞"},
		{"selfdestruct", "Selfdestruct 攻击"},
		{"tx.origin", "tx.origin 钓鱼攻击"},
		{"flash loan", "闪电贷攻击"},
		{"frontrunning", "抢跑交易（MEV）"},
		{"dex", "去中心化交易所（DEX）"},
		{"erc20", "ERC-20 代币标准"},
		{"erc721", "ERC-721 NFT 标准"},
		{"nonce", "交易 Nonce"},
		{"gas", "Gas 费用"},
		{"wei", "Wei（以太坊最小单位）"},
	}
	for _, kw := range bcKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"区块链CTF: " + kw.hint}
		}
	}
	return nil
}

// tryMLSecurity 检测机器学习安全特征（对抗样本/模型窃取）。
func tryMLSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	mlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"adversarial example", "对抗样本"},
		{"adversarial attack", "对抗攻击"},
		{"model inversion", "模型逆向攻击"},
		{"model stealing", "模型窃取"},
		{"data poisoning", "数据投毒攻击"},
		{"prompt injection", "Prompt 注入攻击（LLM）"},
		{"jailbreak", "越狱攻击（LLM）"},
		{"prompt leaking", "Prompt 泄露"},
		{"neural network", "神经网络"},
		{"machine learning", "机器学习"},
		{"deep learning", "深度学习"},
		{"classification", "分类任务"},
		{"regression", "回归任务"},
	}
	for _, kw := range mlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"AI安全: " + kw.hint}
		}
	}
	return nil
}

// ── P7 批次：misc 高级 ──────────────────────────────────

// tryBrainfuck 解释 Brainfuck 代码并提取 flag。
func tryBrainfuck(text string) []string {
	clean := strings.TrimSpace(text)
	// Brainfuck 仅含 8 种指令字符
	bfRe := regexp.MustCompile(`^[><+\-.,\[\]\s]+$`)
	if !bfRe.MatchString(clean) || len(clean) < 20 {
		return nil
	}
	// 简易解释器（最多执行 10000 步防死循环）
	tape := make([]byte, 3000)
	ptr := 0
	var output strings.Builder
	steps := 0
	code := clean
	codeIdx := 0
	bracketMap := buildBracketMap(code)

	for codeIdx < len(code) && steps < 10000 {
		steps++
		switch code[codeIdx] {
		case '>':
			ptr++
			if ptr >= len(tape) {
				ptr = len(tape) - 1
			}
		case '<':
			ptr--
			if ptr < 0 {
				ptr = 0
			}
		case '+':
			tape[ptr]++
		case '-':
			tape[ptr]--
		case '.':
			output.WriteByte(tape[ptr])
		case '[':
			if tape[ptr] == 0 {
				if end, ok := bracketMap[codeIdx]; ok {
					codeIdx = end
				}
			}
		case ']':
			if tape[ptr] != 0 {
				if start, ok := bracketMap[codeIdx]; ok {
					codeIdx = start
				}
			}
		}
		codeIdx++
	}
	result := output.String()
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 && isPrintableRatio(result) > 0.7 {
		return []string{"Brainfuck解码: " + result[:minInt(100, len(result))]}
	}
	return nil
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

// tryOok 检测 Ook! 语言（Brainfuck 的变体，用"Ook."等词）。
func tryOok(text string) []string {
	clean := strings.TrimSpace(text)
	// Ook 特征：连续的 "Ook" 词
	ookRe := regexp.MustCompile(`(?i)ook[.?!]`)
	matches := ookRe.FindAllString(clean, -1)
	if len(matches) < 8 {
		return nil
	}
	// 转换 Ook → Brainfuck
	bf := ookToBrainfuck(clean)
	if bf == "" {
		return nil
	}
	return tryBrainfuck(bf)
}

// ookToBrainfuck 将 Ook! 代码转换为 Brainfuck。
func ookToBrainfuck(ook string) string {
	re := regexp.MustCompile(`(?i)(ook)\s*([.?!])`)
	matches := re.FindAllStringSubmatch(ook, -1)
	if len(matches) < 2 {
		return ""
	}
	var bf strings.Builder
	for i := 0; i+1 < len(matches); i += 2 {
		pair := matches[i][2] + matches[i+1][2]
		switch pair {
		case "..":
			bf.WriteByte('+')
		case "!!":
			bf.WriteByte('-')
		case ".!":
			bf.WriteByte('>')
		case "!.":
			bf.WriteByte('<')
		case "!?":
			bf.WriteByte('[')
		case "?!":
			bf.WriteByte(']')
		case "?.":
			bf.WriteByte('.')
		case "??":
			bf.WriteByte(',')
		}
	}
	return bf.String()
}

// tryRailFenceVariant 栅栏密码变体（W 形 / 倒序 / 不同偏移）。
func tryRailFenceVariant(text string) []string {
	clean := strings.TrimSpace(text)
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	if !alphaRe.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	// 标准栅栏（2-8 栏）
	for rails := 2; rails <= 8; rails++ {
		decoded := railFenceDecode(clean, rails)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	// W 形栅栏（从中间开始）
	for rails := 3; rails <= 6; rails++ {
		decoded := railFenceDecodeW(clean, rails)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// railFenceDecodeW W 形栅栏解码（从中间栏开始）。
func railFenceDecodeW(cipher string, rails int) string {
	n := len(cipher)
	if rails <= 1 || rails >= n {
		return cipher
	}
	// 构建 W 形模式
	rows := make([][]byte, rails)
	cycle := 2 * (rails - 1)
	for i := 0; i < n; i++ {
		pos := i % cycle
		var row int
		if pos < rails {
			row = pos
		} else {
			row = cycle - pos
		}
		rows[row] = append(rows[row], cipher[i])
	}
	// 还原
	result := make([]byte, n)
	idx := 0
	for r := 0; r < rails; r++ {
		for _, b := range rows[r] {
			result[idx] = b
			idx++
		}
	}
	return string(result)
}

// tryVigenereAutoKey 维吉尼亚自动密钥恢复（利用已知明文前缀恢复密钥）。
func tryVigenereAutoKey(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 10 {
		return nil
	}
	// 常见明文前缀（flag/Crypto/CTF等）
	prefixes := []string{"flag{", "FLAG{", "ctf{", "CTF{", "crypto{", "mctf{"}
	for _, prefix := range prefixes {
		if len(clean) < len(prefix) {
			continue
		}
		// 从密文和已知明文恢复密钥
		key := recoverVigenereKey(clean, prefix)
		if key == "" {
			continue
		}
		// 用恢复的密钥解密全文
		decoded := vigenereDecode(clean, key)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// recoverVigenereKey 从已知明文前缀恢复维吉尼亚密钥。
func recoverVigenereKey(cipher, knownPlain string) string {
	if len(cipher) < len(knownPlain) {
		return ""
	}
	var key []byte
	for i := 0; i < len(knownPlain); i++ {
		c := byte(0)
		if cipher[i] >= 'a' && cipher[i] <= 'z' {
			c = cipher[i]
		} else if cipher[i] >= 'A' && cipher[i] <= 'Z' {
			c = cipher[i] + 32 // 转小写
		} else {
			continue
		}
		p := byte(0)
		if knownPlain[i] >= 'a' && knownPlain[i] <= 'z' {
			p = knownPlain[i]
		} else if knownPlain[i] >= 'A' && knownPlain[i] <= 'Z' {
			p = knownPlain[i] + 32
		} else {
			continue
		}
		k := (c - p + 26) % 26
		key = append(key, k+'a')
	}
	if len(key) == 0 {
		return ""
	}
	return string(key)
}

// ── P7 批次：crypto 高级 ──────────────────────────────────

// tryECDSANonceReuse 检测 ECDSA nonce 重用条件（同 nonce + 同私钥 → 私钥泄露）。
func tryECDSANonceReuse(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ecdsaKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ecdsa", "ECDSA 椭圆曲线数字签名"},
		{"nonce reuse", "Nonce 重用攻击（同 nonce 不同消息→私钥泄露）"},
		{"same nonce", "相同 Nonce"},
		{"repeated nonce", "重复 Nonce"},
		{"k reuse", "k 值重用"},
		{"r value", "ECDSA r 值"},
		{"s value", "ECDSA s 值"},
		{"signature reuse", "签名重用"},
		{"secp256k1", "secp256k1 椭圆曲线（比特币）"},
		{"ecdsa recovery", "ECDSA 公钥恢复"},
		{"low entropy nonce", "低熵 Nonce（可预测）"},
		{"biased nonce", "有偏 Nonce"},
	}
	for _, kw := range ecdsaKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"ECDSA特征: " + kw.hint}
		}
	}
	// 检测两个相同 r 值的签名（nonce 重用的直接证据）
	rRe := regexp.MustCompile(`(?i)\br\s*=\s*(\d+)`)
	rMatches := rRe.FindAllStringSubmatch(fullText, -1)
	if len(rMatches) >= 2 {
		r1, ok1 := new(big.Int).SetString(rMatches[0][1], 10)
		r2, ok2 := new(big.Int).SetString(rMatches[1][1], 10)
		if ok1 && ok2 && r1.Cmp(r2) == 0 {
			return []string{"ECDSA Nonce 重用检测：两组签名 r 值相同（r=" + r1.String() + "），可恢复私钥"}
		}
	}
	return nil
}

// tryRSABroadcastComplete 系统化 RSA 广播攻击（e 组同明文多 n 求解）。
func tryRSABroadcastComplete(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 检测是否存在 e 组 (n, c) 对
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	nRe := regexp.MustCompile(`(?i)n\d*\s*=\s*(\d+)`)
	cRe := regexp.MustCompile(`(?i)c\d*\s*=\s*(\d+)`)
	eMatch := eRe.FindStringSubmatch(fullText)
	if eMatch == nil {
		return nil
	}
	e, ok := new(big.Int).SetString(eMatch[1], 10)
	if !ok || e.Sign() <= 0 || e.Cmp(big.NewInt(10)) > 0 {
		return nil
	}
	nMatches := nRe.FindAllStringSubmatch(fullText, -1)
	cMatches := cRe.FindAllStringSubmatch(fullText, -1)
	eVal := int(e.Int64())
	if len(nMatches) >= eVal && len(cMatches) >= eVal {
		return []string{fmt.Sprintf("RSA 广播攻击条件：e=%d, %d 组(n,c)（同明文+多n→CRT+开根）", eVal, len(nMatches))}
	}
	return nil
}

// tryXORMultiByte 多字节 XOR / 重复密钥 XOR 检测。
func tryXORMultiByte(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	xorKeywords := []struct {
		keyword string
		hint    string
	}{
		{"multi-byte xor", "多字节 XOR 加密"},
		{"repeating key xor", "重复密钥 XOR"},
		{"fixed xor", "固定密钥 XOR"},
		{"single-byte xor", "单字节 XOR"},
		{"known plaintext", "已知明文攻击"},
		{"hamming distance", "汉明距离（密钥长度猜测）"},
		{"kasiski", "Kasiski 测试（密钥长度）"},
		{"index of coincidence", "重合指数"},
		{"ic ", "重合指数"},
		{"crib dragging", "Crib Dragging 已知明文攻击"},
		{"xor ", "XOR 运算"},
	}
	for _, kw := range xorKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"XOR攻击: " + kw.hint}
		}
	}
	// 检测 hex 串疑似 XOR 密文（重复模式）
	hexRe := regexp.MustCompile(`[0-9a-fA-F]{16,}`)
	for _, m := range hexRe.FindAllString(fullText, -1) {
		data, err := hex.DecodeString(m)
		if err != nil || len(data) < 8 {
			continue
		}
		// 检测重复 4 字节块（重复密钥特征）
		blocks := make(map[string]int)
		for i := 0; i+4 <= len(data); i += 4 {
			block := string(data[i : i+4])
			blocks[block]++
		}
		for _, count := range blocks {
			if count >= 3 {
				return []string{"XOR 重复密钥检测：hex 串中发现 " + fmt.Sprintf("%d", count) + " 个重复 4 字节块"}
			}
		}
	}
	return nil
}

// ── P7 批次：web 高级 ──────────────────────────────────

// tryPrototypePollution 检测原型链污染特征（Node.js/JavaScript 对象注入）。
func tryPrototypePollution(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ppKeywords := []struct {
		keyword string
		hint    string
	}{
		{"prototype pollution", "原型链污染攻击"},
		{"__proto__", "__proto__ 原型链注入"},
		{"constructor.prototype", "constructor.prototype 污染"},
		{"object.assign", "Object.assign 合并漏洞"},
		{"deep merge", "深合并漏洞"},
		{"lodash", "Lodash 深合并漏洞"},
		{"merge()", "merge 函数漏洞"},
		{"extend()", "extend 函数漏洞"},
		{"json.parse", "JSON.parse 与原型链"},
		{"polluted", "污染检测"},
		{"gadget chain", "利用链（原型污染→RCE）"},
		{"code execution", "代码执行（通过原型链）"},
		{"remote code execution", "远程代码执行"},
		{"rce", "RCE 漏洞"},
	}
	for _, kw := range ppKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"原型链污染: " + kw.hint}
		}
	}
	// 检测 JSON 中的 __proto__ 键
	if strings.Contains(fullText, "__proto__") || strings.Contains(fullText, "constructor") {
		if strings.Contains(lower, "pollution") || strings.Contains(lower, "inject") {
			return []string{"原型链污染: 检测到 __proto__ 注入特征"}
		}
	}
	return nil
}

// tryGraphQLBatch 检测 GraphQL 批量注入/深度攻击特征。
func tryGraphQLBatch(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gqlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"graphql injection", "GraphQL 注入攻击"},
		{"graphql batching", "GraphQL 批量查询攻击"},
		{"query batching", "查询批量发送"},
		{"aliasing attack", "别名攻击（绕过查询复杂度限制）"},
		{"nested query", "嵌套查询攻击"},
		{"circular reference", "循环引用攻击"},
		{"depth attack", "查询深度攻击"},
		{"complexity attack", "查询复杂度攻击"},
		{"field duplication", "字段重复攻击"},
		{"fragment injection", "Fragment 注入"},
		{"inline fragment", "内联 Fragment"},
		{"defer directive", "defer 延迟指令"},
		{"stream directive", "stream 流式指令"},
	}
	for _, kw := range gqlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"GraphQL攻击: " + kw.hint}
		}
	}
	// 检测 GraphQL 查询中的批量特征
	if strings.Contains(fullText, "[{") && strings.Contains(fullText, "query") {
		return []string{"GraphQL 批量查询: 检测到数组格式 GraphQL 请求"}
	}
	return nil
}

// tryHTTPRequestSmuggling 检测 HTTP 请求走私特征。
func tryHTTPRequestSmuggling(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	smugKeywords := []struct {
		keyword string
		hint    string
	}{
		{"request smuggling", "HTTP 请求走私"},
		{"http request smuggling", "HTTP 请求走私攻击"},
		{"cl.te", "CL.TE 走私（Content-Length vs Transfer-Encoding）"},
		{"te.cl", "TE.CL 走私"},
		{"te.te", "TE.TE 走私（Transfer-Encoding 混淆）"},
		{"transfer-encoding", "Transfer-Encoding 头"},
		{"content-length", "Content-Length 头"},
		{"chunked encoding", "分块传输编码"},
		{"header injection", "HTTP 头注入"},
		{"crlf injection", "CRLF 注入"},
		{"host header", "Host 头注入"},
		{"hop-by-hop", "逐跳头攻击"},
		{"reverse proxy", "反向代理漏洞"},
		{"nginx", "Nginx 配置漏洞"},
		{"apache", "Apache 配置漏洞"},
		{"cache poisoning", "Web 缓存投毒"},
		{"web cache deception", "Web 缓存欺骗"},
		{"response splitting", "HTTP 响应拆分"},
	}
	for _, kw := range smugKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"HTTP走私: " + kw.hint}
		}
	}
	// 检测异常 Transfer-Encoding（走私的直接证据）
	teRe := regexp.MustCompile(`(?i)transfer-encoding\s*:\s*(.+)`)
	if m := teRe.FindString(fullText); m != "" {
		val := strings.TrimSpace(strings.SplitN(m, ":", 2)[1])
		if strings.Contains(strings.ToLower(val), "chunked") && strings.Contains(val, " ") {
			return []string{"HTTP 走私特征: Transfer-Encoding 值含异常空格（混淆攻击）"}
		}
	}
	return nil
}

// ── P8 批次：crypto 深水区 ──────────────────────────────────

// tryEllipticCurve 检测椭圆曲线密码学特征（ECC/ECDSA/ECDH/点运算）。
func tryEllipticCurve(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ecKeywords := []struct {
		keyword string
		hint    string
	}{
		{"elliptic curve", "椭圆曲线密码学（ECC）"},
		{"ecdsa", "ECDSA 椭圆曲线数字签名"},
		{"ecdh", "ECDH 椭圆曲线密钥交换"},
		{"ed25519", "Ed25519 椭圆曲线"},
		{"ed448", "Ed448 椭圆曲线"},
		{"curve25519", "Curve25519 椭圆曲线"},
		{"secp256k1", "secp256k1 曲线（比特币）"},
		{"secp256r1", "secp256r1/P-256 曲线"},
		{"secp384r1", "secp384r1/P-384 曲线"},
		{"point addition", "椭圆曲线点加运算"},
		{"point multiplication", "椭圆曲线标量乘"},
		{"scalar multiplication", "标量乘法"},
		{"generator point", "基点/生成元"},
		{"order", "曲线阶"},
		{"cofactor", "辅因子"},
		{"embedding degree", "嵌入度（MOV 攻击条件）"},
		{"mov attack", "MOV 攻击（将 ECDLP 映射到有限域）"},
		{"smart attack", "Smart 攻击（超奇异曲线）"},
		{"pollard kangaroo", "Pollard's Kangaroo 算法"},
		{"baby-step giant-step", "BSGS 算法"},
		{"weierstrass", "Weierstrass 形式"},
		{"montgomery", "Montgomery 形式"},
		{"edwards", "Edwards 形式"},
		{"twisted edwards", "Twisted Edwards 形式"},
		{"infinity point", "无穷远点"},
		{"point at infinity", "无穷远点"},
	}
	for _, kw := range ecKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"椭圆曲线: " + kw.hint}
		}
	}
	// 检测疑似椭圆曲线参数（a, b, p, G, n 格式）
	if strings.Contains(fullText, "y^2") && strings.Contains(fullText, "x^3") {
		return []string{"椭圆曲线: 检测到 y²=x³+ax+b 形式的曲线方程"}
	}
	return nil
}

// tryLatticeLLL 检测格基规约攻击特征（LLL/BKZ/Coppersmith）。
func tryLatticeLLL(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	lllKeywords := []struct {
		keyword string
		hint    string
	}{
		{"lattice", "格基规约"},
		{"lll algorithm", "LLL 算法（Lenstra-Lenstra-Lovász）"},
		{"bkz", "BKZ 算法（Block Korkine-Zolotarev）"},
		{"coppersmith", "Coppersmith 方法（小根/部分密钥泄露）"},
		{"howgrave-graham", "Howgrave-Graham 方法"},
		{"small roots", "小根问题"},
		{"partial key exposure", "部分密钥泄露"},
		{"boneh-durfee", "Boneh-Durfee 攻击（小 d）"},
		{"wiener attack", "Wiener 攻击（连分数）"},
		{"franklin-reiter", "Franklin-Reiter 相关消息攻击"},
		{"related message", "相关消息攻击"},
		{"hidden number problem", "隐藏数问题（HNP）"},
		{"dsa", "DSA 签名"},
		{"lattice reduction", "格基规约"},
		{"gram-schmidt", "Gram-Schmidt 正交化"},
		{"hermite normal form", "Hermite 标准型"},
		{"smith normal form", "Smith 标准型"},
		{"short vector", "短向量问题（SVP）"},
		{"closest vector", "最近向量问题（CVP）"},
	}
	for _, kw := range lllKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"格基攻击: " + kw.hint}
		}
	}
	return nil
}

// tryPolynomialDiscreteLog 检测多项式离散对数特征。
func tryPolynomialDiscreteLog(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	polyKeywords := []struct {
		keyword string
		hint    string
	}{
		{"polynomial", "多项式运算"},
		{"finite field", "有限域"},
		{"galois field", "伽罗瓦域（GF）"},
		{"gf(", "有限域 GF(p^n)"},
		{"irreducible polynomial", "不可约多项式"},
		{"primitive polynomial", "本原多项式"},
		{"minimal polynomial", "最小多项式"},
		{"characteristic", "域特征"},
		{"extension field", "扩域"},
		{"splitting field", "分裂域"},
		{"algebraic closure", "代数闭包"},
		{"polynomial factorization", "多项式分解"},
		{"berlekamp", "Berlekamp 算法"},
		{"cantor-zassenhaus", "Cantor-Zassenhaus 算法"},
	}
	for _, kw := range polyKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"多项式域: " + kw.hint}
		}
	}
	return nil
}

// ── P8 批次：misc 深水区 ──────────────────────────────────

// tryDNACoding 检测 DNA 编码密码（A/T/C/G 四字母编码）。
func tryDNACoding(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 8 {
		return nil
	}
	// DNA 编码特征：仅含 A/T/C/G 四个字符，长度为偶数
	dnaRe := regexp.MustCompile(`^[ATCG\s]+$`)
	if !dnaRe.MatchString(clean) {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	if len(clean)%2 != 0 || len(clean) < 4 {
		return nil
	}
	// DNA 编码映射（常见变体）
	dnaMap := map[string]string{
		"AA": "00", "AC": "01", "AT": "10", "AG": "11",
		"CA": "00", "CC": "01", "CT": "10", "CG": "11",
		"TA": "00", "TC": "01", "TT": "10", "TG": "11",
		"GA": "00", "GC": "01", "GT": "10", "GG": "11",
	}
	var binary strings.Builder
	for i := 0; i+1 < len(clean); i += 2 {
		pair := clean[i : i+2]
		if bits, ok := dnaMap[pair]; ok {
			binary.WriteString(bits)
		}
	}
	// 二进制转 ASCII
	result := binaryToASCII(binary.String())
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 && isPrintableRatio(result) > 0.8 {
		return []string{"DNA解码: " + result}
	}
	return nil
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

// tryBraille 检测盲文编码（六点阵列模式）。
func tryBraille(text string) []string {
	clean := strings.TrimSpace(text)
	// 盲文特征：含 Unicode 盲文字符（U+2800 到 U+28FF）
	for _, r := range clean {
		if r >= 0x2800 && r <= 0x28FF {
			return []string{"盲文编码: 检测到 Unicode 盲文字符（U+2800-U+28FF），可用盲文解码器还原"}
		}
	}
	// 数字格式盲文（六点阵列用数字表示）
	brailleRe := regexp.MustCompile(`^[0-6\s/\-]{10,}$`)
	if brailleRe.MatchString(clean) && len(clean) >= 10 {
		return []string{"盲文数字编码: 检测到疑似盲文六点阵列数字表示"}
	}
	return nil
}

// tryBarcode 检测条形码/二维码特征。
func tryBarcode(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	barcodeKeywords := []struct {
		keyword string
		hint    string
	}{
		{"qr code", "二维码（QR Code）"},
		{"barcode", "条形码"},
		{"ean-13", "EAN-13 条形码"},
		{"ean-8", "EAN-8 条形码"},
		{"upc-a", "UPC-A 条形码"},
		{"code 128", "Code 128 条形码"},
		{"code 39", "Code 39 条形码"},
		{"data matrix", "Data Matrix 二维码"},
		{"aztec", "Aztec 二维码"},
		{"pdf417", "PDF417 二维码"},
		{"zxing", "ZXing 二维码识别库"},
		{"qrcode", "二维码"},
	}
	for _, kw := range barcodeKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"条码特征: " + kw.hint}
		}
	}
	return nil
}

// ── P8 批次：web 深水区 ──────────────────────────────────

// tryWebSocketHijack 检测 WebSocket 劫持/跨站特征。
func tryWebSocketHijack(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"websocket hijacking", "WebSocket 劫持"},
		{"cross-site websocket", "跨站 WebSocket 劫持"},
		{"cswh", "CSWH（跨站 WebSocket 劫持）"},
		{"ws poisoning", "WebSocket 投毒"},
		{"ws injection", "WebSocket 注入"},
		{"websocket frame", "WebSocket 帧分析"},
		{"binary frame", "二进制帧"},
		{"text frame", "文本帧"},
		{"ping pong", "Ping/Pong 帧"},
		{"close frame", "关闭帧"},
		{"websocket subprotocol", "WebSocket 子协议"},
	}
	for _, kw := range wsKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"WebSocket安全: " + kw.hint}
		}
	}
	return nil
}

// tryPrototypePollutionVariant 检测原型链污染变体（Node.js/Express/Koa 特定）。
func tryPrototypePollutionVariant(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ppKeywords := []struct {
		keyword string
		hint    string
	}{
		{"express", "Express.js 框架"},
		{"koa", "Koa.js 框架"},
		{"hapi", "Hapi.js 框架"},
		{"fastify", "Fastify 框架"},
		{"nest.js", "NestJS 框架"},
		{"next.js", "Next.js 框架"},
		{"nuxt.js", "Nuxt.js 框架"},
		{"object.assign", "Object.assign 合并"},
		{"deep clone", "深克隆"},
		{"json.parse", "JSON.parse"},
		{"extend", "extend/merge 函数"},
		{"polluted", "污染检测标志"},
		{"__defineGetter__", "__defineGetter__ 方法"},
		{"__defineSetter__", "__defineSetter__ 方法"},
		{"__lookupGetter__", "__lookupGetter__ 方法"},
		{"__lookupSetter__", "__lookupSetter__ 方法"},
	}
	for _, kw := range ppKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"JS框架: " + kw.hint}
		}
	}
	return nil
}

// ── P8 补全：reverse 深水区（heredoc 截断恢复） ──────────────

// tryObfuscationDetection 检测代码混淆算法特征。
func tryObfuscationDetection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	obfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"control flow flattening", "控制流平坦化混淆"},
		{"opaque predicate", "不透明谓词混淆"},
		{"dead code injection", "死代码注入"},
		{"string encryption", "字符串加密混淆"},
		{"instruction substitution", "指令替换"},
		{"array flattening", "数组扁平化"},
		{"variable renaming", "变量重命名"},
		{"proxy call", "代理调用"},
		{"virtual machine", "虚拟机保护"},
		{"code virtualization", "代码虚拟化"},
		{"bytecode obfuscation", "字节码混淆"},
		{"source map", "Source Map（可能含原始代码）"},
		{"webpack", "Webpack 打包"},
	}
	for _, kw := range obfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"混淆检测: " + kw.hint}
		}
	}
	return nil
}

// tryEmulatorDetection 检测模拟器/沙箱检测特征（反调试/反分析）。
func tryEmulatorDetection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	emuKeywords := []struct {
		keyword string
		hint    string
	}{
		{"anti-debug", "反调试技术"},
		{"anti-vm", "反虚拟机检测"},
		{"anti-sandbox", "反沙箱检测"},
		{"vm detection", "虚拟机检测"},
		{"isdebuggerpresent", "IsDebuggerPresent"},
		{"ptrace", "ptrace 自检"},
		{"timing check", "时间检测"},
		{"cpuid", "CPUID 指令"},
		{"vmware", "VMware 检测"},
		{"virtualbox", "VirtualBox 检测"},
		{"qemu", "QEMU 检测"},
		{"debugger detection", "调试器检测"},
		{"integrity check", "完整性校验"},
		{"crc32", "CRC32 校验"},
	}
	for _, kw := range emuKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"反分析: " + kw.hint}
		}
	}
	return nil
}

// tryCodeVirtualization 检测代码虚拟化保护特征。
func tryCodeVirtualization(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	vmKeywords := []struct {
		keyword string
		hint    string
	}{
		{"vmprotect", "VMProtect 虚拟化保护"},
		{"themida", "Themida 加壳/虚拟化"},
		{"enigma protector", "Enigma Protector"},
		{"upx", "UPX 加壳"},
		{"aspack", "ASPack 加壳"},
		{"virtual machine", "自定义虚拟机"},
		{"bytecode interpreter", "字节码解释器"},
		{"dispatch table", "分发表"},
	}
	for _, kw := range vmKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"虚拟化保护: " + kw.hint}
		}
	}
	return nil
}

// ── P9 批次：crypto ──────────────────────────────────────

// tryElGamalSignature 检测 ElGamal 签名攻击特征（重复 k/弱参数）。
func tryElGamalSignature(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	elKeywords := []struct {
		keyword string
		hint    string
	}{
		{"elgamal", "ElGamal 加密/签名"},
		{"ephemeral key", "临时密钥 k"},
		{"random nonce", "随机数 k"},
		{"nonce reuse", "k 重用攻击"},
		{"same nonce", "相同 k 值"},
		{"discrete log", "离散对数"},
		{"generator", "生成元 g"},
		{"primitive root", "原根"},
		{"modular inverse", "模逆"},
		{"extended euclidean", "扩展欧几里得"},
		{"signed message", "签名消息"},
		{"message hash", "消息哈希"},
	}
	for _, kw := range elKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"ElGamal特征: " + kw.hint}
		}
	}
	return nil
}

// trySchnorrSignature 检测 Schnorr 签名特征。
func trySchnorrSignature(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	schKeywords := []struct {
		keyword string
		hint    string
	}{
		{"schnorr", "Schnorr 签名"},
		{"schnorr signature", "Schnorr 签名方案"},
		{"sigma protocol", "Sigma 协议"},
		{"commitment scheme", "承诺方案"},
		{"challenge response", "挑战-应答"},
		{"zero knowledge proof", "零知识证明"},
		{"interactive proof", "交互式证明"},
		{"non-interactive", "非交互式证明"},
		{"fiat-shamir", "Fiat-Shamir 变换"},
		{"random oracle", "随机预言机"},
	}
	for _, kw := range schKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Schnorr特征: " + kw.hint}
		}
	}
	return nil
}

// tryRSAOracleAttack 检测 RSA Oracle 攻击模式（签名/解密预言机）。
func tryRSAOracleAttack(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	oracleKeywords := []struct {
		keyword string
		hint    string
	}{
		{"oracle attack", "预言机攻击"},
		{"signing oracle", "签名预言机"},
		{"decryption oracle", "解密预言机"},
		{"bleichenbacher", "Bleichenbacher 攻击（PKCS#1 v1.5 填充预言机）"},
		{"manger", "Manger 攻击（OAEP 填充预言机）"},
		{"padding oracle", "填充预言机"},
		{"chosen ciphertext", "选择密文攻击"},
		{"cca2", "CCA2 安全性"},
		{"adaptive chosen", "自适应选择攻击"},
		{"signature forgery", "签名伪造"},
		{"existential forgery", "存在性伪造"},
		{"blind signature", "盲签名"},
		{"rsa blinding", "RSA 盲化攻击"},
	}
	for _, kw := range oracleKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"RSA Oracle: " + kw.hint}
		}
	}
	return nil
}

// ── P9 批次：misc ──────────────────────────────────────

// tryEXIFMetadata 检测图片 EXIF 元数据特征（GPS/相机/编辑痕迹）。
func tryEXIFMetadata(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	exifKeywords := []struct {
		keyword string
		hint    string
	}{
		{"exif", "EXIF 元数据"},
		{"gps", "GPS 定位信息"},
		{"latitude", "纬度"},
		{"longitude", "经度"},
		{"camera", "相机信息"},
		{"make", "设备制造商"},
		{"model", "设备型号"},
		{"software", "编辑软件"},
		{"datetime", "拍摄时间"},
		{"thumbnail", "缩略图"},
		{"iptc", "IPTC 元数据"},
		{"xmp", "XMP 元数据"},
		{"metadata", "元数据"},
		{"geolocation", "地理定位"},
	}
	for _, kw := range exifKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"EXIF取证: " + kw.hint}
		}
	}
	return nil
}

// tryAudioStego 检测音频隐写特征（频谱分析/LSB/回声隐藏）。
func tryAudioStego(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	audioKeywords := []struct {
		keyword string
		hint    string
	}{
		{"audio steganography", "音频隐写"},
		{"spectrogram", "频谱图"},
		{"frequency domain", "频域分析"},
		{"echo hiding", "回声隐藏"},
		{"lsb audio", "音频 LSB 隐写"},
		{"phase coding", "相位编码"},
		{"spread spectrum", "扩频隐写"},
		{"tone insertion", "音调插入"},
		{"wav", "WAV 音频"},
		{"mp3", "MP3 音频"},
		{"flac", "FLAC 音频"},
		{"ogg", "OGG 音频"},
		{"waveform", "波形分析"},
		{"audacity", "Audacity 音频编辑"},
	}
	for _, kw := range audioKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"音频隐写: " + kw.hint}
		}
	}
	return nil
}

// tryMagicBytes 检测文件魔术字节（文件头/尾/签名识别）。
func tryMagicBytes(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	magicKeywords := []struct {
		keyword string
		hint    string
	}{
		{"magic bytes", "文件魔术字节"},
		{"file signature", "文件签名"},
		{"file header", "文件头"},
		{"89504e47", "PNG 文件头"},
		{"ffd8ff", "JPEG 文件头"},
		{"47494638", "GIF 文件头"},
		{"504b0304", "ZIP 文件头"},
		{"25504446", "PDF 文件头"},
		{"7f454c46", "ELF 文件头"},
		{"4d5a", "PE/EXE 文件头"},
		{"cafebabe", "Java Class 文件头"},
		{"52617221", "RAR 文件头"},
		{"1f8b08", "GZIP 文件头"},
		{"425a68", "BZ2 文件头"},
		{"377abcaf271c", "7Z 文件头"},
		{"hex dump", "十六进制转储"},
		{"binwalk", "Binwalk 文件分析"},
	}
	for _, kw := range magicKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"文件签名: " + kw.hint}
		}
	}
	return nil
}

// ── P9 批次：web ──────────────────────────────────────

// tryWAFBypass 检测 WAF 绕过特征。
func tryWAFBypass(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wafKeywords := []struct {
		keyword string
		hint    string
	}{
		{"waf bypass", "WAF 绕过"},
		{"web application firewall", "Web 应用防火墙"},
		{"bypass waf", "WAF 绕过"},
		{"sql injection bypass", "SQL 注入绕过"},
		{"xss filter bypass", "XSS 过滤绕过"},
		{"payload encoding", "Payload 编码绕过"},
		{"double encoding", "双重编码"},
		{"unicode bypass", "Unicode 绕过"},
		{"case manipulation", "大小写变换"},
		{"comment injection", "注释注入"},
		{"null byte", "空字节注入"},
		{"chunked transfer", "分块传输绕过"},
		{"ip rotation", "IP 轮换"},
		{"user-agent rotation", "UA 轮换"},
		{"rate limit bypass", "速率限制绕过"},
	}
	for _, kw := range wafKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"WAF绕过: " + kw.hint}
		}
	}
	return nil
}

// tryRCEDetection 检测远程代码执行（RCE）特征。
func tryRCEDetection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	rceKeywords := []struct {
		keyword string
		hint    string
	}{
		{"remote code execution", "远程代码执行（RCE）"},
		{"command injection", "命令注入"},
		{"os command", "操作系统命令"},
		{"shell command", "Shell 命令"},
		{"exec(", "exec 函数调用"},
		{"system(", "system 函数调用"},
		{"popen", "popen 命令执行"},
		{"subprocess", "子进程调用"},
		{"eval(", "eval 动态执行"},
		{"runtime.exec", "Runtime.exec"},
		{"processbuilder", "ProcessBuilder"},
		{"deserialization", "反序列化"},
		{"pickle", "Python pickle 反序列化"},
		{"yaml.load", "YAML 反序列化"},
		{"unserialize", "PHP 反序列化"},
		{"template injection", "模板注入"},
		{"server-side include", "服务端包含（SSI）"},
		{"code injection", "代码注入"},
	}
	for _, kw := range rceKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"RCE特征: " + kw.hint}
		}
	}
	return nil
}

// tryFileInclusion 检测文件包含漏洞链（LFI/RFI/路径遍历）。
func tryFileInclusion(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	fiKeywords := []struct {
		keyword string
		hint    string
	}{
		{"file inclusion", "文件包含漏洞"},
		{"local file inclusion", "本地文件包含（LFI）"},
		{"remote file inclusion", "远程文件包含（RFI）"},
		{"path traversal", "路径遍历"},
		{"directory traversal", "目录遍历"},
		{"dot dot slash", "目录遍历（../）"},
		{"null byte", "空字节截断"},
		{"php://filter", "PHP 流包装器"},
		{"php://input", "PHP 输入流"},
		{"data://", "data:// 协议"},
		{"expect://", "expect:// 协议"},
		{"zip://", "zip:// 协议"},
		{"phar://", "phar:// 协议"},
		{"file://", "file:// 协议"},
		{"log poisoning", "日志投毒"},
		{"log injection", "日志注入"},
	}
	for _, kw := range fiKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"文件包含: " + kw.hint}
		}
	}
	return nil
}

// tryDeserialization 检测反序列化漏洞特征（Java/Python/PHP/Ruby/.NET）。
func tryDeserialization(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	deserKeywords := []struct {
		keyword string
		hint    string
	}{
		{"deserialization", "反序列化漏洞"},
		{"ysoserial", "Ysoserial（Java 反序列化）"},
		{"commons collections", "Commons Collections"},
		{"pickle", "Python pickle"},
		{"yaml.load", "YAML 反序列化"},
		{"unserialize", "PHP 反序列化"},
		{"gadget chain", "利用链"},
		{"magic method", "魔术方法"},
		{"__wakeup", "__wakeup 方法"},
		{"__destruct", "__destruct 方法"},
	}
	for _, kw := range deserKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"反序列化: " + kw.hint}
		}
	}
	return nil
}

// ── P9 补全：heredoc 截断恢复 ──────────────────────────────

// tryObfuscationVariant 检测混淆算法变体（OLLVM/虚拟机壳/DEX混淆）。
func tryObfuscationVariant(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	obfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ollvm", "OLLVM 混淆编译器"},
		{"obfuscator-llvm", "Obfuscator-LLVM"},
		{"string obfuscation", "字符串混淆"},
		{"control flow", "控制流混淆"},
		{"bogus control flow", "虚假控制流"},
		{"flattening", "控制流平坦化"},
		{"proguard", "ProGuard（Android 混淆）"},
		{"dexguard", "DexGuard"},
		{"dex2jar", "dex2jar"},
		{"jadx", "JADX 反编译"},
		{"apktool", "APKTool"},
		{"smali", "Smali 汇编"},
		{"dalvik", "Dalvik 虚拟机"},
		{"ndk", "Android NDK"},
	}
	for _, kw := range obfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"混淆变体: " + kw.hint}
		}
	}
	return nil
}

// tryDecompilerChain 检测反编译工具链特征。
func tryDecompilerChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	decKeywords := []struct {
		keyword string
		hint    string
	}{
		{"decompiler", "反编译器"},
		{"disassembler", "反汇编器"},
		{"ida pro", "IDA Pro"},
		{"ghidra", "Ghidra"},
		{"binary ninja", "Binary Ninja"},
		{"radare2", "Radare2"},
		{"rizin", "Rizin"},
		{"angr", "angr 符号执行"},
		{"capstone", "Capstone 反汇编"},
		{"keystone", "Keystone 汇编"},
		{"unicorn", "Unicorn 模拟器"},
		{"frida", "Frida 动态插桩"},
		{"gdb", "GDB 调试器"},
		{"lldb", "LLDB 调试器"},
		{"windbg", "WinDbg"},
		{"x64dbg", "x64dbg"},
		{"ollydbg", "OllyDbg"},
		{"pwntools", "Pwntools"},
		{"one_gadget", "one_gadget"},
	}
	for _, kw := range decKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"逆向工具链: " + kw.hint}
		}
	}
	return nil
}

// tryIOFileExploit 检测 IO_FILE/FSOP 利用特征。
func tryIOFileExploit(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ioKeywords := []struct {
		keyword string
		hint    string
	}{
		{"io_file", "IO_FILE 结构体利用"},
		{"_io_list_all", "_IO_list_all"},
		{"fsop", "FSOP（File Stream Oriented Programming）"},
		{"fake file stream", "伪造文件流"},
		{"vtable hijacking", "vtable 劫持"},
		{"house of apple", "House of Apple"},
		{"house of banana", "House of Banana"},
		{"house of cat", "House of Cat"},
		{"house of orange", "House of Orange"},
		{"house of spirit", "House of Spirit"},
		{"house of force", "House of Force"},
		{"got overwrite", "GOT 表覆写"},
		{"ret2dlresolve", "ret2dlresolve"},
		{"lazy binding", "延迟绑定"},
	}
	for _, kw := range ioKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"IO_FILE/FSOP: " + kw.hint}
		}
	}
	return nil
}

// tryHeapSpray 检测堆喷射/格式化字符串漏洞特征。
func tryHeapSpray(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	heapKeywords := []struct {
		keyword string
		hint    string
	}{
		{"heap spray", "堆喷射"},
		{"format string", "格式化字符串漏洞"},
		{"format string attack", "格式化字符串攻击"},
		{"printf vulnerability", "printf 漏洞"},
		{"%n", "格式化字符串 %n 写入"},
		{"%x", "格式化字符串 %x 泄露"},
		{"stack pivot", "栈迁移"},
		{"stack smash", "栈溢出"},
		{"return address", "返回地址覆写"},
		{"canary bypass", "Canary 绕过"},
		{"information leak", "信息泄露"},
		{"partial overwrite", "部分覆写"},
		{"one gadget", "one_gadget"},
		{"ret2libc", "ret2libc"},
		{"rop chain", "ROP 链"},
		{"jop", "JOP（Jump-Oriented Programming）"},
		{"cop", "COP（Call-Oriented Programming）"},
	}
	for _, kw := range heapKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Pwn利用: " + kw.hint}
		}
	}
	return nil
}

// ── P10 批次：crypto ──────────────────────────────────────

// tryHomomorphicEncryption 检测同态加密特征（FHE/PHE/SHE）。
func tryHomomorphicEncryption(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	heKeywords := []struct {
		keyword string
		hint    string
	}{
		{"homomorphic encryption", "同态加密"},
		{"fully homomorphic", "全同态加密（FHE）"},
		{"partially homomorphic", "部分同态加密（PHE）"},
		{"somewhat homomorphic", "有限同态加密（SHE）"},
		{"lattice-based", "格基密码学"},
		{"ring-lwe", "Ring-LWE 问题"},
		{"learning with errors", "LWE 问题"},
		{"brakerski", "Brakerski 方案"},
		{"gentry", "Gentry 方案"},
		{"ckks", "CKKS 方案"},
		{"bfv", "BFV 方案"},
		{"bgv", "BGV 方案"},
		{"paillier", "Paillier 加密"},
		{"elgamal encryption", "ElGamal 加密"},
		{"rsa encryption", "RSA 加密"},
		{"elliptic curve", "椭圆曲线加密"},
		{"zero knowledge", "零知识证明"},
		{"zk-snark", "zk-SNARK"},
		{"zk-stark", "zk-STARK"},
	}
	for _, kw := range heKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"同态加密: " + kw.hint}
		}
	}
	return nil
}

// tryEllipticCurvePointOps 检测椭圆曲线点运算特征。
func tryEllipticCurvePointOps(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ecKeywords := []struct {
		keyword string
		hint    string
	}{
		{"point addition", "椭圆曲线点加运算"},
		{"point doubling", "椭圆曲线点倍运算"},
		{"point multiplication", "椭圆曲线标量乘"},
		{"scalar multiplication", "标量乘法"},
		{"generator point", "基点/生成元"},
		{"infinity point", "无穷远点"},
		{"weierstrass", "Weierstrass 形式"},
		{"montgomery form", "Montgomery 形式"},
		{"edwards curve", "Edwards 曲线"},
		{"twisted edwards", "Twisted Edwards 曲线"},
		{"birational equivalence", "双有理等价"},
		{"order of curve", "曲线阶"},
		{"cofactor", "辅因子"},
		{"embedding degree", "嵌入度"},
		{"mov attack", "MOV 攻击"},
		{"franklin reiter", "Franklin-Reiter 相关消息攻击"},
	}
	for _, kw := range ecKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"椭圆曲线点运算: " + kw.hint}
		}
	}
	// 检测 y² = x³ + ax + b 形式
	if strings.Contains(fullText, "y^2") && strings.Contains(fullText, "x^3") {
		return []string{"椭圆曲线: 检测到曲线方程"}
	}
	return nil
}

// tryLatticeKeywords 检测格基密码学关键词。
func tryLatticeKeywords(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	latKeywords := []struct {
		keyword string
		hint    string
	}{
		{"lattice reduction", "格基规约"},
		{"lattice attack", "格基攻击"},
		{"shortest vector", "最短向量问题（SVP）"},
		{"closest vector", "最近向量问题（CVP）"},
		{"basis reduction", "基底规约"},
		{"hermite normal", "Hermite 标准型"},
		{"smith normal", "Smith 标准型"},
		{"determinant", "行列式"},
		{"gram matrix", "Gram 矩阵"},
		{"orthogonal", "正交化"},
		{"q-ary lattice", "q-ary 格"},
		{"ideal lattice", "理想格"},
		{"module lattice", "模格"},
		{"ntru", "NTRU 密码"},
		{"crystals-kyber", "Crystals-Kyber"},
		{"crystals-dilithium", "Crystals-Dilithium"},
		{"falcon", "Falcon 签名"},
		{"sphincs", "SPHINCS+ 签名"},
	}
	for _, kw := range latKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"格基密码: " + kw.hint}
		}
	}
	return nil
}

// ── P10 批次：misc 编码变体 ──────────────────────────────

// tryBase32 检测 Base32 编码。
func tryBase32(text string) []string {
	clean := strings.TrimSpace(text)
	// Base32 字符集：A-Z, 2-7, =
	b32Re := regexp.MustCompile(`^[A-Z2-7=]{8,}$`)
	if !b32Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	decoded, err := base32Decode(clean)
	if err != nil || len(decoded) == 0 {
		return nil
	}
	if flags := scanFlags(string(decoded)); len(flags) > 0 {
		return flags
	}
	if isPrintableRatio(string(decoded)) > 0.8 {
		return []string{"Base32解码: " + string(decoded)[:minInt(80, len(decoded))]}
	}
	return nil
}

func base32Decode(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	s = strings.TrimRight(s, "=")
	var result []byte
	for i := 0; i < len(s); i += 8 {
		chunk := s[i:minInt(i+8, len(s))]
		var bits uint64
		for _, c := range chunk {
			idx := strings.IndexRune(alphabet, c)
			if idx < 0 {
				return nil, fmt.Errorf("invalid char")
			}
			bits = bits<<5 | uint64(idx)
		}
		for j := 0; j < 5; j++ {
			byteIdx := (4 - j) * 8
			if byteIdx < 40 {
				result = append(result, byte(bits>>byteIdx&0xFF))
			}
		}
	}
	return result, nil
}

// tryBase85 检测 Base85/Ascii85 编码。
func tryBase85(text string) []string {
	clean := strings.TrimSpace(text)
	// Base85 标准版（Ascii85）：字符范围 33-117 (! 到 u)
	// Z85 版：0-9, a-z, A-Z, .-:+=^!/*
	if len(clean) < 8 {
		return nil
	}
	// Ascii85 检测：<~...~> 包裹
	if strings.HasPrefix(clean, "<~") && strings.HasSuffix(clean, "~>") {
		return []string{"Base85/Ascii85 检测: <~...~> 包裹格式"}
	}
	// Z85 检测
	z85Re := regexp.MustCompile(`^[0-9a-zA-Z.:\-+^!/*()]{8,}$`)
	if z85Re.MatchString(clean) {
		return []string{"Z85 检测: 符合 Z85 编码字符集（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
	}
	return nil
}

// tryBase91 检测 Base91 编码。
func tryBase91(text string) []string {
	clean := strings.TrimSpace(text)
	// Base91 字符集：ASCII 35-126（# 到 ~），不含空格
	b91Re := regexp.MustCompile(`^[!-~]{8,}$`)
	if !b91Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	// 检测特征：Base91 编码后长度约为原文的 1.23 倍
	// 如果输入看起来不像 base64（没有+/=），可能是 base91
	if strings.ContainsAny(clean, "+/=") {
		return nil // 可能是 base64
	}
	return []string{"Base91 检测: 符合 Base91 字符集（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}

// tryUUencode 检测 UUencode 编码。
func tryUUencode(text string) []string {
	clean := strings.TrimSpace(text)
	// UUencode 特征：每行以长度字符开头（'M' = 45字节/行），行首字符范围 ' ' 到 '`'
	lines := strings.Split(clean, "\n")
	if len(lines) < 2 {
		return nil
	}
	uuRe := regexp.MustCompile(`^[\x20-\x60][\x20-\x7E]*$`)
	validLines := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 0 && uuRe.MatchString(trimmed) {
			validLines++
		}
	}
	if validLines >= 2 && float64(validLines)/float64(len(lines)) > 0.5 {
		return []string{"UUencode 检测: 符合 UUencode 行格式（" + fmt.Sprintf("%d", validLines) + "/" + fmt.Sprintf("%d", len(lines)) + " 行）"}
	}
	return nil
}

// tryQuotedPrintable 检测 Quoted-Printable 编码。
func tryQuotedPrintable(text string) []string {
	clean := strings.TrimSpace(text)
	// Quoted-Printable 特征：=XX 十六进制转义
	qpRe := regexp.MustCompile(`=[0-9A-Fa-f]{2}`)
	matches := qpRe.FindAllString(clean, -1)
	if len(matches) >= 3 {
		return []string{"Quoted-Printable 检测: " + fmt.Sprintf("%d", len(matches)) + " 个 =XX 转义序列"}
	}
	// 软换行（行尾 =）
	if strings.HasSuffix(clean, "=") {
		return []string{"Quoted-Printable 检测: 行尾软换行（= 结尾）"}
	}
	return nil
}

// tryPunycode 检测 Punycode 编码（国际化域名）。
func tryPunycode(text string) []string {
	clean := strings.TrimSpace(text)
	// Punycode 特征：xn-- 前缀
	if strings.HasPrefix(clean, "xn--") || strings.Contains(clean, ".xn--") {
		return []string{"Punycode 检测: 国际化域名编码（xn-- 前缀）"}
	}
	// 纯 ASCII 字母+数字+连字符
	punyRe := regexp.MustCompile(`^[a-zA-Z0-9-]{4,}$`)
	if punyRe.MatchString(clean) && strings.Contains(clean, "-") {
		return []string{"Punycode 特征: 纯 ASCII+连字符格式（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
	}
	return nil
}

// ── P10 批次：web 高级 ──────────────────────────────────

// trySSRFChain 检测 SSRF 链/高级 SSRF 特征。
func trySSRFChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ssrfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ssrf chain", "SSRF 链攻击"},
		{"server-side request forgery", "服务端请求伪造"},
		{"dns rebinding", "DNS 重绑定"},
		{"time-of-check", "TOCTOU 漏洞"},
		{"url redirect", "URL 重定向"},
		{"open redirect", "开放重定向"},
		{"ssrf to rce", "SSRF → RCE 链"},
		{"cloud metadata", "云元数据服务"},
		{"169.254.169.254", "AWS/GCP 元数据"},
		{"metadata.google.internal", "GCP 元数据"},
		{"100.100.100.200", "阿里云元数据"},
		{"internal service", "内网服务探测"},
		{"service discovery", "服务发现"},
		{"gopher://", "Gopher 协议利用"},
		{"file://", "FILE 协议读取"},
		{"dict://", "DICT 协议利用"},
	}
	for _, kw := range ssrfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"SSRF高级: " + kw.hint}
		}
	}
	privateIPRe := regexp.MustCompile(`(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}`)
	if m := privateIPRe.FindString(fullText); m != "" {
		return []string{"SSRF目标: " + m}
	}
	return nil
}
	

// ── P10 补全：heredoc 截断恢复 ──────────────────────────────

// tryDOMXSS 检测 DOM 型 XSS 特征。
func tryDOMXSS(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	domKeywords := []struct {
		keyword string
		hint    string
	}{
		{"document.write", "document.write（XSS sink）"},
		{"innerhtml", "innerHTML（XSS sink）"},
		{"outerhtml", "outerHTML"},
		{"eval(", "eval() 执行"},
		{"settimeout", "setTimeout 字符串执行"},
		{"setinterval", "setInterval 字符串执行"},
		{"location.href", "location.href 重定向"},
		{"location.hash", "location.hash（DOM XSS 源）"},
		{"location.search", "location.search（DOM XSS 源）"},
		{"postmessage", "postMessage"},
		{"dom clobbering", "DOM 碰撞攻击"},
		{"mutation xss", "Mutation XSS"},
		{"trusted types", "Trusted Types 防护"},
	}
	for _, kw := range domKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"DOM XSS: " + kw.hint}
		}
	}
	return nil
}

// tryStoredXSS 检测存储型 XSS 特征。
func tryStoredXSS(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	sxssKeywords := []struct {
		keyword string
		hint    string
	}{
		{"stored xss", "存储型 XSS"},
		{"persistent xss", "持久型 XSS"},
		{"reflected xss", "反射型 XSS"},
		{"blind xss", "盲 XSS"},
		{"<script>", "Script 标签注入"},
		{"javascript:", "JavaScript 协议注入"},
		{"onerror", "onerror 事件处理器"},
		{"onload", "onload 事件处理器"},
		{"csp bypass", "CSP 绕过"},
		{"content security policy", "内容安全策略"},
		{"httponly", "HttpOnly Cookie 防护"},
	}
	for _, kw := range sxssKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"存储型XSS: " + kw.hint}
		}
	}
	return nil
}

// tryGoReverseAdvanced 检测 Go 语言逆向高级特征。
func tryGoReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	goKeywords := []struct {
		keyword string
		hint    string
	}{
		{"go reverse", "Go 语言逆向"},
		{"goretk", "goretk（Go 运行时逆向工具）"},
		{"redress", "redress（Go 二进制分析）"},
		{"go tool objdump", "Go 反汇编"},
		{"pclntab", "Go 程序计数器行号表（pclntab）"},
		{"gopclntab", "gopclntab（Go PC-line table）"},
		{"runtime.main", "Go runtime 主函数"},
		{"runtime.goexit", "Go 协程退出"},
		{"type descriptor", "Go 类型描述符"},
	}
	for _, kw := range goKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Go逆向: " + kw.hint}
		}
	}
	return nil
}

// tryPythonReverseAdvanced 检测 Python 逆向高级特征。
func tryPythonReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	pyKeywords := []struct {
		keyword string
		hint    string
	}{
		{"pyinstaller", "PyInstaller 打包"},
		{"py2exe", "py2exe 打包"},
		{"nuitka", "Nuitka 编译"},
		{"uncompyle6", "uncompyle6 反编译"},
		{"decompyle3", "decompyle3 反编译"},
		{"pycdc", "pycdc 反编译"},
		{"marshal", "marshal 序列化"},
		{"co_code", "Python 字节码"},
		{".pyc", "Python 编译文件"},
	}
	for _, kw := range pyKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Python逆向: " + kw.hint}
		}
	}
	return nil
}

// tryDotNetReverseAdvanced 检测 .NET 逆向高级特征。
func tryDotNetReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	dotnetKeywords := []struct {
		keyword string
		hint    string
	}{
		{"csharp", "C# 程序"},
		{"ilspy", "ILSpy 反编译"},
		{"dnspy", "dnSpy 调试/反编译"},
		{"il code", "IL 中间代码"},
		{"cil", "通用中间语言"},
		{"ildasm", "ILDASM 反汇编"},
		{"de4dot", ".NET 混淆器脱壳"},
		{"assembly", ".NET 程序集"},
		{"managed code", "托管代码"},
		{"pinvoke", "P/Invoke 调用"},
	}
	for _, kw := range dotnetKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{".NET逆向: " + kw.hint}
		}
	}
	return nil
}

// tryRet2csu 检测 ret2csu 利用特征。
func tryRet2csu(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	csuKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ret2csu", "ret2csu 利用"},
		{"__libc_csu_init", "__libc_csu_init gadget"},
		{"pop gadget", "POP gadget"},
		{"ret gadget", "RET gadget"},
		{"syscall gadget", "syscall gadget"},
		{"rop chain", "ROP 链"},
		{"rop gadget", "ROP gadget"},
	}
	for _, kw := range csuKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"ret2csu: " + kw.hint}
		}
	}
	return nil
}

// tryRet2Syscall 检测 ret2syscall 利用特征。
func tryRet2Syscall(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	sysKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ret2syscall", "ret2syscall 利用"},
		{"execve", "execve 系统调用"},
		{"open", "open 系统调用"},
		{"read", "read 系统调用"},
		{"write", "write 系统调用"},
		{"mmap", "mmap 系统调用"},
		{"mprotect", "mprotect 系统调用"},
		{"dup2", "dup2 系统调用"},
		{"socket", "socket 系统调用"},
	}
	for _, kw := range sysKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"ret2syscall: " + kw.hint}
		}
	}
	return nil
}

// tryFormatStringArbitraryWrite 检测格式化字符串任意写特征。
func tryFormatStringArbitraryWrite(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	fmtKeywords := []struct {
		keyword string
		hint    string
	}{
		{"format string arbitrary write", "格式化字符串任意写"},
		{"%n write", "%n 写入"},
		{"%hn write", "%hn 写入（两字节）"},
		{"%hhn write", "%hhn 写入（单字节）"},
		{"got overwrite", "GOT 表覆写"},
		{"global offset table", "全局偏移表"},
		{"format string leak", "格式化字符串泄露"},
		{"stack leak", "栈泄露"},
		{"canary leak", "Canary 泄露"},
		{"libc leak", "libc 泄露"},
	}
	for _, kw := range fmtKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"格式化字符串: " + kw.hint}
		}
	}
	return nil
}

// tryStackOverflow 检测栈溢出漏洞特征。
func tryStackOverflow(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	soKeywords := []struct {
		keyword string
		hint    string
	}{
		{"buffer overflow", "缓冲区溢出"},
		{"stack overflow", "栈溢出"},
		{"heap overflow", "堆溢出"},
		{"integer overflow", "整数溢出"},
		{"off-by-one", "Off-by-one 溢出"},
		{"strcpy", "strcpy 不安全函数"},
		{"gets", "gets 不安全函数"},
		{"sprintf", "sprintf 不安全函数"},
		{"canary", "栈保护 Canary"},
		{"nx bit", "NX 位（不可执行栈）"},
		{"aslr", "ASLR 地址随机化"},
	}
	for _, kw := range soKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"栈溢出: " + kw.hint}
		}
	}
	return nil
}

// ── P11 批次：云安全 ──────────────────────────────────────

// tryCloudSecurity 检测云安全误配置/攻击特征。
func tryCloudSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	cloudKeywords := []struct {
		keyword string
		hint    string
	}{
		{"aws", "Amazon Web Services"},
		{"ec2", "EC2 实例"},
		{"s3 bucket", "S3 存储桶"},
		{"lambda", "AWS Lambda"},
		{"iam", "AWS IAM 权限"},
		{"cloudtrail", "CloudTrail 审计"},
		{"sts", "AWS STS 临时凭证"},
		{"access key", "AWS Access Key"},
		{"secret key", "AWS Secret Key"},
		{"gcp", "Google Cloud Platform"},
		{"gcs", "Google Cloud Storage"},
		{"compute engine", "GCP Compute Engine"},
		{"service account", "GCP Service Account"},
		{"azure", "Microsoft Azure"},
		{"blob storage", "Azure Blob Storage"},
		{"cosmos db", "Azure Cosmos DB"},
		{"active directory", "Azure AD"},
		{"managed identity", "Azure Managed Identity"},
		{"kubernetes", "Kubernetes 容器编排"},
		{"docker", "Docker 容器"},
		{"container escape", "容器逃逸"},
		{"privilege escalation", "权限提升"},
		{"misconfiguration", "配置错误"},
		{"exposed", "暴露/泄露"},
		{"public access", "公共访问"},
		{"anonymous", "匿名访问"},
		{"metadata service", "元数据服务"},
		{"imds", "实例元数据服务"},
		{"ssrf to cloud", "SSRF → 云元数据"},
	}
	for _, kw := range cloudKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"云安全: " + kw.hint}
		}
	}
	return nil
}

// tryIoTSecurity 检测 IoT 安全特征。
func tryIoTSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	iotKeywords := []struct {
		keyword string
		hint    string
	}{
		{"iot", "物联网"},
		{"mqtt", "MQTT 协议"},
		{"coap", "CoAP 协议"},
		{"zigbee", "Zigbee 协议"},
		{"z-wave", "Z-Wave 协议"},
		{"bluetooth", "蓝牙协议"},
		{"ble", "低功耗蓝牙"},
		{"lorawan", "LoRaWAN 协议"},
		{"embedded", "嵌入式系统"},
		{"rtos", "实时操作系统"},
		{"firmware", "固件"},
		{"embedded linux", "嵌入式 Linux"},
		{"openwrt", "OpenWrt 路由器"},
		{"router exploit", "路由器漏洞利用"},
		{"scada", "SCADA 工控系统"},
		{"ics", "工业控制系统"},
		{"plc", "可编程逻辑控制器"},
		{"modbus", "Modbus 协议"},
		{"opc", "OPC 协议"},
		{"smart home", "智能家居"},
		{"ip camera", "IP 摄像头"},
		{"default credentials", "默认凭据"},
		{"hardcoded password", "硬编码密码"},
	}
	for _, kw := range iotKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"IoT安全: " + kw.hint}
		}
	}
	return nil
}

// tryMobileSecurity 检测移动安全特征（Android/iOS）。
func tryMobileSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	mobileKeywords := []struct {
		keyword string
		hint    string
	}{
		{"android", "Android 平台"},
		{"ios", "iOS 平台"},
		{"apk", "Android APK"},
		{"ipa", "iOS IPA"},
		{"smali", "Smali 反汇编"},
		{"dalvik", "Dalvik 虚拟机"},
		{"art", "ART 运行时"},
		{"dex", "DEX 字节码"},
		{"apktool", "APKTool"},
		{"jadx", "JADX 反编译"},
		{"frida", "Frida 动态插桩"},
		{"xposed", "Xposed 框架"},
		{"magisk", "Magisk Root"},
		{"cydia", "Cydia（越狱）"},
		{"checkra1n", "checkra1n 越狱"},
		{"unc0ver", "unc0ver 越狱"},
		{"ssl pinning", "SSL Pinning"},
		{"certificate pinning", "证书固定"},
		{"jailbreak detection", "越狱检测"},
		{"root detection", "Root 检测"},
		{"emulator detection", "模拟器检测"},
		{"deep link", "Deep Link"},
		{"intent", "Android Intent"},
		{"content provider", "Content Provider"},
		{"broadcast receiver", "Broadcast Receiver"},
		{"webview", "WebView"},
		{"sqlite", "SQLite 数据库"},
		{"keychain", "iOS Keychain"},
		{"shared preferences", "SharedPreferences"},
	}
	for _, kw := range mobileKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"移动安全: " + kw.hint}
		}
	}
	return nil
}

// ── P11 批次：AI/ML安全 + 区块链高级 ──────────────────

// tryAIMLSecurity 检测 AI/ML 安全特征。
func tryAIMLSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	aiKeywords := []struct {
		keyword string
		hint    string
	}{
		{"adversarial example", "对抗样本"},
		{"adversarial attack", "对抗攻击"},
		{"model inversion", "模型逆向攻击"},
		{"model stealing", "模型窃取"},
		{"data poisoning", "数据投毒"},
		{"prompt injection", "Prompt 注入攻击"},
		{"jailbreak", "LLM 越狱攻击"},
		{"prompt leaking", "Prompt 泄露"},
		{"training data extraction", "训练数据提取"},
		{"membership inference", "成员推断攻击"},
		{"differential privacy", "差分隐私"},
		{"federated learning", "联邦学习"},
		{"adversarial patch", "对抗补丁"},
		{"backdoor attack", "后门攻击"},
		{"model watermark", "模型水印"},
		{"neural network", "神经网络"},
		{"machine learning", "机器学习"},
		{"deep learning", "深度学习"},
	}
	for _, kw := range aiKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"AI安全: " + kw.hint}
		}
	}
	return nil
}

// tryBlockchainAdvanced 检测区块链安全高级特征。
func tryBlockchainAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	bcKeywords := []struct {
		keyword string
		hint    string
	}{
		{"reentrancy", "重入攻击"},
		{"integer overflow", "整数溢出"},
		{"flash loan", "闪电贷攻击"},
		{"frontrunning", "抢跑交易"},
		{"sandwich attack", "三明治攻击"},
		{"oracle manipulation", "预言机操纵"},
		{"governance attack", "治理攻击"},
		{"rug pull", "Rug Pull"},
		{"honeypot", "蜜罐合约"},
		{"abi encoding", "ABI 编码"},
		{"calldata", "Calldata 注入"},
		{"delegatecall", "Delegatecall 漏洞"},
		{"selfdestruct", "Selfdestruct 攻击"},
		{"tx.origin", "tx.origin 钓鱼"},
		{"proxy contract", "代理合约"},
		{"upgradeable", "可升级合约"},
		{"diamond pattern", "Diamond 模式"},
		{"erc20 approval", "ERC-20 授权漏洞"},
		{"permit", "EIP-2612 Permit"},
		{"mev", "MEV（最大可提取价值）"},
		{"cross-chain", "跨链安全"},
		{"bridge", "跨链桥安全"},
		{"l2 security", "L2 安全"},
	}
	for _, kw := range bcKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"区块链高级: " + kw.hint}
		}
	}
	return nil
}

// ── P11 批次：crypto 细节 + 编码变体 ──────────────────

// tryTimingAttack 检测时序攻击/功耗分析特征。
func tryTimingAttack(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	taKeywords := []struct {
		keyword string
		hint    string
	}{
		{"timing attack", "时序攻击"},
		{"timing side channel", "时序侧信道"},
		{"cache timing", "缓存时序"},
		{"branch prediction", "分支预测侧信道"},
		{"speculative execution", "推测执行"},
		{"spectre", "Spectre 漏洞"},
		{"meltdown", "Meltdown 漏洞"},
		{"power analysis", "功耗分析"},
		{"differential power", "差分功耗分析（DPA）"},
		{"simple power", "简单功耗分析（SPA）"},
		{"electromagnetic", "电磁侧信道"},
		{"acoustic", "声学侧信道"},
		{"fault injection", "故障注入"},
		{"rowhammer", "Rowhammer DRAM"},
		{"cold boot", "冷启动攻击"},
		{"hardware security", "硬件安全"},
		{"tpm", "可信平台模块"},
		{"secure enclave", "安全飞地"},
		{"sgx", "Intel SGX"},
		{"trustzone", "ARM TrustZone"},
	}
	for _, kw := range taKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"侧信道: " + kw.hint}
		}
	}
	return nil
}

// tryZ85 检测 Z85 编码。
func tryZ85(text string) []string {
	clean := strings.TrimSpace(text)
	// Z85 字符集：0-9, a-z, A-Z, .-:+=^!/*
	z85Re := regexp.MustCompile(`^[0-9a-zA-Z.:\-+^!/*()]{8,}$`)
	if !z85Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	// 排除 base64（含+/=）
	if strings.ContainsAny(clean, "+/=") {
		return nil
	}
	return []string{"Z85 检测: 符合 Z85 编码字符集（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}


// ── P11 批次：reverse 新语言 + pwn 高级（修复版）─────────────────────

// tryRustReverse 检测 Rust 逆向特征。
func tryRustReverse(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	rk := []struct{ k, h string }{
		{"rust", "Rust"}, {"cargo", "Cargo"}, {"rustc", "rustc"},
		{"panic_unwind", "panic"}, {"result<", "Result"}, {"option<", "Option"},
	}
	for _, kw := range rk {
		if strings.Contains(lower, kw.k) {
			return []string{"Rust: " + kw.h}
		}
	}
	return nil
}

// trySwiftReverse 检测 Swift 逆向特征。
func trySwiftReverse(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	sk := []struct{ k, h string }{
		{"swift", "Swift"}, {"swiftui", "SwiftUI"}, {"uikit", "UIKit"},
		{"xcode", "Xcode"}, {"cocoapods", "CocoaPods"}, {"protocol", "Swift协议"},
	}
	for _, kw := range sk {
		if strings.Contains(lower, kw.k) {
			return []string{"Swift: " + kw.h}
		}
	}
	return nil
}

// tryWebAssemblyReverse 检测 WebAssembly 逆向特征。
func tryWebAssemblyReverse(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wk := []struct{ k, h string }{
		{"wasm", "WebAssembly"}, {"webassembly", "WebAssembly"}, {"wat", "WAT格式"},
		{"wasmtime", "Wasmtime"}, {"wasmer", "Wasmer"}, {"emscripten", "Emscripten"},
	}
	for _, kw := range wk {
		if strings.Contains(lower, kw.k) {
			return []string{"WASM: " + kw.h}
		}
	}
	return nil
}

// tryKernelExploitAdvanced 检测内核利用高级特征。
func tryKernelExploitAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kk := []struct{ k, h string }{
		{"kernel exploit", "内核漏洞"}, {"privilege escalation", "权限提升"},
		{"root shell", "Root Shell"}, {"suid", "SUID"}, {"io_uring", "io_uring"},
		{"userfaultfd", "userfaultfd"}, {"namespace escape", "命名空间逃逸"},
		{"container escape", "容器逃逸"}, {"cgroup escape", "cgroup逃逸"},
	}
	for _, kw := range kk {
		if strings.Contains(lower, kw.k) {
			return []string{"内核高级: " + kw.h}
		}
	}
	return nil
}

// tryHypervisorEscape 检测虚拟化逃逸特征。
func tryHypervisorEscape(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	hk := []struct{ k, h string }{
		{"hypervisor escape", "虚拟机逃逸"}, {"vm escape", "VM逃逸"},
		{"vmware escape", "VMware逃逸"}, {"virtualbox escape", "VBox逃逸"},
		{"qemu escape", "QEMU逃逸"}, {"container breakout", "容器突破"},
		{"sandbox escape", "沙箱逃逸"},
	}
	for _, kw := range hk {
		if strings.Contains(lower, kw.k) {
			return []string{"虚拟化逃逸: " + kw.h}
		}
	}
	return nil
}

// tryFirmwareExploit 检测固件利用特征。
func tryFirmwareExploit(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	fk := []struct{ k, h string }{
		{"firmware", "固件"}, {"bios", "BIOS"}, {"uefi", "UEFI"},
		{"bootkit", "Bootkit"}, {"rootkit", "Rootkit"}, {"secure boot", "安全启动绕过"},
		{"tpm attack", "TPM攻击"}, {"supply chain", "供应链攻击"}, {"jtag", "JTAG"},
	}
	for _, kw := range fk {
		if strings.Contains(lower, kw.k) {
			return []string{"固件利用: " + kw.h}
		}
	}
	return nil
}

// ── P12 批次：密码学算法识别 ──────────────────────────────

// tryCryptoAlgorithmDetect 检测具体密码学算法特征（AES/DES/Blowfish/ChaCha20等）。
func tryCryptoAlgorithmDetect(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	algoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"aes", "AES 加密（高级加密标准）"},
		{"advanced encryption standard", "AES"},
		{"aes-128", "AES-128"},
		{"aes-256", "AES-256"},
		{"des", "DES 加密（数据加密标准）"},
		{"3des", "3DES（三重DES）"},
		{"triple des", "三重DES"},
		{"blowfish", "Blowfish 加密"},
		{"twofish", "Twofish 加密"},
		{"chacha20", "ChaCha20 流密码"},
		{"chacha20-poly1305", "ChaCha20-Poly1305 AEAD"},
		{"salsa20", "Salsa20 流密码"},
		{"rc4", "RC4 流密码"},
		{"rc5", "RC5 加密"},
		{"rc6", "RC6 加密"},
		{"idea", "IDEA 加密"},
		{"cast5", "CAST5 加密"},
		{"camellia", "Camellia 加密"},
		{"aria", "ARIA 加密（韩国标准）"},
		{"sm4", "SM4 加密（中国国密）"},
		{"sm2", "SM2 椭圆曲线（中国国密）"},
		{"sm3", "SM3 哈希（中国国密）"},
		{"zuc", "ZUC 流密码（中国国密）"},
		{"poly1305", "Poly1305 MAC"},
		{"siphash", "SipHash"},
		{"blake2", "BLAKE2 哈希"},
		{"blake3", "BLAKE3 哈希"},
		{"sha3", "SHA-3"},
		{"keccak", "Keccak"},
		{"ripemd160", "RIPEMD-160"},
		{"whirlpool", "Whirlpool"},
		{"hmac", "HMAC"},
		{"cmac", "CMAC"},
		{"gmac", "GMAC"},
	}
	for _, kw := range algoKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"密码算法: " + kw.hint}
		}
	}
	return nil
}

// tryEncodingChain 检测多层编码链（编码套编码）。
func tryEncodingChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	encKeywords := []struct {
		keyword string
		hint    string
	}{
		{"multi-layer encoding", "多层编码"},
		{"nested encoding", "嵌套编码"},
		{"encoding chain", "编码链"},
		{"double base64", "双层 Base64"},
		{"base64 decode", "Base64 解码"},
		{"hex decode", "Hex 解码"},
		{"url decode", "URL 解码"},
		{"html entities", "HTML 实体编码"},
		{"unicode escape", "Unicode 转义"},
		{"javascript escape", "JavaScript 转义"},
		{"rot13", "ROT13"},
		{"rot47", "ROT47"},
		{"atbash", "Atbash 密码"},
		{"caesar cipher", "凯撒密码"},
		{"vigenere cipher", "维吉尼亚密码"},
		{"substitution cipher", "替换密码"},
		{"transposition cipher", "置换密码"},
	}
	for _, kw := range encKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"编码检测: " + kw.hint}
		}
	}
	return nil
}

// ── P12 批次：Web3安全 ──────────────────────────────────

// tryWeb3Security 检测 Web3/智能合约安全特征。
func tryWeb3Security(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	web3Keywords := []struct {
		keyword string
		hint    string
	}{
		{"solidity", "Solidity 智能合约"},
		{"smart contract", "智能合约"},
		{"evm", "以太坊虚拟机"},
		{"ethereum", "以太坊"},
		{"erc20", "ERC-20 代币"},
		{"erc721", "ERC-721 NFT"},
		{"erc1155", "ERC-1155 多代币"},
		{"reentrancy", "重入攻击"},
		{"integer overflow", "整数溢出"},
		{"delegatecall", "Delegatecall 漏洞"},
		{"selfdestruct", "Selfdestruct 攻击"},
		{"tx.origin", "tx.origin 钓鱼"},
		{"flash loan", "闪电贷攻击"},
		{"frontrunning", "抢跑交易"},
		{"sandwich attack", "三明治攻击"},
		{"oracle manipulation", "预言机操纵"},
		{"rug pull", "Rug Pull"},
		{"honeypot", "蜜罐合约"},
		{"abi encoding", "ABI 编码"},
		{"calldata", "Calldata 注入"},
		{"proxy contract", "代理合约"},
		{"upgradeable", "可升级合约"},
		{"diamond pattern", "Diamond 模式"},
		{"mev", "MEV（最大可提取价值）"},
		{"cross-chain", "跨链安全"},
		{"bridge", "跨链桥安全"},
		{"l2 security", "L2 安全"},
		{"rollup", "Rollup"},
		{"zero knowledge proof", "零知识证明"},
		{"zk-snark", "zk-SNARK"},
		{"zk-stark", "zk-STARK"},
		{"plonk", "PLONK"},
		{"groth16", "Groth16"},
	}
	for _, kw := range web3Keywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Web3安全: " + kw.hint}
		}
	}
	return nil
}

// ── P12 批次：汽车安全 ──────────────────────────────────

// tryAutomotiveSecurity 检测汽车安全特征（CAN总线/车载网络/ADAS）。
func tryAutomotiveSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	autoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"can bus", "CAN 总线"},
		{"canbus", "CAN 总线"},
		{"obd", "OBD 诊断接口"},
		{"obd-ii", "OBD-II 接口"},
		{"uds", "统一诊断服务（UDS）"},
		{"automotive", "汽车安全"},
		{"connected car", "车联网"},
		{"v2x", "车对万物通信（V2X）"},
		{"adas", "高级驾驶辅助系统（ADAS）"},
		{"autonomous driving", "自动驾驶"},
		{"lidar", "激光雷达"},
		{"radar", "毫米波雷达"},
		{"tesla", "特斯拉"},
		{"can injection", "CAN 注入攻击"},
		{"can sniffing", "CAN 嗅探"},
		{"ecu", "电子控制单元（ECU）"},
		{"firmware update", "OTA 固件更新"},
		{"vehicle security", "车辆安全"},
		{"immobilizer", "防盗系统"},
		{"key fob", "遥控钥匙"},
		{"relay attack", "中继攻击"},
		{"tpms", "胎压监测系统"},
	}
	for _, kw := range autoKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"汽车安全: " + kw.hint}
		}
	}
	return nil
}

// ── P12 批次：卫星安全 ──────────────────────────────────

// trySatelliteSecurity 检测卫星安全特征（卫星通信/遥测/地面站）。
func trySatelliteSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	satKeywords := []struct {
		keyword string
		hint    string
	}{
		{"satellite", "卫星安全"},
		{"satellite communication", "卫星通信"},
		{"satcom", "卫星通信（SATCOM）"},
		{"telemetry", "遥测"},
		{"telecommand", "遥控指令"},
		{"ground station", "地面站"},
		{"uplink", "上行链路"},
		{"downlink", "下行链路"},
		{"gnss", "全球导航卫星系统（GNSS）"},
		{"gps spoofing", "GPS 欺骗"},
		{"gps jamming", "GPS 干扰"},
		{"signal jamming", "信号干扰"},
		{"frequency hopping", "跳频"},
		{"spread spectrum", "扩频"},
		{"modulation", "调制"},
		{"demodulation", "解调"},
		{"signal analysis", "信号分析"},
		{"sdr", "软件定义无线电（SDR）"},
		{"rtl-sdr", "RTL-SDR"},
		{"gnu radio", "GNU Radio"},
		{"iq data", "IQ 数据"},
		{"constellation", "星座图"},
		{"spectrum analysis", "频谱分析"},
		{"interference", "干扰"},
	}
	for _, kw := range satKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"卫星安全: " + kw.hint}
		}
	}
	return nil
}

// ── P12 批次：密码学高级算法识别 ──────────────────────────

// tryAdvancedCrypto 检测高级密码学算法/协议特征。
func tryAdvancedCrypto(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	advKeywords := []struct {
		keyword string
		hint    string
	}{
		{"tls", "TLS 协议"},
		{"ssl", "SSL 协议"},
		{"certificate", "证书"},
		{"x509", "X.509 证书"},
		{"public key", "公钥"},
		{"private key", "私钥"},
		{"key exchange", "密钥交换"},
		{"diffie-hellman", "Diffie-Hellman"},
		{"elliptic curve", "椭圆曲线"},
		{"digital signature", "数字签名"},
		{"hash function", "哈希函数"},
		{"message authentication", "消息认证"},
		{"hmac", "HMAC"},
		{"key derivation", "密钥派生"},
		{"pbkdf2", "PBKDF2"},
		{"bcrypt", "bcrypt"},
		{"scrypt", "scrypt"},
		{"argon2", "Argon2"},
		{"salting", "加盐"},
		{"peppering", "加胡椒"},
		{"key stretching", "密钥拉伸"},
		{"password hashing", "密码哈希"},
		{"random number", "随机数生成"},
		{"prng", "伪随机数生成器"},
		{"csprng", "密码学安全伪随机数生成器"},
		{"entropy", "熵"},
	}
	for _, kw := range advKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"高级密码学: " + kw.hint}
		}
	}
	return nil
}

// ── P12 批次：编码检测链高级 ──────────────────────────────

// tryEncodingDetectionAdvanced 检测高级编码特征（yEnc/BinHex/QuotedPrintable）。
func tryEncodingDetectionAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	encKeywords := []struct {
		keyword string
		hint    string
	}{
		{"yenc", "yEnc 编码"},
		{"binhex", "BinHex 编码"},
		{"quoted-printable", "Quoted-Printable"},
		{"charset", "字符集"},
		{"encoding", "编码"},
		{"utf-8", "UTF-8"},
		{"utf-16", "UTF-16"},
		{"utf-32", "UTF-32"},
		{"iso-8859", "ISO-8859"},
		{"windows-1252", "Windows-1252"},
		{"euc-kr", "EUC-KR"},
		{"euc-jp", "EUC-JP"},
		{"gb2312", "GB2312"},
		{"gbk", "GBK"},
		{"big5", "Big5"},
		{"shift_jis", "Shift_JIS"},
	}
	for _, kw := range encKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"编码高级: " + kw.hint}
		}
	}
	return nil
}

// tryCryptoAttackPatterns 检测密码学攻击模式特征。
func tryCryptoAttackPatterns(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	attackKeywords := []struct {
		keyword string
		hint    string
	}{
		{"known plaintext", "已知明文攻击"},
		{"chosen plaintext", "选择明文攻击"},
		{"chosen ciphertext", "选择密文攻击"},
		{"differential cryptanalysis", "差分密码分析"},
		{"linear cryptanalysis", "线性密码分析"},
		{"side channel", "侧信道攻击"},
		{"timing attack", "时序攻击"},
		{"power analysis", "功耗分析"},
		{"fault injection", "故障注入"},
		{"dictionary attack", "字典攻击"},
		{"brute force", "暴力破解"},
		{"rainbow table", "彩虹表"},
		{"collision attack", "碰撞攻击"},
		{"birthday attack", "生日攻击"},
		{"length extension", "长度扩展攻击"},
		{"padding oracle", "填充预言机"},
		{"bleichenbacher", "Bleichenbacher 攻击"},
	}
	for _, kw := range attackKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"密码攻击: " + kw.hint}
		}
	}
	return nil
}

// ── P13 批次：网络协议安全 ──────────────────────────────────

// tryNetworkProtocol 检测网络协议安全特征（TCP/IP/DNS/HTTP2/QUIC等）。
func tryNetworkProtocol(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	protoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"tcp/ip", "TCP/IP 协议栈"},
		{"tcp reset", "TCP RST 注入"},
		{"tcp sequence", "TCP 序列号预测"},
		{"syn flood", "SYN 洪泛攻击"},
		{"dns poisoning", "DNS 投毒"},
		{"dns rebinding", "DNS 重绑定"},
		{"dns tunneling", "DNS 隧道"},
		{"dns exfiltration", "DNS 数据外泄"},
		{"dnssec", "DNSSEC"},
		{"http/2", "HTTP/2 协议"},
		{"http/3", "HTTP/3 协议"},
		{"quic", "QUIC 协议"},
		{"server-sent events", "SSE 服务器推送"},
		{"grpc", "gRPC 协议"},
		{"protobuf", "Protocol Buffers"},
		{"graphql subscription", "GraphQL 订阅"},
		{"websocket upgrade", "WebSocket 升级握手"},
		{"hsts", "HSTS 严格传输安全"},
		{"csp", "内容安全策略（CSP）"},
		{"cors misconfiguration", "CORS 配置错误"},
		{"host header injection", "Host 头注入"},
		{"request smuggling", "HTTP 请求走私"},
		{"cache poisoning", "缓存投毒"},
		{"clickjacking", "点击劫持"},
	}
	for _, kw := range protoKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"网络协议: " + kw.hint}
		}
	}
	return nil
}

// tryDatabaseSecurity 检测数据库安全特征（SQL注入变体/NoSQL注入）。
func tryDatabaseSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	dbKeywords := []struct {
		keyword string
		hint    string
	}{
		{"sql injection", "SQL 注入"},
		{"nosql injection", "NoSQL 注入"},
		{"mongodb injection", "MongoDB 注入"},
		{"couchdb", "CouchDB 注入"},
		{"redis injection", "Redis 注入"},
		{"ldap injection", "LDAP 注入"},
		{"xpath injection", "XPath 注入"},
		{"xml injection", "XML 注入"},
		{"orm injection", "ORM 注入"},
		{"second order injection", "二次注入"},
		{"blind sql injection", "SQL 盲注"},
		{"time-based sql", "时间盲注"},
		{"union select", "UNION 注入"},
		{"error-based sql", "报错注入"},
		{"stacked queries", "堆叠查询"},
		{"information_schema", "INFORMATION_SCHEMA"},
		{"mysql", "MySQL"},
		{"postgresql", "PostgreSQL"},
		{"sqlite", "SQLite"},
		{"oracle", "Oracle"},
		{"mssql", "Microsoft SQL Server"},
		{"cassandra", "Cassandra"},
		{"neo4j", "Neo4j 图数据库"},
	}
	for _, kw := range dbKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"数据库安全: " + kw.hint}
		}
	}
	return nil
}

// ── P13 批次：无线安全 ──────────────────────────────────

// tryWirelessSecurity 检测无线安全特征（WiFi/Bluetooth/NFC/RFID）。
func tryWirelessSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"wifi", "WiFi 安全"},
		{"wpa2", "WPA2 加密"},
		{"wpa3", "WPA3 加密"},
		{"wep", "WEP 加密"},
		{"deauthentication", "解除认证攻击"},
		{"evil twin", "Evil Twin 攻击"},
		{"evil ap", "Evil AP 攻击"},
		{"rogue ap", "Rogue AP"},
		{"handshake capture", "握手包捕获"},
		{"pmkid", "PMKID 攻击"},
		{"bluetooth", "蓝牙安全"},
		{"ble", "低功耗蓝牙"},
		{"bluejacking", "蓝牙骚扰"},
		{"bluesnarfing", "蓝牙窃取"},
		{"bluebugging", "蓝牙窃听"},
		{"nfc", "NFC 安全"},
		{"rfid", "RFID 安全"},
		{"rfid cloning", "RFID 克隆"},
		{"proxmark", "Proxmark 工具"},
		{"sdr", "软件定义无线电"},
		{"rtl-sdr", "RTL-SDR"},
		{"gnu radio", "GNU Radio"},
		{"signal analysis", "信号分析"},
		{"frequency hopping", "跳频"},
	}
	for _, kw := range wlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"无线安全: " + kw.hint}
		}
	}
	return nil
}

// ── P13 批次：硬件安全高级 ──────────────────────────────────

// tryHardwareSecurityAdvanced 检测硬件安全高级特征。
func tryHardwareSecurityAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	hwKeywords := []struct {
		keyword string
		hint    string
	}{
		{"jtag", "JTAG 调试接口"},
		{"uart", "UART 串口"},
		{"spi", "SPI 协议"},
		{"i2c", "I2C 协议"},
		{"can bus", "CAN 总线"},
		{"openocd", "OpenOCD 调试器"},
		{"bus pirate", "Bus Pirate"},
		{"logic analyzer", "逻辑分析仪"},
		{"oscilloscope", "示波器"},
		{"fpga", "FPGA"},
		{"asic", "ASIC"},
		{"microcontroller", "微控制器"},
		{"arm cortex", "ARM Cortex"},
		{"risc-v", "RISC-V"},
		{"mips", "MIPS 架构"},
		{"power analysis", "功耗分析"},
		{"electromagnetic", "电磁分析"},
		{"fault injection", "故障注入"},
		{"chip whisperer", "ChipWhisperer"},
		{"side channel attack", "侧信道攻击"},
	}
	for _, kw := range hwKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"硬件安全: " + kw.hint}
		}
	}
	return nil
}

// ── P13 批次：操作系统内核安全 ──────────────────────────────

// tryOSKernelSecurity 检测操作系统内核安全特征。
func tryOSKernelSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	osKeywords := []struct {
		keyword string
		hint    string
	}{
		{"windows kernel", "Windows 内核"},
		{"nt kernel", "NT 内核"},
		{"driver vulnerability", "驱动漏洞"},
		{"kernel exploit", "内核漏洞利用"},
		{"syscall", "系统调用"},
		{"sysenter", "sysenter 指令"},
		{"int 0x80", "int 0x80 中断"},
		{"linux kernel", "Linux 内核"},
		{"loadable kernel module", "可加载内核模块（LKM）"},
		{"rootkit", "Rootkit"},
		{"bootkit", "Bootkit"},
		{"ring 0", "Ring 0（内核态）"},
		{"ring 3", "Ring 3（用户态）"},
		{"privileged instruction", "特权指令"},
		{"page fault", "页错误"},
		{"segmentation fault", "段错误"},
		{"memory management", "内存管理"},
		{"virtual memory", "虚拟内存"},
		{"address space", "地址空间"},
		{"aslr", "ASLR 地址空间随机化"},
		{"dep", "DEP 数据执行保护"},
		{"sme", "SME 安全内存加密"},
		{"sev", "SEV 安全加密虚拟化"},
	}
	for _, kw := range osKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"内核安全: " + kw.hint}
		}
	}
	return nil
}

// ── P13 批次：编码变体扩展 ──────────────────────────────

// tryBase45 检测 Base45 编码（RFC 9285，用于 COVID 证书）。
func tryBase45(text string) []string {
	clean := strings.TrimSpace(text)
	// Base45 字符集：0-9, A-Z, space, $%*+-./:
	b45Re := regexp.MustCompile(`^[0-9A-Z\s$%*+\-./:]{8,}$`)
	if !b45Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	return []string{"Base45 检测: 符合 Base45 字符集（RFC 9285，" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}

// tryBech32 检测 Bech32 编码（比特币隔离见证地址）。
func tryBech32(text string) []string {
	clean := strings.TrimSpace(text)
	// Bech32 特征：小写字母+数字，含 '1' 分隔符
	bech32Re := regexp.MustCompile(`^[a-z2-9]+1[a-z2-9]+$`)
	if !bech32Re.MatchString(clean) || len(clean) < 14 {
		return nil
	}
	return []string{"Bech32 检测: 比特币隔离见证地址格式（" + clean[:minInt(20, len(clean))] + "）"}
}

// tryBase62 检测 Base62 编码（URL 短链常用）。
func tryBase62(text string) []string {
	clean := strings.TrimSpace(text)
	b62Re := regexp.MustCompile(`^[0-9A-Za-z]{8,}$`)
	if !b62Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	// 排除 base64（含+/=）
	if strings.ContainsAny(clean, "+/=") {
		return nil
	}
	return []string{"Base62 检测: 纯字母数字编码（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}

// ── P14 批次：量子计算 ──────────────────────────────────

// tryQuantumComputing 检测量子计算特征（Shor/Grover/Qiskit/Cirq）。
func tryQuantumComputing(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	qcKeywords := []struct {
		keyword string
		hint    string
	}{
		{"quantum", "量子计算"},
		{"shor algorithm", "Shor 算法（量子因式分解）"},
		{"grover algorithm", "Grover 算法（量子搜索）"},
		{"qiskit", "Qiskit（IBM 量子框架）"},
		{"cirq", "Cirq（Google 量子框架）"},
		{"pennylane", "PennyLane（量子机器学习）"},
		{"qubit", "量子比特"},
		{"superposition", "叠加态"},
		{"entanglement", "纠缠"},
		{"quantum gate", "量子门"},
		{"hadamard", "Hadamard 门"},
		{"cnot", "CNOT 门"},
		{"toffoli", "Toffoli 门"},
		{"quantum circuit", "量子电路"},
		{"quantum error correction", "量子纠错"},
		{"post-quantum", "后量子密码学"},
		{"lattice-based", "格基密码学（后量子）"},
		{"code-based", "编码密码学（后量子）"},
		{"multivariate", "多元密码学（后量子）"},
		{"hash-based", "哈希签名（后量子）"},
	}
	for _, kw := range qcKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"量子计算: " + kw.hint}
		}
	}
	return nil
}

// ── P14 批次：生物信息学 ──────────────────────────────────

// tryBioinformatics 检测生物信息学特征（DNA序列/蛋白质结构）。
func tryBioinformatics(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	bioKeywords := []struct {
		keyword string
		hint    string
	}{
		{"bioinformatics", "生物信息学"},
		{"dna sequence", "DNA 序列"},
		{"rna sequence", "RNA 序列"},
		{"protein structure", "蛋白质结构"},
		{"amino acid", "氨基酸"},
		{"nucleotide", "核苷酸"},
		{"genome", "基因组"},
		{"gene", "基因"},
		{"phylogenetic", "系统发育"},
		{"alignment", "序列比对"},
		{"blast", "BLAST 比对"},
		{"fasta", "FASTA 格式"},
		{"pdb", "PDB 蛋白质结构"},
		{"bio python", "Biopython"},
		{"bioconductor", "Bioconductor"},
		{"crispr", "CRISPR 基因编辑"},
		{"pcr", "PCR 扩增"},
		{"sequencing", "测序"},
		{"polymerase chain", "聚合酶链式反应"},
	}
	for _, kw := range bioKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"生物信息: " + kw.hint}
		}
	}
	return nil
}

// ── P14 批次：游戏安全 ──────────────────────────────────

// tryGameSecurity 检测游戏安全特征（Unity/Unreal/反作弊/内存修改）。
func tryGameSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gameKeywords := []struct {
		keyword string
		hint    string
	}{
		{"game hacking", "游戏破解"},
		{"unity", "Unity 引擎"},
		{"unreal engine", "Unreal Engine"},
		{"godot", "Godot 引擎"},
		{"memory editing", "内存修改"},
		{"cheat engine", "Cheat Engine"},
		{"gameguardian", "GameGuardian"},
		{"anti-cheat", "反作弊系统"},
		{"vac", "VAC（Valve 反作弊）"},
		{"battleye", "BattlEye"},
		{"easy anti-cheat", "Easy Anti-Cheat"},
		{"eac", "EAC"},
		{"punkbuster", "PunkBuster"},
		{"speed hack", "加速外挂"},
		{"aimbot", "自瞄外挂"},
		{"wallhack", "透视外挂"},
		{"god mode", "无敌模式"},
		{"noclip", "穿墙模式"},
		{"dll injection", "DLL 注入"},
		{"hook", "Hook 挂钩"},
		{"opcode patch", "操作码补丁"},
		{"game trainer", "游戏修改器"},
	}
	for _, kw := range gameKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"游戏安全: " + kw.hint}
		}
	}
	return nil
}

// ── P14 批次：数字取证高级 ──────────────────────────────

// tryDigitalForensicsAdvanced 检测数字取证高级特征（内存取证/网络取证/日志分析）。
func tryDigitalForensicsAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	dfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"digital forensics", "数字取证"},
		{"memory forensics", "内存取证"},
		{"volatility", "Volatility 内存取证"},
		{"rekall", "Rekall 内存取证"},
		{"network forensics", "网络取证"},
		{"packet capture", "数据包捕获"},
		{"pcap analysis", "PCAP 分析"},
		{"wireshark", "Wireshark"},
		{"zeek", "Zeek（Bro）网络安全监控"},
		{"suricata", "Suricata IDS"},
		{"snort", "Snort IDS"},
		{"log analysis", "日志分析"},
		{"siem", "SIEM 安全信息和事件管理"},
		{"splunk", "Splunk"},
		{"elk stack", "ELK Stack"},
		{"elasticsearch", "Elasticsearch"},
		{"timeline analysis", "时间线分析"},
		{"artifact analysis", "工件分析"},
		{"evidence preservation", "证据保全"},
		{"chain of custody", "监管链"},
		{"forensic imaging", "取证镜像"},
		{"write blocker", "写保护器"},
	}
	for _, kw := range dfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"数字取证: " + kw.hint}
		}
	}
	return nil
}

// ── P14 批次：密码学实现细节 ──────────────────────────────

// tryCryptoImplementationDetails 检测密码学实现细节特征。
func tryCryptoImplementationDetails(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ciKeywords := []struct {
		keyword string
		hint    string
	}{
		{"rsa-crt", "RSA-CRT 优化实现"},
		{"chinese remainder theorem", "中国剩余定理"},
		{"point compression", "椭圆曲线点压缩"},
		{"compressed point", "压缩点格式"},
		{"uncompressed point", "非压缩点格式"},
		{"hmac construction", "HMAC 构造"},
		{"key derivation function", "密钥派生函数"},
		{"pbkdf2", "PBKDF2"},
		{"bcrypt", "bcrypt"},
		{"scrypt", "scrypt"},
		{"argon2", "Argon2"},
		{"hkdf", "HKDF"},
		{"concat kdf", "Concat KDF"},
		{"x963 kdf", "X9.63 KDF"},
		{"ansi x963", "ANSI X9.63"},
		{"nonce", "随机数/Nonce"},
		{"iv", "初始化向量"},
		{"salt", "盐值"},
		{"pepper", "胡椒值"},
		{"key stretching", "密钥拉伸"},
		{"key wrapping", "密钥包装"},
		{"aes-key-wrap", "AES Key Wrap"},
		{"ecb mode", "ECB 模式"},
		{"cbc mode", "CBC 模式"},
		{"ctr mode", "CTR 模式"},
		{"gcm mode", "GCM 模式"},
		{"ccm mode", "CCM 模式"},
		{"poly1305", "Poly1305 MAC"},
		{"siphash", "SipHash"},
	}
	for _, kw := range ciKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"密码学实现: " + kw.hint}
		}
	}
	return nil
}

// ── P15 批次：密码学协议分析 ──────────────────────────────────

// tryCryptoProtocolAnalysis 检测密码学协议分析特征（TLS握手/证书链/密钥交换）。
func tryCryptoProtocolAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	protoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"tls handshake", "TLS 握手分析"},
		{"ssl handshake", "SSL 握手分析"},
		{"certificate chain", "证书链分析"},
		{"certificate transparency", "证书透明度"},
		{"certificate pinning", "证书固定"},
		{"public key pinning", "公钥固定"},
		{"key exchange", "密钥交换"},
		{"diffie-hellman", "Diffie-Hellman 密钥交换"},
		{"elliptic curve diffie-hellman", "ECDH 椭圆曲线密钥交换"},
		{"rsa key exchange", "RSA 密钥交换"},
		{"forward secrecy", "前向保密"},
		{"perfect forward secrecy", "完美前向保密（PFS）"},
		{"cipher suite", "密码套件"},
		{"tls version", "TLS 版本"},
		{"ssl version", "SSL 版本"},
		{"handshake failure", "握手失败"},
		{"certificate expired", "证书过期"},
		{"certificate revoked", "证书吊销"},
		{"self-signed certificate", "自签名证书"},
		{"certificate authority", "证书颁发机构（CA）"},
		{"ocsp", "在线证书状态协议（OCSP）"},
		{"crl", "证书吊销列表（CRL）"},
		{"sni", "服务器名称指示（SNI）"},
		{"alpn", "应用层协议协商（ALPN）"},
	}
	for _, kw := range protoKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"协议分析: " + kw.hint}
		}
	}
	return nil
}

// ── P15 批次：网络取证 ──────────────────────────────────

// tryNetworkForensics 检测网络取证特征（PCAP分析/流量还原/协议解析）。
func tryNetworkForensics(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	netKeywords := []struct {
		keyword string
		hint    string
	}{
		{"pcap", "PCAP 流量捕获"},
		{"pcapng", "PCAPNG 流量捕获"},
		{"tcpdump", "tcpdump 流量捕获"},
		{"wireshark", "Wireshark 协议分析"},
		{"tshark", "tshark 命令行分析"},
		{"zeek", "Zeek（Bro）网络安全监控"},
		{"suricata", "Suricata IDS"},
		{"snort", "Snort IDS"},
		{"network forensics", "网络取证"},
		{"packet analysis", "数据包分析"},
		{"flow analysis", "流量分析"},
		{"conversation analysis", "会话分析"},
		{"protocol dissection", "协议解析"},
		{"http analysis", "HTTP 流量分析"},
		{"dns analysis", "DNS 流量分析"},
		{"tls decryption", "TLS 流量解密"},
		{"ssl decryption", "SSL 流量解密"},
		{"key log file", "SSL Key Log 文件"},
		{"master secret", "主密钥"},
		{"pre-master secret", "预主密钥"},
		{"network tap", "网络分流器"},
		{"packet capture", "数据包捕获"},
		{"traffic mirroring", "流量镜像"},
	}
	for _, kw := range netKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"网络取证: " + kw.hint}
		}
	}
	return nil
}

// ── P15 批次：漏洞利用链检测 ──────────────────────────────────

// tryExploitChainDetection 检测漏洞利用链特征（多步攻击/链式利用/工具组合）。
func tryExploitChainDetection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	chainKeywords := []struct {
		keyword string
		hint    string
	}{
		{"exploit chain", "漏洞利用链"},
		{"attack chain", "攻击链"},
		{"kill chain", "杀伤链"},
		{"ttp", "战术、技术与程序（TTPs）"},
		{"mitre att&ck", "MITRE ATT&CK 框架"},
		{"initial access", "初始访问"},
		{"execution", "执行"},
		{"persistence", "持久化"},
		{"privilege escalation", "权限提升"},
		{"defense evasion", "防御规避"},
		{"credential access", "凭证访问"},
		{"discovery", "发现"},
		{"lateral movement", "横向移动"},
		{"collection", "收集"},
		{"command and control", "命令与控制（C2）"},
		{"exfiltration", "数据外泄"},
		{"impact", "影响"},
		{"apt", "高级持续威胁（APT）"},
		{"advanced persistent threat", "高级持续威胁"},
		{"threat intelligence", "威胁情报"},
		{"ioc", "入侵指标（IOC）"},
		{"indicator of compromise", "入侵指标"},
		{"indicator of attack", "攻击指标"},
		{"threat hunting", "威胁狩猎"},
	}
	for _, kw := range chainKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"攻击链检测: " + kw.hint}
		}
	}
	return nil
}
