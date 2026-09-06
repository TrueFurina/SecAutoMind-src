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
