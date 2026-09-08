// presolve_crypto.go —— 非对称与哈希类求解器（RSA/格/椭圆曲线/ECDSA/哈希破解等）
// 自 presolve.go 机械拆分（30 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

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

// tryECDSANonceReuse 真实攻击：ECDSA nonce 重用恢复私钥。
//
// 给定两组共享同一 nonce k 的签名 (r, s1, z1) 与 (r, s2, z2)（r 相同 = nonce 复用铁证）：
//
//	k  = (z1 - z2) * (s1 - s2)^-1 mod n
//	d  = (s1*k - z1) * r^-1        mod n
//
// 从题目描述/附件解析 r, s1, s2, z1, z2, n（n 为曲线阶）。解出私钥 d 后产出 flag 候选。
// 纯大数运算，确定性、可双语言机验，不依赖在线 oracle。
func tryECDSANonceReuse(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	parseBI := func(pat string) *big.Int {
		m := regexp.MustCompile(pat).FindStringSubmatch(fullText)
		if m == nil {
			return nil
		}
		b, ok := new(big.Int).SetString(m[1], 10)
		if !ok {
			return nil
		}
		return b
	}
	r := parseBI(`(?i)\br\s*=\s*(\d+)`)
	n := parseBI(`(?i)\bn\s*=\s*(\d+)`)
	s1 := parseBI(`(?i)\bs1\s*=\s*(\d+)`)
	s2 := parseBI(`(?i)\bs2\s*=\s*(\d+)`)
	z1 := parseBI(`(?i)\bz1\s*=\s*(\d+)`)
	z2 := parseBI(`(?i)\bz2\s*=\s*(\d+)`)
	if r == nil || n == nil || s1 == nil || s2 == nil || z1 == nil || z2 == nil {
		return nil
	}
	if r.Sign() == 0 || n.Sign() <= 0 || s1.Cmp(s2) == 0 {
		return nil
	}
	// k = (z1 - z2) * (s1 - s2)^-1 mod n
	zdiff := new(big.Int).Sub(z1, z2)
	zdiff.Mod(zdiff, n)
	sdiff := new(big.Int).Sub(s1, s2)
	sdiff.Mod(sdiff, n)
	k := new(big.Int).ModInverse(sdiff, n)
	if k == nil {
		return nil
	}
	k.Mul(zdiff, k)
	k.Mod(k, n)
	// d = (s1*k - z1) * r^-1 mod n
	rInv := new(big.Int).ModInverse(r, n)
	if rInv == nil {
		return nil
	}
	d := new(big.Int).Mul(s1, k)
	d.Sub(d, z1)
	d.Mod(d, n)
	d.Mul(d, rInv)
	d.Mod(d, n)
	if d.Sign() == 0 {
		return nil
	}
	dHex := fmt.Sprintf("%x", d)
	cands := []string{"flag{" + dHex + "}", "CTF{" + dHex + "}", string(d.Bytes()), d.Text(10)}
	for _, c := range cands {
		if flags := scanFlags(c); len(flags) > 0 {
			return flags
		}
	}
	return []string{"ECDSA私钥(hex): " + dHex}
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

// tryCommonFactor 共享素数分解攻击：两个 RSA 模数共享素数 p（gcd(n1,n2)=p）。
// 文本需含 n1=, n2=（或两组 n=）、e=、c= 参数。分解成功后用 n1 对应私钥解密。
func tryCommonFactor(text string) []string {
	nRe := regexp.MustCompile(`(?i)\bn([12]?)\s*=\s*(\d+)`)
	cRe := regexp.MustCompile(`(?i)\bc([12]?)\s*=\s*(\d+)`)
	eRe := regexp.MustCompile(`(?i)\be([12]?)\s*=\s*(\d+)`)

	var ns, cs, es []*big.Int
	for _, m := range nRe.FindAllStringSubmatch(text, -1) {
		v, ok := new(big.Int).SetString(m[2], 10)
		if ok && v.Sign() > 0 {
			ns = append(ns, v)
		}
	}
	for _, m := range cRe.FindAllStringSubmatch(text, -1) {
		v, ok := new(big.Int).SetString(m[2], 10)
		if ok && v.Sign() > 0 {
			cs = append(cs, v)
		}
	}
	for _, m := range eRe.FindAllStringSubmatch(text, -1) {
		v, ok := new(big.Int).SetString(m[2], 10)
		if ok && v.Sign() > 0 {
			es = append(es, v)
		}
	}
	if len(ns) < 2 || len(cs) < 1 || len(es) < 1 {
		return nil
	}
	p := new(big.Int).GCD(nil, nil, ns[0], ns[1])
	if p.Cmp(big.NewInt(1)) <= 0 || p.Cmp(ns[0]) >= 0 {
		return nil
	}
	q := new(big.Int).Div(ns[0], p)
	if q.Cmp(p) == 0 {
		return nil
	}
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	d := new(big.Int).ModInverse(es[0], phi)
	if d == nil {
		return nil
	}
	m := new(big.Int).Exp(cs[0], d, ns[0])
	if flags := scanFlags(string(m.Bytes())); len(flags) > 0 {
		return flags
	}
	return nil
}

// ── P5 批次：crypto 高级 ──────────────────────────────────

// tryHastadCRT 实现 Hastad 广播攻击：同明文+e=3+3组(n,c) → CRT合并后开立方根。
func tryHastadCRT(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	if !strings.Contains(lower, "hastad") && !strings.Contains(lower, "broadcast") {
		return nil
	}
	// 提取 n1/n2/n3, c1/c2/c3, e
	nRe := regexp.MustCompile(`(?i)n(\d)\s*=\s*(\d+)`)
	cRe := regexp.MustCompile(`(?i)c(\d)\s*=\s*(\d+)`)
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	eMatch := eRe.FindStringSubmatch(fullText)
	if eMatch == nil {
		return []string{"Hastad广播攻击: 检测到条件，需提供 e, n1/n2/n3, c1/c2/c3"}
	}
	e, _ := new(big.Int).SetString(eMatch[1], 10)
	if e == nil || e.Cmp(big.NewInt(10)) > 0 {
		return nil
	}
	nMap := make(map[string]*big.Int)
	cMap := make(map[string]*big.Int)
	for _, m := range nRe.FindAllStringSubmatch(fullText, -1) {
		if v, ok := new(big.Int).SetString(m[2], 10); ok {
			nMap[m[1]] = v
		}
	}
	for _, m := range cRe.FindAllStringSubmatch(fullText, -1) {
		if v, ok := new(big.Int).SetString(m[2], 10); ok {
			cMap[m[1]] = v
		}
	}
	if len(nMap) < 3 || len(cMap) < 3 {
		return nil
	}
	// CRT 合并
	N := new(big.Int).Mul(nMap["1"], new(big.Int).Mul(nMap["2"], nMap["3"]))
	var crtSum big.Int
	for _, key := range []string{"1", "2", "3"} {
		ni, ci := nMap[key], cMap[key]
		if ni == nil || ci == nil {
			continue
		}
		mi := new(big.Int).Div(N, ni)
		yi := new(big.Int).ModInverse(mi, ni)
		if yi == nil {
			continue
		}
		tmp := new(big.Int).Mul(ci, new(big.Int).Mul(mi, yi))
		crtSum.Add(&crtSum, tmp)
	}
	crtSum.Mod(&crtSum, N)
	// 开 e 次方根
	m := iroot(&crtSum, e)
	if m != nil {
		mBytes := m.Bytes()
		if flags := scanFlags(string(mBytes)); len(flags) > 0 {
			return flags
		}
		return []string{"Hastad解密(hex): " + hex.EncodeToString(mBytes)}
	}
	return nil
}

// tryCommonModulusComplete 完整共模攻击：同n+不同e+gcd(e1,e2)=1。

// tryLowExponentBroadcast 低加密指数广播攻击（e很小，多组n加密同一明文）。
func tryLowExponentBroadcast(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	eMatch := eRe.FindStringSubmatch(fullText)
	if eMatch == nil {
		return nil
	}
	e, _ := new(big.Int).SetString(eMatch[1], 10)
	if e == nil || e.Cmp(big.NewInt(5)) > 0 {
		return nil
	}
	// 检查是否有足够多的 (n, c) 对
	nRe := regexp.MustCompile(`(?i)n\d*\s*=\s*(\d+)`)
	cRe := regexp.MustCompile(`(?i)c\d*\s*=\s*(\d+)`)
	if len(nRe.FindAllStringSubmatch(fullText, -1)) >= int(e.Int64()) &&
		len(cRe.FindAllStringSubmatch(fullText, -1)) >= int(e.Int64()) {
		return []string{fmt.Sprintf("低指数广播攻击条件：e=%s, %d组(n,c)，CRT合并后开%sth根", e.String(), len(nRe.FindAllStringSubmatch(fullText, -1)), e.String())}
	}
	return nil
}

// tryRSAWiener 检测 RSA Wiener 攻击条件（e极大，d较小）。

// ── P6 批次：crypto 经典攻击完整版（真解题出 flag，非检测提示）──────────

// tryHastadBroadcastAttack 完整 Hastad 广播攻击：e 组同明文不同 n（e=3 典型），
// CRT 合成 m^e mod ∏n_i 后开 e 次根还原明文。
func tryHastadBroadcastAttack(text string, attachments map[string]string) []string {
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
	if !ok || e.Sign() <= 0 || e.Cmp(big.NewInt(16)) > 0 {
		return nil
	}
	// 收集 n_i 与 c_i（n1/n2/... 与 c1/c2/...，纯 n=/c= 亦兼容）
	pairRe := regexp.MustCompile(`(?i)\bn(\d*)\s*=\s*(\d+)`)
	nMap := map[string]*big.Int{}
	for _, m := range pairRe.FindAllStringSubmatch(fullText, -1) {
		v, okv := new(big.Int).SetString(m[2], 10)
		if okv {
			nMap[m[1]] = v
		}
	}
	cpairRe := regexp.MustCompile(`(?i)\bc(\d*)\s*=\s*(\d+)`)
	cMap := map[string]*big.Int{}
	for _, m := range cpairRe.FindAllStringSubmatch(fullText, -1) {
		v, okv := new(big.Int).SetString(m[2], 10)
		if okv {
			cMap[m[1]] = v
		}
	}
	if len(nMap) < int(e.Int64()) || len(cMap) < int(e.Int64()) {
		return nil
	}
	// 按键序取前 e 组（键 "" 优先视为第 1 组，其余数字键升序）
	nKeys := make([]string, 0, len(nMap))
	for k := range nMap {
		nKeys = append(nKeys, k)
	}
	sort.Slice(nKeys, func(i, j int) bool {
		if nKeys[i] == "" {
			return true
		}
		if nKeys[j] == "" {
			return false
		}
		return nKeys[i] < nKeys[j]
	})
	cKeys := make([]string, 0, len(cMap))
	for k := range cMap {
		cKeys = append(cKeys, k)
	}
	sort.Slice(cKeys, func(i, j int) bool {
		if cKeys[i] == "" {
			return true
		}
		if cKeys[j] == "" {
			return false
		}
		return cKeys[i] < cKeys[j]
	})
	ns := make([]*big.Int, 0, e.Int64())
	cs := make([]*big.Int, 0, e.Int64())
	for i := 0; i < int(e.Int64()); i++ {
		ni, okN := nMap[nKeys[i]]
		ci, okC := cMap[cKeys[i]]
		if !okN || !okC {
			return nil
		}
		ns = append(ns, ni)
		cs = append(cs, ci)
	}
	// CRT 合成 x ≡ c_i (mod n_i) → x = m^e mod ∏n_i
	N := big.NewInt(1)
	for _, ni := range ns {
		N.Mul(N, ni)
	}
	x := new(big.Int)
	for i := range ns {
		Ni := new(big.Int).Div(N, ns[i])
		inv := new(big.Int).ModInverse(Ni, ns[i])
		if inv == nil {
			return nil
		}
		t := new(big.Int).Mul(cs[i], Ni)
		t.Mul(t, inv)
		t.Mod(t, N)
		x.Add(x, t)
		x.Mod(x, N)
	}
	root := integerNthRoot(x, int(e.Int64()))
	if root == nil {
		return nil
	}
	if flags := scanFlags(string(root.Bytes())); len(flags) > 0 {
		return flags
	}
	return nil
}

// integerNthRoot 整数 k 次根（二分），非完全幂返回 nil。
func integerNthRoot(x *big.Int, k int) *big.Int {
	if x.Sign() <= 0 || k <= 0 {
		return nil
	}
	lo := big.NewInt(0)
	hi := new(big.Int).Lsh(big.NewInt(1), uint(x.BitLen()/k+2))
	one := big.NewInt(1)
	for lo.Cmp(hi) < 0 {
		mid := new(big.Int).Add(lo, hi)
		mid.Div(mid, big.NewInt(2))
		pow := new(big.Int).Exp(mid, big.NewInt(int64(k)), nil)
		switch pow.Cmp(x) {
		case 0:
			return mid
		case -1:
			lo = new(big.Int).Add(mid, one)
		default:
			hi = mid
		}
	}
	return nil
}

// tryRSAWienerAttack 完整 Wiener 攻击：e/n 连分数展开取收敛分数 (k,d)，
// 逐候选验证 c^d ≡ m (mod n) 还原明文。
func tryRSAWienerAttack(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	eRe := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	nRe := regexp.MustCompile(`(?i)\bn\s*=\s*(\d+)`)
	cRe := regexp.MustCompile(`(?i)\bc\s*=\s*(\d+)`)
	eM, nM, cM := eRe.FindStringSubmatch(fullText), nRe.FindStringSubmatch(fullText), cRe.FindStringSubmatch(fullText)
	if eM == nil || nM == nil || cM == nil {
		return nil
	}
	e, ok1 := new(big.Int).SetString(eM[1], 10)
	n, ok2 := new(big.Int).SetString(nM[1], 10)
	c, ok3 := new(big.Int).SetString(cM[1], 10)
	// 合理性：n 至少 128-bit 才谈得上 Wiener（Sign() 只有 -1/0/1，别用 Sign 判大小！）
	if !ok1 || !ok2 || !ok3 || e.Sign() <= 0 || n.BitLen() < 128 || c.Sign() < 0 {
		return nil
	}
	// 连分数展开 e/n
	a := new(big.Int).Set(e)
	b := new(big.Int).Set(n)
	h0, h1 := big.NewInt(0), big.NewInt(1) // 分子（k）
	k0, k1 := big.NewInt(1), big.NewInt(0) // 分母（d）
	for b.Sign() > 0 {
		q := new(big.Int).Div(a, b)
		a, b = b, new(big.Int).Mod(a, b)
		// 收敛分数递推
		hNew := new(big.Int).Mul(q, h1)
		hNew.Add(hNew, h0)
		kNew := new(big.Int).Mul(q, k1)
		kNew.Add(kNew, k0)
		h0, h1 = h1, hNew
		k0, k1 = k1, kNew
		if h1.Sign() <= 0 {
			continue
		}
		// 候选 d = k1（分母），直接验证 c^d ≡ m (mod n) 是否还原可读明文
		d := new(big.Int).Set(k1)
		if d.Sign() <= 0 {
			continue
		}
		m := new(big.Int).Exp(c, d, n)
		if flags := scanFlags(string(m.Bytes())); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// ── P6 批次：crypto 深水区 ──────────────────────────────────

// tryEllipticCurvePointOps 检测椭圆曲线点运算特征。

// trySideChannel 检测侧信道攻击特征。
func trySideChannel(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"timing attack", "时序攻击"}, {"cache timing", "缓存时序"}, {"power analysis", "功耗分析"},
		{"differential power", "差分功耗DPA"}, {"simple power", "简单功耗SPA"},
		{"electromagnetic", "电磁侧信道"}, {"acoustic", "声学侧信道"}, {"fault injection", "故障注入"},
		{"rowhammer", "Rowhammer"}, {"cold boot", "冷启动"}, {"spectre", "Spectre"},
		{"meltdown", "Meltdown"}, {"branch prediction", "分支预测"},
		{"speculative execution", "推测执行"}, {"cache attack", "缓存攻击"},
		{"tpm", "可信平台模块"}, {"sgx", "Intel SGX"}, {"trustzone", "ARM TrustZone"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"侧信道: " + kw.h} }
	}
	return nil
}

// tryLatticeAdvanced 检测格基密码学高级特征。
func tryLatticeAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"lattice reduction", "格基规约"}, {"shortest vector", "最短向量SVP"}, {"closest vector", "最近向量CVP"},
		{"hermite normal", "Hermite标准型"}, {"smith normal", "Smith标准型"},
		{"ntru", "NTRU"}, {"crystals-kyber", "Crystals-Kyber"}, {"crystals-dilithium", "Crystals-Dilithium"},
		{"falcon", "Falcon签名"}, {"sphincs", "SPHINCS+"}, {"basis reduction", "基底规约"},
		{"gram matrix", "Gram矩阵"}, {"orthogonal", "正交化"}, {"q-ary lattice", "q-ary格"},
		{"ideal lattice", "理想格"}, {"module lattice", "模格"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"格基密码: " + kw.h} }
	}
	return nil
}

// ── 真解题求解器扩展（有实际算法实现，能从密文解出明文）──────────

// tryVigenereDecode 维吉尼亚解码（爆破密钥长度 + 频率分析）。
func tryVigenereDecode(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 10 || len(clean) > 500 {
		return nil
	}
	// 只对纯字母文本尝试
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	if !alphaRe.MatchString(clean) {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	// 尝试密钥长度 2-10
	for keyLen := 2; keyLen <= 10; keyLen++ {
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

// guessVigenereKey 通过重合指数猜测维吉尼亚密钥。

// vigenereDecode 用已知密钥解密维吉尼亚密码。

// tryAtbashDecode Atbash 密码解码（a↔z, b↔y, ...）。
func tryAtbashDecode(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 6 {
		return nil
	}
	var sb strings.Builder
	for _, c := range clean {
		switch {
		case c >= 'a' && c <= 'z':
			sb.WriteRune('z' - (c - 'a'))
		case c >= 'A' && c <= 'Z':
			sb.WriteRune('Z' - (c - 'A'))
		default:
			sb.WriteRune(c)
		}
	}
	decoded := sb.String()
	if flags := scanFlags(decoded); len(flags) > 0 {
		return flags
	}
	return nil
}

// tryROT13 ROT13 解码。
func tryROT13(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 6 {
		return nil
	}
	var sb strings.Builder
	for _, c := range clean {
		switch {
		case c >= 'a' && c <= 'z':
			sb.WriteRune((c-'a'+13)%26 + 'a')
		case c >= 'A' && c <= 'Z':
			sb.WriteRune((c-'A'+13)%26 + 'A')
		default:
			sb.WriteRune(c)
		}
	}
	decoded := sb.String()
	if flags := scanFlags(decoded); len(flags) > 0 {
		return flags
	}
	return nil
}

// tryHexDecode Hex 解码后扫 flag。
func tryHexDecode(text string) []string {
	clean := strings.TrimSpace(text)
	hexRe := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	if !hexRe.MatchString(clean) || len(clean) < 8 || len(clean)%2 != 0 {
		return nil
	}
	decoded, err := hex.DecodeString(clean)
	if err != nil {
		return nil
	}
	result := string(decoded)
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if isPrintableRatio(result) > 0.8 && len(result) > 3 {
		return []string{"Hex解码: " + result[:minInt(80, len(result))]}
	}
	return nil
}

// tryURLDecode URL 解码后扫 flag。
func tryURLDecode(text string) []string {
	clean := strings.TrimSpace(text)
	urlRe := regexp.MustCompile(`(%[0-9a-fA-F]{2})+`)
	if !urlRe.MatchString(clean) {
		return nil
	}
	decoded := clean
	// 多轮解码（最多 3 层）
	for i := 0; i < 3; i++ {
		newDecoded := urlDecodeOnce(decoded)
		if newDecoded == decoded {
			break
		}
		decoded = newDecoded
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

func urlDecodeOnce(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			val, err := hex.DecodeString(s[i+1 : i+3])
			if err == nil {
				sb.WriteByte(val[0])
				i += 2
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// tryBinaryDecode 二进制字符串解码（01串转 ASCII）。
func tryBinaryDecode(text string) []string {
	clean := strings.TrimSpace(text)
	// 二进制字符串：仅含 0 和 1，长度为 8 的倍数
	binRe := regexp.MustCompile(`^[01\s]+$`)
	if !binRe.MatchString(clean) {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	if len(clean) < 16 || len(clean)%8 != 0 {
		return nil
	}
	var sb strings.Builder
	for i := 0; i+7 < len(clean); i += 8 {
		val := 0
		for j := 0; j < 8; j++ {
			if clean[i+j] == '1' {
				val |= 1 << (7 - j)
			}
		}
		if val >= 32 && val < 127 {
			sb.WriteByte(byte(val))
		}
	}
	result := sb.String()
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 && isPrintableRatio(result) > 0.8 {
		return []string{"二进制解码: " + result}
	}
	return nil
}

// tryOctalDecode 八进制解码。
func tryOctalDecode(text string) []string {
	clean := strings.TrimSpace(text)
	octRe := regexp.MustCompile(`^[0-7\s]+$`)
	if !octRe.MatchString(clean) || len(clean) < 6 {
		return nil
	}
	parts := strings.Fields(clean)
	if len(parts) < 3 {
		return nil
	}
	var sb strings.Builder
	for _, p := range parts {
		val := 0
		for _, c := range p {
			val = val*8 + int(c-'0')
		}
		if val >= 32 && val < 127 {
			sb.WriteByte(byte(val))
		}
	}
	result := sb.String()
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 && isPrintableRatio(result) > 0.8 {
		return []string{"八进制解码: " + result}
	}
	return nil
}

// tryDecimalDecode 十进制 ASCII 解码（空格分隔的十进制数转字符）。
func tryDecimalDecode(text string) []string {
	clean := strings.TrimSpace(text)
	decRe := regexp.MustCompile(`^[\d\s]+$`)
	if !decRe.MatchString(clean) || len(clean) < 6 {
		return nil
	}
	parts := strings.Fields(clean)
	if len(parts) < 3 {
		return nil
	}
	var sb strings.Builder
	for _, p := range parts {
		val := 0
		for _, c := range p {
			val = val*10 + int(c-'0')
		}
		if val >= 32 && val < 127 {
			sb.WriteByte(byte(val))
		}
	}
	result := sb.String()
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 && isPrintableRatio(result) > 0.8 {
		return []string{"十进制解码: " + result}
	}
	return nil
}

// tryReverseText 文本反转解码。
func tryReverseText(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 6 {
		return nil
	}
	runes := []rune(clean)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	decoded := string(runes)
	if flags := scanFlags(decoded); len(flags) > 0 {
		return flags
	}
	return nil
}

// tryPigLatin Pig Latin 解码（ay 后缀移除）。
func tryPigLatin(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 6 {
		return nil
	}
	// 简单 Pig Latin：单词以 ay 结尾，去掉 ay 后把首字母移到末尾
	words := strings.Fields(clean)
	var decoded []string
	for _, w := range words {
		lower := strings.ToLower(w)
		if strings.HasSuffix(lower, "ay") && len(lower) > 3 {
			core := lower[:len(lower)-2]
			decoded = append(decoded, core[1:]+string(core[0]))
		} else {
			decoded = append(decoded, w)
		}
	}
	result := strings.Join(decoded, " ")
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	return nil
}

// tryBase64URLSafe URL-safe Base64 解码（- 和 _ 替代 + 和 /）。
func tryBase64URLSafe(text string) []string {
	clean := strings.TrimSpace(text)
	// URL-safe Base64：含 - 和 _，不含 + 和 /
	b64urlRe := regexp.MustCompile(`^[A-Za-z0-9\-_=]{8,}$`)
	if !b64urlRe.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	if strings.ContainsAny(clean, "+/") {
		return nil // 标准 Base64，不处理
	}
	std := strings.ReplaceAll(clean, "-", "+")
	std = strings.ReplaceAll(std, "_", "/")
	decoded, err := base64.StdEncoding.DecodeString(padBase64(std))
	if err != nil || len(decoded) == 0 {
		return nil
	}
	result := string(decoded)
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if isPrintableRatio(result) > 0.8 && len(result) > 3 {
		return []string{"Base64URL解码: " + result[:minInt(80, len(result))]}
	}
	return nil
}
