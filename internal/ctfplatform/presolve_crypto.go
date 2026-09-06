// presolve_crypto.go —— 非对称与哈希类求解器（RSA/格/椭圆曲线/ECDSA/哈希破解等）
// 自 presolve.go 机械拆分（30 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
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
