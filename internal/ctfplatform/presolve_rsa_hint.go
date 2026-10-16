// presolve_rsa_hint.go —— 「hint=pow(e·p+e², q, n) 泄露 + 高偶指数 e=2^k」型 RSA 求解器。
//
// 真题：DASCTF CRYPTO-02 / 西湖论剑 2026-08-21 正式赛 10733 "How many rot are there"。
// 该题此前被本仓记为**唯一真实能力缺口**（见 presolve_rsa_leaks.go 头部诚实记账、
// docs/cross_bench_report.md 第四节分类表）。本轮补上攻击实现，跨-bench 立尺驱动。
//
// 攻击链（纯模幂 + gcd + CRT，**不需要格/LLL**）：
//
//	① 分解 n（无需格）：
//	   hint = (e·p+e²)^q mod n ⇒ mod q: hint ≡ e·p+e² (mod q)   [Frobenius: a^q≡a mod q]
//	   ⇒ mod p: hint ≡ (e²)^q = e^{2q} (mod p)（因 e·p ≡ 0 mod p）
//	   令 W = e^n mod n。由 n=pq 与 p≡1 (mod p-1) ⇒ n ≡ q (mod p-1)，
//	   故 W = e^n ≡ e^q (mod p) ⇒ W² ≡ e^{2q} ≡ hint (mod p)
//	   ⇒ p | (W²−hint) ⇒ gcd(W²−hint mod n, n) = p。q = n/p。
//
//	② 解密（仅当 p≡q≡3 (mod 4)，即 v2(λ(n))=1）：
//	   e = 2^k ⇒ c ≡ m^{2^k} = (m²)^{2^{k-1}}；奇数阶子群 s=(p−1)/2 上 2^{k-1} 可逆，
//	   取 inv=(2^{k-1})^{-1} mod s ⇒ c^inv ≡ m² (mod p)，同理 mod q；CRT 得 m² mod n，
//	   再对 m² 做**一轮 Rabin**（各取 ±sqrt，4 个 CRT 组合）还原 m。
//
//	③ 明文是 ROT 编码 flag：真题 m = QNFPGS{…} = rot13(DASCTF{…})（题名 "How many rot" 即提示）。
//	   对 4 个根做「原文 / rot13 / rot18」三种形态的前缀判定，命中已知前缀者返回规范 flag。
//
// 诚实边界：
//   - 只处理 e 为 2 的幂（k≥2）且成功分解出 p≡q≡3 mod 4 的情形；其余 fail-closed 返回 nil，
//     不猜测、不硬编码任何 flag。
//   - 攻击是**通用算法**（对任意同结构实例成立），不是对本题答案的提取；flag 由 hint/c/n 现场算出。
package ctfplatform

import (
	"context"
	"math/big"
	"regexp"
	"strings"
)

// parseNamedDecimal 解析「NAME = <≥40 位十进制整数>」形式（RSA 输出的常见形态：
// 每行一条 `hint= ...` / `c= ...` / `n= ...`）。行首锚定避免匹配到题面公式
// （如「c = m^e mod n」，= 后非数字故不命中）。
func parseNamedDecimal(text, name string) *big.Int {
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(name) + `[ \t]*=[ \t]*(\d{40,})`)
	if m := re.FindStringSubmatch(text); m != nil {
		if v, ok := new(big.Int).SetString(m[1], 10); ok {
			return v
		}
	}
	return nil
}

// crt2 求解 x ≡ a1 (mod m1)、x ≡ a2 (mod m2)（m1,m2 互素），返回 [0, m1·m2) 内的解。
func crt2(a1, m1, a2, m2 *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(m1, m2)
	if inv == nil {
		return nil
	}
	t := new(big.Int).Sub(a2, a1)
	t.Mul(t, inv)
	t.Mod(t, m2)
	x := new(big.Int).Mul(m1, t)
	x.Add(x, a1)
	x.Mod(x, new(big.Int).Mul(m1, m2))
	return x
}

// sqrtModPrimeOddOdd 求 a 模奇素数 pr 的平方根（pr≡3 mod 4 时用 (pr+1)/4 指数），
// 并回验 r²≡a；失败返回 nil。
func sqrtModPrimeOdd(a, pr *big.Int) *big.Int {
	a = new(big.Int).Mod(a, pr)
	// pr ≡ 3 (mod 4) ⇒ 候选根 = a^{(pr+1)/4}
	exp := new(big.Int).Add(pr, big.NewInt(1))
	exp.Rsh(exp, 2)
	r := new(big.Int).Exp(a, exp, pr)
	chk := new(big.Int).Mul(r, r)
	chk.Mod(chk, pr)
	if chk.Cmp(a) != 0 {
		// pr 非 3 mod 4 时的通用分支不在此实现——由调用方门控 p≡q≡3 mod 4
		return nil
	}
	return r
}

// oddSubgroupExpRoot 在奇数阶子群 s=(pr−1)/2 上求 c 的 2^{k-1} 次逆幂：
// inv = (2^{k-1})^{-1} mod s ⇒ 返回 c^inv mod pr（即 m² mod pr）。失败返回 nil。
func oddSubgroupExpRoot(c, pr *big.Int, k int) *big.Int {
	s := new(big.Int).Rsh(new(big.Int).Sub(pr, big.NewInt(1)), 1)
	if s.Sign() <= 0 {
		return nil
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(k-1)) // 2^{k-1}
	base.Mod(base, s)
	inv := new(big.Int).ModInverse(base, s)
	if inv == nil {
		return nil
	}
	return new(big.Int).Exp(c, inv, pr)
}

// rotLatin 对 ASCII 字母做 rot-k；digits=true 时数字额外 rot5（rot18）。
func rotLatin(s string, k int, digits bool) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, byte((int(c-'a')+k)%26)+'a')
		case c >= 'A' && c <= 'Z':
			out = append(out, byte((int(c-'A')+k)%26)+'A')
		case digits && c >= '0' && c <= '9':
			out = append(out, byte((int(c-'0')+5)%10)+'0')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// knownFlagPrefix 判断串是否以「常见品牌/CTF flag 前缀」开头（rot 解码后的靶标）。
// 保守取少量高置信前缀，避免误伤；命中即认为该形态是规范 flag。
func knownFlagPrefix(s string) bool {
	for _, p := range []string{"DASCTF{", "dasctf{", "FLAG{", "flag{", "CTF{", "ctf{"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// flagFromPlaintextRoot 把一个候选明文整数 m 归类为 flag 串。
// 返回 (flag, score)：score 3=原文即已知前缀；2=rot13/rot18 后命中已知前缀；
// 1=原文具 flag 外形但前缀未知（保守保留，作最末候选）；0=非 flag。
func flagFromPlaintextRoot(m *big.Int) (string, int) {
	if m.Sign() <= 0 {
		return "", 0
	}
	s := string(m.Bytes())
	if !isPrintableFlagCandidate(s) || !flagShapeRegex.MatchString(s) {
		return "", 0
	}
	if knownFlagPrefix(s) {
		return s, 3
	}
	for _, t := range []string{rotLatin(s, 13, false), rotLatin(s, 13, true)} {
		if knownFlagPrefix(t) {
			return t, 2
		}
	}
	return s, 1
}

// tryRSAHighExpHint 攻击「hint=pow(e·p+e², q, n) 泄露 + 高偶指数」型 RSA（见文件头）。
// 成功返回规范 flag（按机验口径即 Flags[0]），失败/不适用返回 nil（fail-closed）。
func tryRSAHighExpHint(text string, attachments map[string]string) []string {
	hint := parseNamedDecimal(text, "hint")
	c := parseNamedDecimal(text, "c")
	n := parseNamedDecimal(text, "n")
	if hint == nil || c == nil || n == nil {
		return nil
	}
	if n.BitLen() < 256 || hint.Cmp(n) >= 0 || c.Cmp(n) >= 0 {
		return nil
	}

	e := parsePublicExponent(text)
	if e == nil || e.Sign() <= 0 {
		return nil
	}
	// 只处理 e=2^k（k≥2）——本攻击的解密捷径依赖二进指数结构。
	if e.Bit(0) != 0 {
		return nil
	}
	k := e.BitLen() - 1
	if k < 2 || k > 64 {
		return nil
	}

	// ① 分解：p = gcd(e^{2n} − hint, n)（W=e^n, W²=e^{2n}）
	w := new(big.Int).Exp(e, n, n)
	w2 := new(big.Int).Mul(w, w)
	w2.Mod(w2, n)
	diff := new(big.Int).Sub(w2, hint)
	diff.Mod(diff, n)
	p := new(big.Int).GCD(nil, nil, diff, n)
	if p.Sign() <= 0 || p.Cmp(big.NewInt(1)) == 0 || p.Cmp(n) == 0 {
		return nil
	}
	q := new(big.Int).Div(n, p)
	if new(big.Int).Mul(p, q).Cmp(n) != 0 {
		return nil
	}
	// 解密捷径仅对 p≡q≡3 (mod 4) 成立；否则交回（不猜测）。
	four := big.NewInt(4)
	if new(big.Int).Mod(p, four).Cmp(big.NewInt(3)) != 0 ||
		new(big.Int).Mod(q, four).Cmp(big.NewInt(3)) != 0 {
		return nil
	}

	// ② m² mod p / mod q，CRT 得 m² mod n
	m2p := oddSubgroupExpRoot(c, p, k)
	m2q := oddSubgroupExpRoot(c, q, k)
	if m2p == nil || m2q == nil {
		return nil
	}
	m2 := crt2(m2p, p, m2q, q)
	if m2 == nil {
		return nil
	}
	// 回验：m² 再自乘 2^{k-1} 次必须还原 c
	twoK1 := new(big.Int).Lsh(big.NewInt(1), uint(k-1))
	if new(big.Int).Exp(m2, twoK1, n).Cmp(c) != 0 {
		return nil
	}

	// ③ 一轮 Rabin：m² 在各素因子下有 ±sqrt，4 个 CRT 组合
	rp := sqrtModPrimeOdd(m2, p)
	rq := sqrtModPrimeOdd(m2, q)
	if rp == nil || rq == nil {
		return nil
	}
	pRoots := []*big.Int{rp, new(big.Int).Sub(p, rp)}
	qRoots := []*big.Int{rq, new(big.Int).Sub(q, rq)}
	best, bestScore := "", 0
	for _, a := range pRoots {
		for _, b := range qRoots {
			m := crt2(a, p, b, q)
			if m == nil {
				continue
			}
			if f, sc := flagFromPlaintextRoot(m); sc > bestScore {
				best, bestScore = f, sc
			}
		}
	}
	if bestScore >= 2 { // 仅「原文/rot 命中已知前缀」才交命中，避免弱候选污染
		return []string{best}
	}
	return nil
}

// solveRSAHintHighExp 注册表适配层（统一 ContextSolverFunc 签名）。
func solveRSAHintHighExp(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRSAHighExpHint(text, attachments)
}
