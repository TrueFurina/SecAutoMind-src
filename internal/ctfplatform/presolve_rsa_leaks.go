// presolve_rsa_leaks.go —— RSA 泄露参数类确定性求解器（2026-10-15 cross-bench 立尺驱动）
//
// 三道玄盾杯/西湖论剑真题的攻击实现，全部经过 sha256 真值验证：
//   - rsa_phi_pinv：已知 phi(n) 与 pinv=p^{-1} mod q、qinv=q^{-1} mod p，n 未给出
//     （玄盾杯 ExcitingInverse）。攻击见 tryRSAPhiPinv 注释处的完整推导。
//   - legendre_bit_phi：phi 泄露 + 逐位 Legendre 符号加密（玄盾杯 SimpleLegendre）。
//   - hastad_broadcast 的裸数字解析扩展见 presolve_crypto.go（玄盾杯 ezRSA）。
//
// 10733（DASCTF CRYPTO-02，hint=(e*p+e^2)^q mod n 型）的攻击**已于 2026-10-16 实现**，
// 见 presolve_rsa_hint.go::tryRSAHighExpHint。此前本条记为「能力缺口，须二元 Coppersmith」——
// **该归因被本轮证伪**：无需格。关键是 hint ≡ e^{2q} (mod p)（mod p 下 e·p 项消失），
// 而 W=e^n mod n 满足 W ≡ e^q (mod p)（因 n≡q mod p-1），故 W²≡hint (mod p)，
// 直接 gcd(W²−hint, n)=p。解密侧 e=2^k 且 p≡q≡3 (mod 4) 时走奇数阶子群求逆 + 一轮 Rabin。
package ctfplatform

import (
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// bigDecimalRe 提取长十进制整数（≥40 位，约 133 bit）——RSA 参数/密文的最小形态。
var bigDecimalRe = regexp.MustCompile(`\b\d{40,}\b`)

// extractBigDecimalInts 按出现顺序提取文本中的长十进制整数。
func extractBigDecimalInts(text string) []*big.Int {
	var out []*big.Int
	for _, m := range bigDecimalRe.FindAllString(text, -1) {
		if v, ok := new(big.Int).SetString(m, 10); ok {
			out = append(out, v)
		}
	}
	return out
}

// parsePublicExponent 从文本解析公钥指数 e：优先 "e=65537" 形式，
// 退化到裸行小整数（output 文件首行），再退化到 65537。
func parsePublicExponent(text string) *big.Int {
	if m := regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`).FindStringSubmatch(text); m != nil {
		if v, ok := new(big.Int).SetString(m[1], 10); ok && v.Sign() > 0 && v.BitLen() < 64 {
			return v
		}
	}
	if m := regexp.MustCompile(`(?m)^\s*(\d{1,12})\s*$`).FindStringSubmatch(text); m != nil {
		if v, ok := new(big.Int).SetString(m[1], 10); ok && v.Sign() > 0 && v.Cmp(big.NewInt(3)) >= 0 && v.BitLen() < 64 {
			return v
		}
	}
	return big.NewInt(65537)
}

// tryRSAPhiPinv 攻击「phi + pinv/qinv 泄露」型 RSA（玄盾杯 ExcitingInverse）。
//
// 已知 e, phi=(p-1)(q-1), c=m^e mod n, pinv=p^{-1} mod q, qinv=q^{-1} mod p，n 未给出。
// 推导：设 k=(p·pinv-1)/q, j=(q·qinv-1)/p（均为正整数），则
//
//	p·pinv - k·q = 1 …(I)   q·qinv - j·p = 1 …(II)
//
// (I)×qinv − (II)×pinv 消去 pq 项得 pinv·qinv − kj = 1，即 kj = pinv·qinv − 1（记 w）。
// 由 (I)(II) 解出 p = qinv + k, q = pinv + j。代入 phi=(p-1)(q-1)，记
// u=qinv−1, v=pinv−1，得关于 k 的二次方程：
//
//	v·k² + (u·v + w − phi)·k + u·w = 0
//
// 判别式须为完全平方数；两根分别对应 (k,j) 与 (j,k)（即 p/q 互换，n 与 phi 不变）。
// 数值验证：随机 256-bit 素数 3/3 精确恢复；真题 output 实跑命中 sha256 真值。
func tryRSAPhiPinv(text string) []string {
	nums := extractBigDecimalInts(text)
	if len(nums) < 4 {
		return nil
	}
	// 按位长聚类：两个 ~2× 长（phi/c 候选）与两个 ~1× 长（pinv/qinv 候选），
	// 用最大位长间隙定位切分点（2048 vs 1024 的间隙约 1024，远大于噪声）。
	sorted := append([]*big.Int(nil), nums...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].BitLen() > sorted[j].BitLen() })
	split, bestGap := -1, 0
	for i := 1; i < len(sorted); i++ {
		if gap := sorted[i-1].BitLen() - sorted[i].BitLen(); gap > bestGap {
			bestGap, split = gap, i
		}
	}
	if split < 2 || bestGap < 128 || len(sorted)-split < 2 {
		return nil
	}
	bigs, smalls := sorted[:split], sorted[split:]
	if len(bigs) > 4 {
		bigs = bigs[:4]
	}
	if len(smalls) > 4 {
		smalls = smalls[:4]
	}
	e := parsePublicExponent(text)
	for i := 0; i < len(bigs); i++ {
		for j := 0; j < len(bigs); j++ {
			if i == j {
				continue
			}
			for a := 0; a < len(smalls); a++ {
				for b := 0; b < len(smalls); b++ {
					if a == b {
						continue
					}
					if flag := rsaPhiPinvAttempt(e, bigs[i], bigs[j], smalls[a], smalls[b]); flag != "" {
						return []string{flag}
					}
				}
			}
		}
	}
	return nil
}

// rsaPhiPinvAttempt 一次 (phi, c, pinv, qinv) 组合的求解；成功返回 flag，否则空串。
func rsaPhiPinvAttempt(e, phi, c, pinv, qinv *big.Int) string {
	if e == nil || e.Sign() <= 0 {
		e = big.NewInt(65537)
	}
	u := new(big.Int).Sub(qinv, big.NewInt(1))
	v := new(big.Int).Sub(pinv, big.NewInt(1))
	w := new(big.Int).Mul(pinv, qinv)
	w.Sub(w, big.NewInt(1))
	if w.Sign() <= 0 {
		return ""
	}
	B := new(big.Int).Mul(u, v)
	B.Add(B, w)
	B.Sub(B, phi) // B = u·v + w − phi
	C := new(big.Int).Mul(u, w)
	var roots []*big.Int
	if v.Sign() == 0 {
		// v=0（pinv=1）退化为线性方程 B·k + C = 0
		if B.Sign() == 0 {
			return ""
		}
		if new(big.Int).Rem(C, B).Sign() != 0 {
			return ""
		}
		roots = []*big.Int{new(big.Int).Neg(new(big.Int).Div(C, B))}
	} else {
		disc := new(big.Int).Mul(B, B)
		disc.Sub(disc, new(big.Int).Lsh(new(big.Int).Mul(v, C), 2)) // B² − 4·v·C
		if disc.Sign() < 0 {
			return ""
		}
		r := new(big.Int).Sqrt(disc)
		if new(big.Int).Mul(r, r).Cmp(disc) != 0 {
			return ""
		}
		twoV := new(big.Int).Lsh(v, 1)
		for _, num := range []*big.Int{
			new(big.Int).Sub(r, B),  // −B + r
			new(big.Int).Neg(new(big.Int).Add(r, B)), // −B − r
		} {
			if new(big.Int).Rem(num, twoV).Sign() != 0 {
				continue
			}
			roots = append(roots, new(big.Int).Div(num, twoV))
		}
	}
	for _, k := range roots {
		if flag := rsaPhiPinvFinish(e, phi, c, pinv, qinv, w, k); flag != "" {
			return flag
		}
	}
	return ""
}

// rsaPhiPinvFinish 由候选 k 完成 p/q 恢复、校验与解密。
func rsaPhiPinvFinish(e, phi, c, pinv, qinv, w, k *big.Int) string {
	if k.Sign() <= 0 || new(big.Int).Rem(w, k).Sign() != 0 {
		return ""
	}
	j := new(big.Int).Div(w, k)
	if j.Sign() <= 0 {
		return ""
	}
	p := new(big.Int).Add(qinv, k)
	q := new(big.Int).Add(pinv, j)
	if p.Sign() <= 0 || q.Sign() <= 0 {
		return ""
	}
	chk := new(big.Int).Sub(p, big.NewInt(1))
	chk.Mul(chk, new(big.Int).Sub(q, big.NewInt(1)))
	if chk.Cmp(phi) != 0 {
		return ""
	}
	n := new(big.Int).Mul(p, q)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return ""
	}
	m := new(big.Int).Exp(c, d, n)
	if flags := scanFlags(string(m.Bytes())); len(flags) > 0 {
		return flags[0]
	}
	return ""
}

// tryLegendreBitPhi 攻击「phi 泄露 + 逐位 Legendre 符号加密」型 RSA
// （玄盾杯 SimpleLegendre）。
//
// 挑战结构：明文的每个二进制位 bi 被加密为 c = x^(2·br+bi)·r² mod N，
// 其中 br 是随机 r 的二进制、x 是满足 (x|p)=(x|q)=−1 的公开密钥。
// 因此 (c|p) = (x|p)^bi·(r²|p) = (−1)^bi —— 逐位计算 Legendre 符号即得明文比特。
// 关键点：Jacobi 符号 (c/N)=(c|p)·(c|q)=(−1)·(−1)=+1 对两个比特值**同值**，
// 必须先用泄露的 phi 分解 N（p+q = N−phi+1，解二次方程），再逐位算 (c|p)。
func tryLegendreBitPhi(text string) []string {
	nums := extractBigDecimalInts(text)
	if len(nums) < 12 { // phi + N + ≥10 个密文位
		return nil
	}
	phi, n := nums[0], nums[1]
	if n.BitLen() < 256 || phi.BitLen() < 256 {
		return nil
	}
	p, _, ok := factorFromPhi(n, phi)
	if !ok {
		return nil
	}
	half := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1) // (p−1)/2
	minusOne := new(big.Int).Sub(p, big.NewInt(1))
	var sb strings.Builder
	for _, c := range nums[2:] {
		leg := new(big.Int).Exp(c, half, p)
		if leg.Cmp(minusOne) == 0 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	bits := sb.String()
	if len(bits) < 8 {
		return nil
	}
	m, ok := new(big.Int).SetString(bits, 2)
	if !ok {
		return nil
	}
	if flags := scanFlags(string(m.Bytes())); len(flags) > 0 {
		return flags
	}
	return nil
}

// factorFromPhi 由 phi(n) 分解 n：p+q = n−phi+1，p/q 为 x²−(p+q)x+n 的根。
func factorFromPhi(n, phi *big.Int) (*big.Int, *big.Int, bool) {
	s := new(big.Int).Sub(n, phi)
	s.Add(s, big.NewInt(1))
	disc := new(big.Int).Mul(s, s)
	disc.Sub(disc, new(big.Int).Lsh(n, 2)) // s² − 4n
	if disc.Sign() < 0 {
		return nil, nil, false
	}
	r := new(big.Int).Sqrt(disc)
	if new(big.Int).Mul(r, r).Cmp(disc) != 0 {
		return nil, nil, false
	}
	p := new(big.Int).Sub(s, r)
	q := new(big.Int).Add(s, r)
	p.Rsh(p, 1)
	q.Rsh(q, 1)
	if p.Sign() <= 0 || q.Sign() <= 0 || new(big.Int).Mul(p, q).Cmp(n) != 0 {
		return nil, nil, false
	}
	return p, q, true
}
