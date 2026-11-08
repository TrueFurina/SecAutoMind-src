// presolve_halfprime.go —— 破碎素数恢复 + RSA OAEP 解密（2026-10-26 固化）。
//
// 实证：HTB Cyber Apocalypse 2024 "partial_tenacity"（cybench 采源，锚
// 0b5ad12b…）。题面给 n/ct + p 的偶数位十进制串 + q 的奇数位十进制串
// （p=str(p)[::2]、q=str(q)[1::2]）→ branch-and-prune 低位恢复完整 p/q →
// RSA-OAEP 解密。数学核心：逐位枚举已知位之外的数字，用 `p*q ≡ n (mod 10^k)`
// 剪枝；位数假设 (Lp,Lq) 由个位约束扫描自动锁定（手解时踩过 (155,154) 假设
// 陷阱——个位扫描秒杀）。
//
// 诚实口径：仅处理"十进制位碎片恢复"范式；OAEP 需公钥参数齐全。非此形态
// 一律返回 nil（不猜）。
package ctfplatform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"math/big"
	"regexp"
	"strings"
)

// tryHalfPrimeOAEP 从题面文本识别 n/ct/p 半串/q 半串并尝试恢复+解密。
// 成功返回 flag 候选（经 scanFlags 过滤）。
func tryHalfPrimeOAEP(text string) []string {
	// 材料识别：必须同时有 p=、q= 的十进制半串与 n=、ct=（hex）
	pHalf := extractLabeledDecimal(text, "p")
	qHalf := extractLabeledDecimal(text, "q")
	nStr := extractLabeledDecimal(text, "n")
	ctHex := extractLabeledHex(text, "ct")
	if pHalf == "" || qHalf == "" || nStr == "" || ctHex == "" {
		return nil
	}
	// 串长度差 1（[::2] vs [1::2]）是本范式的签名
	if len(pHalf) != len(qHalf)+1 && len(qHalf) != len(pHalf)+1 {
		return nil
	}
	n, ok := new(big.Int).SetString(nStr, 10)
	if !ok || n.BitLen() < 512 {
		return nil
	}
	ct, err := hexBytes(ctHex)
	if err != nil {
		return nil
	}
	// 位数假设扫描：p/q 全长 ∈ {2*len-1, 2*len, 2*len+1}，个位约束过滤
	nStr_ := n.String()
	for Lp := 2*len(pHalf) - 1; Lp <= 2*len(pHalf)+1; Lp++ {
		for Lq := 2*len(qHalf) - 1; Lq <= 2*len(qHalf)+1; Lq++ {
			pK := knownDigits(pHalf, Lp, 0) // 偶位（高位 0 起）
			qK := knownDigits(qHalf, Lq, 1) // 奇位
			if !unitDigitFeasible(pK, qK, Lp, Lq, nStr_) {
				continue
			}
			p, q, found := branchPruneHalfPrime(pK, qK, Lp, Lq, n)
			if !found {
				continue
			}
			flags := decryptRSAOAEP(n, p, q, ct)
			if len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}

func extractLabeledDecimal(text, label string) string {
	re := regexp.MustCompile(`(?m)^` + label + `\s*=\s*([0-9]+)\s*$`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

func extractLabeledHex(text, label string) string {
	re := regexp.MustCompile(`(?m)^` + label + `\s*=\s*([0-9a-fA-F]+)\s*$`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

func hexBytes(h string) ([]byte, error) {
	if len(h)%2 != 0 {
		h = "0" + h
	}
	return decodeHex(h)
}

var errBadHex = &hexError{}

type hexError struct{}

func (e *hexError) Error() string { return "invalid hex" }

func decodeHex(h string) ([]byte, error) {
	out := make([]byte, len(h)/2)
	hexMap := map[byte]byte{'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6,
		'7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15,
		'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15}
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexMap[h[i*2]]
		lo, ok2 := hexMap[h[i*2+1]]
		if !ok1 || !ok2 {
			return nil, errBadHex
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// knownDigits：half 串在高位侧以 step 取位 → 低位索引映射。
// step=0：half[i] 在高位 2i；step=1：高位 2i+1。
func knownDigits(half string, fullLen, step int) map[int]int {
	m := map[int]int{}
	for i, ch := range half {
		hi := 2*i + step
		lo := fullLen - 1 - hi
		if lo >= 0 {
			m[lo] = int(ch - '0')
		}
	}
	return m
}

// unitDigitFeasible 个位约束快筛（p0*q0 mod 10 == n0）。
func unitDigitFeasible(pK, qK map[int]int, Lp, Lq int, nStr string) bool {
	n0 := int(nStr[len(nStr)-1] - '0')
	p0s := make([]int, 0, 4)
	if v, ok := pK[0]; ok {
		p0s = append(p0s, v)
	} else {
		for _, d := range []int{1, 3, 7, 9} {
			p0s = append(p0s, d)
		}
	}
	q0s := make([]int, 0, 4)
	if v, ok := qK[0]; ok {
		q0s = append(q0s, v)
	} else {
		for _, d := range []int{1, 3, 7, 9} {
			q0s = append(q0s, d)
		}
	}
	for _, p0 := range p0s {
		for _, q0 := range q0s {
			if p0*q0%10 == n0 {
				return true
			}
		}
	}
	return false
}

// branchPruneHalfPrime 低位逐位恢复 p/q（p*q≡n mod 10^k 剪枝）。
func branchPruneHalfPrime(pK, qK map[int]int, Lp, Lq int, n *big.Int) (*big.Int, *big.Int, bool) {
	maxL := Lp
	if Lq > maxL {
		maxL = Lq
	}
	// 迭代加深栈实现（避免深递归）
	// 用递归+层叠模（手解验证过深 155 层可行，Go 栈足够）
	var rec func(k int, p, q *big.Int) (*big.Int, *big.Int, bool)
	rec = func(k int, p, q *big.Int) (*big.Int, *big.Int, bool) {
		if k == maxL {
			if new(big.Int).Mul(p, q).Cmp(n) == 0 {
				return p, q, true
			}
			return nil, nil, false
		}
		mod := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(k+1)), nil)
		nMod := new(big.Int).Mod(n, mod)
		pcs := digitChoices(pK, k)
		qcs := digitChoices(qK, k, Lq)
		for _, pd := range pcs {
			np := new(big.Int).Add(p, new(big.Int).Mul(big.NewInt(int64(pd)), pow10(k)))
			for _, qd := range qcs {
				nq := new(big.Int).Add(q, new(big.Int).Mul(big.NewInt(int64(qd)), pow10(k)))
				pp := new(big.Int).Mod(np, mod)
				qq := new(big.Int).Mod(nq, mod)
				if new(big.Int).Mod(new(big.Int).Mul(pp, qq), mod).Cmp(nMod) != 0 {
					continue
				}
				if rp, rq, ok := rec(k+1, np, nq); ok {
					return rp, rq, true
				}
			}
		}
		return nil, nil, false
	}
	p, q, ok := rec(0, big.NewInt(0), big.NewInt(0))
	return p, q, ok
}

func digitChoices(m map[int]int, k int, extra ...int) []int {
	if v, ok := m[k]; ok {
		return []int{v}
	}
	if len(extra) > 0 && k >= extra[0] {
		return []int{0}
	}
	out := make([]int, 0, 10)
	for d := 0; d < 10; d++ {
		out = append(out, d)
	}
	return out
}

var pow10Cache = map[int]*big.Int{}

func pow10(k int) *big.Int {
	if v, ok := pow10Cache[k]; ok {
		return v
	}
	v := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(k)), nil)
	pow10Cache[k] = v
	return v
}

// decryptRSAOAEP 用恢复的 p/q 重构私钥解 OAEP 密文，扫 flag 形态。
// 手解实证：ct=128 字节（1024-bit key），PKCS1_OAEP 语义。
func decryptRSAOAEP(n, p, q *big.Int, ct []byte) []string {
	// 由 p,q 重建私钥指数
	one := big.NewInt(1)
	p1, q1 := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(p1, q1)
	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil
	}
	// OAEP 解密手工实现（deps: 无外部库；SHA-1 MGF1 —— PKCS1_OAEP 默认）
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: 65537},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		return nil
	}
	pt, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, ct, nil)
	if err != nil {
		// 尝试 SHA-256 变体
		pt2, err2 := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ct, nil)
		if err2 != nil {
			return nil
		}
		pt = pt2
	}
	return scanFlags(string(pt))
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "halfprime_oaep", Category: CategoryCryptoS, Priority: 45,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			_ = ctx
			return tryHalfPrimeOAEP(text + "\n" + attachmentsText(attachments))
		},
	})
}

func attachmentsText(attachments map[string]string) string {
	var b strings.Builder
	for _, v := range attachments {
		b.WriteString("\n")
		b.WriteString(v)
	}
	return b.String()
}
