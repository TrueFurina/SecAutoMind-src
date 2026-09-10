package ctfplatform

// LFSR 流预测攻击（Berlekamp–Massey 恢复最小连接多项式）
//
// 经典且常见的 CTF/流密码题型：某"随机比特流"由未知抽头的线性反馈移位寄存器
// (LFSR) 生成，攻击者观察到连续输出比特。若观察长度 >= 2L（L = 序列最小
// 线性复杂度），Berlekamp–Massey 算法可在 GF(2) 上恢复序列的最小连接多项式，
// 从而把序列继续生成下去——预测后续所有比特，无需知道寄存器抽头与初态。
//
//	BM(s[0..n-1]) -> 连接多项式 C(x), 长度 L
//	s[k] = Σ_{i=1..L} C[i]·s[k-i]   （k >= L，GF(2) 上即 XOR）
//	用已观察比特 + 已预测比特逐位前推，即可预测第 n 个及以后的比特。
//
// 全程纯位运算，无外部依赖。本求解器从题目描述解析一段 >=48 位的 0/1 比特流，
// 恢复线性递推后预测紧随其后的 16 个比特，把 16 位二进制按整数转十进制，
// 返回 flag{<decimal>}。

import (
	"context"
	"regexp"
	"strconv"
)

var (
	// 强信号：lfsr / 线性反馈移位寄存器 / Berlekamp(-)Massey / 移位寄存器。
	lfsrSignalRe = regexp.MustCompile(`(?i)\b(lfsr|linear[_\s-]?feedback[_\s-]?shift[_\s-]?register|berlekamp[_\s-]?massey|shift[_\s-]?register)\b`)
	// 一段 >=48 位连续 0/1（BM 需要观察长度 >= 2L，L<=24 时 48 位够用）。
	lfsrBitsRe = regexp.MustCompile(`(?i)\b([01]{48,})\b`)
)

const lfsrPredictBits = 16

// bmRecover 在 GF(2) 上执行 Berlekamp–Massey，返回连接多项式系数 C（C[0]=1，
// 递推 s[k]=Σ_{i=1..L} C[i]·s[k-i]）与线性复杂度 L。bits 为 0/1 切片。
func bmRecover(bits []int) (C []int, L int) {
	B := []int{1}
	C = []int{1}
	L = 0
	m := 1
	for n := 0; n < len(bits); n++ {
		// 偏差 d = s[n] + Σ_{i=1..L} C[i]·s[n-i]  (GF(2))
		d := bits[n]
		for i := 1; i <= L && i < len(C); i++ {
			d ^= C[i] & bits[n-i]
		}
		if d == 0 {
			m++
			continue
		}
		if 2*L <= n {
			T := append([]int{}, C...)
			// C(x) -= x^m · B(x)（GF(2) 中 b 恒为 1，故系数即 d=1）
			for len(C) < m+len(B) {
				C = append(C, 0)
			}
			for i := 0; i < len(B); i++ {
				C[i+m] ^= B[i]
			}
			L = n + 1 - L
			B = T
			m = 1
		} else {
			for len(C) < m+len(B) {
				C = append(C, 0)
			}
			for i := 0; i < len(B); i++ {
				C[i+m] ^= B[i]
			}
			m++
		}
	}
	return C, L
}

// lfsrPredictNext 由已观察比特 bits 预测紧随其后的 k 个比特（0/1 切片）。
func lfsrPredictNext(bits []int, k int) []int {
	if len(bits) == 0 {
		return nil
	}
	C, L := bmRecover(bits)
	seq := append([]int{}, bits...)
	for len(seq) < len(bits)+k {
		var nxt int
		for i := 1; i <= L && i < len(C); i++ {
			if len(seq)-i >= 0 {
				nxt ^= C[i] & seq[len(seq)-i]
			}
		}
		seq = append(seq, nxt)
	}
	return seq[len(bits):]
}

// tryLFSRPredict 入口：解析比特流并预测随后 16 位，返回 []string{"flag{<int>}"}。
func tryLFSRPredict(text string, attachments map[string]string) []string {
	full := text
	for _, v := range attachments {
		full += "\n" + v
	}
	if !lfsrSignalRe.MatchString(full) {
		return nil
	}
	m := lfsrBitsRe.FindStringSubmatch(full)
	if m == nil {
		return nil
	}
	raw := m[1]
	bits := make([]int, len(raw))
	for i, c := range raw {
		if c == '1' {
			bits[i] = 1
		}
	}
	next := lfsrPredictNext(bits, lfsrPredictBits)
	if len(next) < lfsrPredictBits {
		return nil
	}
	val := 0
	for _, b := range next {
		val = (val << 1) | b
	}
	return []string{"flag{" + strconv.Itoa(val) + "}"}
}

func solveLFSRPredict(ctx context.Context, text string, attachments map[string]string) []string {
	return tryLFSRPredict(text, attachments)
}
