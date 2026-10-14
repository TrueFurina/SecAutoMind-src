// presolve_lfsr.go —— LFSR 相关攻击求解器（2026-10-15 cross-bench 立尺驱动）
//
// 真题：西湖论剑2021 FilterRandom。两个 N=64 位 LFSR（mask1/mask2 在脚本注释中
// 给出），输出序列按 90% 概率取 l1、10% 取 l2 混合（2048 位）；flag 形如
// DASCTF{init1-init2}（init 为 64 位十进制）。
//
// 攻击（确定性，无爆破）：
//  1. LFSR 状态演化 s' = (s<<1) XOR parity(s&mask) 是 GF(2) 线性的且无常数项，
//     故第 i 位输出 = <coeff_i, init>——对 init 完全线性。
//  2. 信息集解码（ISD）恢复 init1：随机取 N 个位置当作无噪方程解出 init，
//     用全部 2048 位的匹配率验证（真 init1 匹配率 ≈95%，伪解 ≈50%）。
//     单次全清概率 0.9^64≈0.0012，期望约 850 次尝试，每次为 64×64 位运算。
//  3. 恢复 init2：在 output≠l1 的位置上，output 必等于 l2（这些位置恰好是
//     l2 被选中且 l2[i]≠l1[i] 的点，无噪声），直接线性求解。
// 已用真题附件实跑命中 sha256 真值（DASCTF{15401137114601469828-11256716742701089092}）。
package ctfplatform

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

// gf2Eq 一条 GF(2) 线性方程：coeff 的第 b 位为未知数 b 的系数，rhs 为右端项。
type gf2Eq struct {
	coeff uint64
	rhs   byte
}

// gf2Solve 解 n（≤64）个未知数的 GF(2) 线性方程组（高斯-约当消元）。
// 返回解与是否「满秩且全部方程满足」——任一不满足即判不可解（fail-closed）。
func gf2Solve(eqs []gf2Eq, n int) (uint64, bool) {
	var piv [64]uint64
	var pivR [64]byte
	var has [64]bool
	for _, e := range eqs {
		c, r := e.coeff, e.rhs
		for b := 0; b < n; b++ {
			if c&(uint64(1)<<uint(b)) == 0 {
				continue
			}
			if has[b] {
				c ^= piv[b]
				r ^= pivR[b]
			} else {
				piv[b], pivR[b], has[b] = c, r, true
				c = 0
				break
			}
		}
	}
	var sol uint64
	for b := n - 1; b >= 0; b-- {
		if !has[b] {
			continue
		}
		v := pivR[b]
		for h := b + 1; h < n; h++ {
			if piv[b]&(uint64(1)<<uint(h)) != 0 && sol&(uint64(1)<<uint(h)) != 0 {
				v ^= 1
			}
		}
		if v == 1 {
			sol |= uint64(1) << uint(b)
		}
	}
	for _, e := range eqs {
		acc := byte(0)
		x := e.coeff & sol
		for x != 0 {
			acc ^= byte(x & 1)
			x >>= 1
		}
		if acc != e.rhs {
			return 0, false
		}
	}
	for b := 0; b < n; b++ {
		if !has[b] {
			return 0, false // 秩不足 → 解不唯一，拒绝
		}
	}
	return sol, true
}

// lfsrStream 按挑战脚本语义产生 count 位输出：s' = (s<<1 & lengthMask) XOR parity(s&mask)。
func lfsrStream(init, mask, lengthMask uint64, count int) []byte {
	s := init & lengthMask
	out := make([]byte, count)
	for i := 0; i < count; i++ {
		o := byte(0)
		x := s & mask & lengthMask
		for x != 0 {
			o ^= byte(x & 1)
			x >>= 1
		}
		s = ((s << 1) & lengthMask) ^ uint64(o)
		out[i] = o
	}
	return out
}

// tryLFSRCorrelation LFSR 相关攻击（FilterRandom 型），完整推导见文件头注释。
func tryLFSRCorrelation(text string) []string {
	n := 64
	if m := regexp.MustCompile(`(?m)^\s*N\s*=\s*(\d+)\s*$`).FindStringSubmatch(text); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil && v >= 8 && v <= 64 {
			n = v
		}
	}
	var lengthMask uint64
	if n == 64 {
		lengthMask = ^uint64(0)
	} else {
		lengthMask = uint64(1)<<uint(n) - 1
	}
	// mask1/mask2：脚本（注释块）中的裸十进制数。二进制输出串也是长数字串，
	// 但超出 uint64 范围会被 ParseUint 拒绝，天然过滤。
	var masks []uint64
	for _, s := range regexp.MustCompile(`\b\d{15,}\b`).FindAllString(text, -1) {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil && v != 0 {
			masks = append(masks, v)
			if len(masks) == 2 {
				break
			}
		}
	}
	if len(masks) < 2 {
		return nil
	}
	m1, m2 := masks[0]&lengthMask, masks[1]&lengthMask
	// output：最长的二进制串
	yStr := ""
	for _, b := range regexp.MustCompile(`\b[01]{100,}\b`).FindAllString(text, -1) {
		if len(b) > len(yStr) {
			yStr = b
		}
	}
	count := len(yStr)
	if count < n*4 {
		return nil
	}
	y := make([]byte, count)
	for i := 0; i < count; i++ {
		y[i] = yStr[i] - '0'
	}
	// 方程系数：coeff_i 的第 b 位 = 第 i 步输出对 init 第 b 位的系数（基向量模拟）。
	coeffOf := func(mask uint64) []uint64 {
		coeff := make([]uint64, count)
		for b := 0; b < n; b++ {
			stream := lfsrStream(uint64(1)<<uint(b), mask, lengthMask, count)
			for i := 0; i < count; i++ {
				if stream[i] == 1 {
					coeff[i] |= uint64(1) << uint(b)
				}
			}
		}
		return coeff
	}
	coeff1 := coeffOf(m1)
	// ISD 恢复 init1（固定种子 → 确定性求解器，测试可复现）。
	rng := rand.New(rand.NewSource(0x5A6B7C8D))
	var init1 uint64
	found := false
	for attempt := 0; attempt < 20000 && !found; attempt++ {
		perm := rng.Perm(count)
		eqs := make([]gf2Eq, n)
		for i := 0; i < n; i++ {
			eqs[i] = gf2Eq{coeff: coeff1[perm[i]], rhs: y[perm[i]]}
		}
		sol, ok := gf2Solve(eqs, n)
		if !ok {
			continue
		}
		stream := lfsrStream(sol, m1, lengthMask, count)
		match := 0
		for i := 0; i < count; i++ {
			if stream[i] == y[i] {
				match++
			}
		}
		if match*100 >= count*85 { // 真 init1 ≈95%，伪解 ≈50%
			init1, found = sol, true
		}
	}
	if !found {
		return nil
	}
	// init2：output≠l1 的位置上 output 必等于 l2（无噪）。
	l1 := lfsrStream(init1, m1, lengthMask, count)
	coeff2 := coeffOf(m2)
	var eqs2 []gf2Eq
	for i := 0; i < count; i++ {
		if y[i] != l1[i] {
			eqs2 = append(eqs2, gf2Eq{coeff: coeff2[i], rhs: y[i]})
		}
	}
	if len(eqs2) < n {
		return nil
	}
	init2, ok := gf2Solve(eqs2, n)
	if !ok {
		return nil
	}
	// flag 模板：脚本中的 b'DASCTF{%d-%d}'（恰含两个 %d）。
	tmpl := ""
	if m := regexp.MustCompile(`b['"]([^'"]*%d[^'"]*)['"]`).FindStringSubmatch(text); m != nil {
		tmpl = m[1]
	}
	if tmpl == "" {
		return nil
	}
	parts := strings.Split(tmpl, "%d")
	if len(parts) != 3 {
		return nil
	}
	flag := parts[0] + strconv.FormatUint(init1, 10) + parts[1] + strconv.FormatUint(init2, 10) + parts[2]
	return []string{flag}
}
