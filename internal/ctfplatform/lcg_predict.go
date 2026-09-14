package ctfplatform

// LCG（线性同余发生器）预测攻击
//
// x_{n+1} = (a·x_n + c) mod m
//
// 经典 CTF 题型：某"随机数"由 LCG 生成，攻击者拿到部分输出。三种常见形态：
//
//	① 参数全知：给定 a,c,m,seed，求 K 步后的状态          → 直接倍增推进
//	② 模数已知：给定 m 与连续输出，反解 a,c 后预测下一个   → a=(x2-x1)/(x1-x0) mod m
//	③ 模数未知：给定 >=6 个连续输出，先用 gcd 恢复 m       → m | (t_{i+1}·t_{i-1} - t_i^2)
//
// 其中 t_i = x_{i+1} - x_i；对多个 i 取 gcd 即得 m（或其倍数，用后续输出验证剔除）。
//
// 全程 math/big，无外部依赖。返回 flag{<十进制>}。

import (
	"context"
	"math/big"
	"regexp"
	"strings"
)

var (
	// 强信号：lcg / linear congruential。
	lcgSignalRe = regexp.MustCompile(`(?i)\b(lcg|linear[_\s-]?congruential)\b`)
	// 输出序列：outputs/states/values = [n, n, ...]
	lcgOutputsRe = regexp.MustCompile(`(?i)\b(?:outputs?|states?|values?)\s*[:=]\s*\[([0-9,\s]+)\]`)
	lcgModulusRe = regexp.MustCompile(`(?i)\b(?:modulus|modulo|mod|m)\s*[:=]\s*(\d+)`)
	lcgMultRe    = regexp.MustCompile(`(?i)\b(?:multiplier|\ba)\s*[:=]\s*(\d+)`)
	lcgIncrRe    = regexp.MustCompile(`(?i)\b(?:increment|\bc)\s*[:=]\s*(\d+)`)
	lcgSeedRe    = regexp.MustCompile(`(?i)\bseed\s*[:=]\s*(\d+)`)
	lcgStepsRe   = regexp.MustCompile(`(?i)\bafter\s+(\d+)\s+steps?`)
)

func lcgFirst(re *regexp.Regexp, s string) *big.Int {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	v, ok := new(big.Int).SetString(m[1], 10)
	if !ok {
		return nil
	}
	return v
}

// lcgStepVal 单步推进：x' = (a·x + c) mod m。
func lcgStepVal(x, a, c, m *big.Int) *big.Int {
	t := new(big.Int).Mul(a, x)
	t.Add(t, c)
	t.Mod(t, m)
	return t
}

// lcgAdvance 用二进制倍增在 O(log steps) 内求 f_steps(x) = a^steps·x + c·(a^{steps}-1)/(a-1)。
// 以仿射函数 (A,C) 表示 f(x)=A·x+C，复合 (A1,C1)∘(A2,C2) = (A1·A2, A1·C2+C1)。
func lcgAdvance(seed, a, c, m, steps *big.Int) *big.Int {
	A := new(big.Int).Mod(big.NewInt(1), m)
	C := new(big.Int).Mod(big.NewInt(0), m)
	for i := steps.BitLen() - 1; i >= 0; i-- {
		// 平方：res ← res∘res
		nA := new(big.Int).Mul(A, A)
		nA.Mod(nA, m)
		nC := new(big.Int).Mul(A, C)
		nC.Add(nC, C)
		nC.Mod(nC, m)
		A, C = nA, nC
		if steps.Bit(i) == 1 {
			// 乘底：res ← res∘base
			nA = new(big.Int).Mul(A, a)
			nA.Mod(nA, m)
			nC = new(big.Int).Mul(A, c)
			nC.Add(nC, C)
			nC.Mod(nC, m)
			A, C = nA, nC
		}
	}
	res := new(big.Int).Mul(A, seed)
	res.Add(res, C)
	res.Mod(res, m)
	return res
}

// lcgRecoverAC 由连续输出与模数反解 a、c，并用全部输出验证一致性。
func lcgRecoverAC(outs []*big.Int, m *big.Int) (a, c *big.Int, ok bool) {
	if len(outs) < 3 || m == nil || m.Sign() <= 0 {
		return nil, nil, false
	}
	d0 := new(big.Int).Sub(outs[1], outs[0])
	d0.Mod(d0, m)
	d1 := new(big.Int).Sub(outs[2], outs[1])
	d1.Mod(d1, m)
	inv := new(big.Int).ModInverse(d0, m)
	if inv == nil {
		return nil, nil, false
	}
	a = new(big.Int).Mul(d1, inv)
	a.Mod(a, m)
	c = new(big.Int).Mul(a, outs[0])
	c.Sub(outs[1], c)
	c.Mod(c, m)
	// 全序列验证
	cur := new(big.Int).Set(outs[0])
	for i := 1; i < len(outs); i++ {
		cur = lcgStepVal(cur, a, c, m)
		if cur.Cmp(outs[i]) != 0 {
			return nil, nil, false
		}
	}
	return a, c, true
}

// lcgRecoverModulus 由 >=6 个连续输出经 gcd 恢复模数 m（t_i = x_{i+1}-x_i，m | t_{i+1}·t_{i-1} - t_i²）。
func lcgRecoverModulus(outs []*big.Int) *big.Int {
	if len(outs) < 6 {
		return nil
	}
	t := make([]*big.Int, len(outs)-1)
	for i := range t {
		t[i] = new(big.Int).Sub(outs[i+1], outs[i])
	}
	g := big.NewInt(0)
	for i := 1; i+1 < len(t); i++ {
		d := new(big.Int).Mul(t[i+1], t[i-1])
		sq := new(big.Int).Mul(t[i], t[i])
		d.Sub(d, sq)
		d.Abs(d)
		g.GCD(nil, nil, g, d)
		if g.Sign() == 0 {
			return nil
		}
	}
	if g.Cmp(big.NewInt(1)) <= 0 {
		return nil
	}
	return g
}

// lcgModulusCandidates 由 gcd 结果 g 生成模数候选：真实 m 必整除 g，但 gcd 可能给出
// k·m（k>1），故先试 g 的小素因子商，再试 g 本身。
func lcgModulusCandidates(g *big.Int) []*big.Int {
	primes := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47}
	var cands []*big.Int
	for _, p := range primes {
		pp := big.NewInt(p)
		q := new(big.Int).Mod(g, pp)
		if q.Sign() == 0 {
			cands = append(cands, new(big.Int).Div(g, pp))
		}
	}
	cands = append(cands, new(big.Int).Set(g))
	return cands
}

// tryLCGPredict 入口：解析题目描述并预测，返回 []string{"flag{<int>}"}。
func tryLCGPredict(text string, attachments map[string]string) []string {
	full := text
	for _, v := range attachments {
		full += "\n" + v
	}
	if !lcgSignalRe.MatchString(full) {
		return nil
	}

	var outs []*big.Int
	if m := lcgOutputsRe.FindStringSubmatch(full); m != nil {
		for _, p := range strings.Split(m[1], ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			v, ok := new(big.Int).SetString(p, 10)
			if !ok {
				return nil
			}
			outs = append(outs, v)
		}
	}

	mod := lcgFirst(lcgModulusRe, full)
	mult := lcgFirst(lcgMultRe, full)
	incr := lcgFirst(lcgIncrRe, full)
	seed := lcgFirst(lcgSeedRe, full)
	steps := lcgFirst(lcgStepsRe, full)

	switch {
	case mod != nil && mult != nil && incr != nil && seed != nil && steps != nil:
		res := lcgAdvance(seed, mult, incr, mod, steps)
		return []string{"flag{" + res.String() + "}"}
	case mod != nil && len(outs) >= 3:
		a, c, ok := lcgRecoverAC(outs, mod)
		if !ok {
			return nil
		}
		next := lcgStepVal(outs[len(outs)-1], a, c, mod)
		return []string{"flag{" + next.String() + "}"}
	case len(outs) >= 6:
		g := lcgRecoverModulus(outs)
		if g == nil {
			return nil
		}
		for _, m := range lcgModulusCandidates(g) {
			a, c, ok := lcgRecoverAC(outs, m)
			if !ok {
				continue
			}
			next := lcgStepVal(outs[len(outs)-1], a, c, m)
			return []string{"flag{" + next.String() + "}"}
		}
		return nil
	}
	return nil
}

func solveLCGPredict(ctx context.Context, text string, attachments map[string]string) []string {
	return tryLCGPredict(text, attachments)
}
