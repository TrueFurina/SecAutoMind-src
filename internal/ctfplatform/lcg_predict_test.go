package ctfplatform

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func bi(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad int: " + s)
	}
	return v
}

// lcgGen 前向生成 n 个输出（首个为 seed=x0）。
func lcgGen(seed, a, c, m *big.Int, n int) []*big.Int {
	out := make([]*big.Int, 0, n)
	cur := new(big.Int).Set(seed)
	for i := 0; i < n; i++ {
		out = append(out, new(big.Int).Set(cur))
		cur = lcgStepVal(cur, a, c, m)
	}
	return out
}

func outsToCSV(outs []*big.Int) string {
	parts := make([]string, len(outs))
	for i, v := range outs {
		parts[i] = v.String()
	}
	return strings.Join(parts, ", ")
}

func TestLCGAdvanceMatchesNaive(t *testing.T) {
	// 倍增推进（O(log n)）必须与朴素迭代逐位一致。
	a := bi("6364136223846793005")
	c := bi("1442695040888963407")
	m := bi("18446744073709551616") // 2^64
	seed := bi("20260914")
	for _, k := range []int64{0, 1, 2, 7, 100, 1000, 999999} {
		cur := new(big.Int).Set(seed)
		for i := int64(0); i < k; i++ {
			cur = lcgStepVal(cur, a, c, m)
		}
		got := lcgAdvance(seed, a, c, m, big.NewInt(k))
		if got.Cmp(cur) != 0 {
			t.Fatalf("advance(%d) 不匹配: got %s want %s", k, got, cur)
		}
	}
}

func TestLCGRecoverAC(t *testing.T) {
	a := bi("6364136223846793005")
	c := bi("1442695040888963407")
	m := bi("18446744073709551616")
	seed := bi("20260914")
	outs := lcgGen(seed, a, c, m, 5)

	ra, rc, ok := lcgRecoverAC(outs, m)
	if !ok {
		t.Fatal("反解 a,c 失败")
	}
	if ra.Cmp(a) != 0 || rc.Cmp(c) != 0 {
		t.Fatalf("a,c 反解错: got a=%s c=%s want a=%s c=%s", ra, rc, a, c)
	}
	want := lcgStepVal(outs[len(outs)-1], a, c, m)
	got := lcgStepVal(outs[len(outs)-1], ra, rc, m)
	if got.Cmp(want) != 0 {
		t.Fatalf("预测不一致: got %s want %s", got, want)
	}
}

func TestLCGRecoverModulus(t *testing.T) {
	// 模数未知：用 >=6 个连续输出经 gcd + 因子候选恢复。
	m := bi("2147483647") // 2^31-1（梅森质数）
	a := bi("48271")
	c := bi("11")
	seed := bi("12345")
	outs := lcgGen(seed, a, c, m, 8)

	g := lcgRecoverModulus(outs)
	if g == nil {
		t.Fatal("gcd 恢复模数失败")
	}
	rec := false
	for _, cand := range lcgModulusCandidates(g) {
		if ra, rc, ok := lcgRecoverAC(outs, cand); ok {
			want := lcgStepVal(outs[len(outs)-1], a, c, m)
			got := lcgStepVal(outs[len(outs)-1], ra, rc, cand)
			if got.Cmp(want) == 0 && cand.Cmp(m) == 0 {
				rec = true
			}
			break // 取首个通过验证的候选
		}
	}
	if !rec {
		t.Fatalf("模数恢复/预测未命中真实 m=%s（gcd=%s）", m, g)
	}
}

func TestLCGSolverParsesKnownParams(t *testing.T) {
	a := bi("6364136223846793005")
	c := bi("1442695040888963407")
	m := bi("18446744073709551616")
	seed := bi("2026")
	const steps = 1000
	want := lcgAdvance(seed, a, c, m, big.NewInt(steps))

	desc := fmt.Sprintf(
		"A service emits tokens using an LCG (linear congruential generator).\n"+
			"modulus = %s\nmultiplier = %s\nincrement = %s\nseed = %s\n"+
			"Predict the state after %d steps and submit flag{value}.\n",
		m, a, c, seed, steps)
	cands := solveLCGPredict(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	if exp := "flag{" + want.String() + "}"; cands[0] != exp {
		t.Fatalf("已知参数预测错: got %q want %q", cands[0], exp)
	}
}

func TestLCGSolverParsesRecoverAC(t *testing.T) {
	m := bi("2147483647")
	a := bi("48271")
	c := bi("0")
	seed := bi("1")
	outs := lcgGen(seed, a, c, m, 5)
	want := lcgStepVal(outs[len(outs)-1], a, c, m)

	desc := fmt.Sprintf(
		"An LCG with known modulus = %s leaked consecutive outputs = [%s].\n"+
			"Recover multiplier and increment, then predict the next value as flag{value}.\n",
		m, outsToCSV(outs))
	cands := solveLCGPredict(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	if exp := "flag{" + want.String() + "}"; cands[0] != exp {
		t.Fatalf("反解 a,c 预测错: got %q want %q", cands[0], exp)
	}
}

func TestLCGSolverParsesRecoverModulus(t *testing.T) {
	m := bi("2147483647")
	a := bi("48271")
	c := bi("11")
	seed := bi("999")
	outs := lcgGen(seed, a, c, m, 8)
	want := lcgStepVal(outs[len(outs)-1], a, c, m)

	desc := fmt.Sprintf(
		"The LCG parameters are unknown. Leaked consecutive outputs = [%s].\n"+
			"Recover everything and predict the next output as flag{value}.\n",
		outsToCSV(outs))
	cands := solveLCGPredict(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	if exp := "flag{" + want.String() + "}"; cands[0] != exp {
		t.Fatalf("未知模数预测错: got %q want %q", cands[0], exp)
	}
}

func TestLCGSolverRegistered(t *testing.T) {
	found := false
	enabled := false
	for _, s := range GetSolvers() {
		if s.Name == "lcg_predict" {
			found = true
			enabled = s.Enabled
			break
		}
	}
	if !found {
		t.Fatal("lcg_predict 未注册（反注水门禁）")
	}
	if !enabled {
		t.Fatal("lcg_predict 已注册但被禁用")
	}
}

func TestLCGNoFalsePositive(t *testing.T) {
	// 反误报：无 LCG 信号、只有一列数字的文本不得触发。
	random := "RC4 keystream bytes observed: 12, 34, 56, 78, 90, 11, 22, 33 in the ciphertext dump."
	if got := solveLCGPredict(context.Background(), random, nil); got != nil {
		t.Fatalf("不应在无信号文本上误报: %v", got)
	}
}
