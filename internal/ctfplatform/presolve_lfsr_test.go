// presolve_lfsr_test.go —— lfsr_correlation（西湖论剑 FilterRandom 型）回归测试。
//
// 纪律同 presolve_rsa_leaks_test.go：合成 fixture 正向回归 + 变异 fail-closed。
// fixture 生成器按真题脚本（Python）语义**独立实现**，不调用被测的 lfsrStream，
// 避免「用被测代码证明自己」的循环论证。

package ctfplatform

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// fixtureLFSRNext 独立实现真题 class lfsr 的 next()（Python 源码语义）：
//
//	nextdata = (init << 1) & lengthmask
//	i = init & mask & lengthmask
//	output = parity(i)
//	nextdata ^= output; init = nextdata
func fixtureLFSRNext(init, mask, lengthMask uint64) (uint64, byte) {
	next := (init << 1) & lengthMask
	i := init & mask & lengthMask
	var out byte
	for i != 0 {
		out ^= byte(i & 1)
		i >>= 1
	}
	return next ^ uint64(out), out
}

// fixtureFilterOutput 复刻 my_filter：90% 取 l1、10% 取 l2，产出 2048 位混合输出。
func fixtureFilterOutput(init1, init2, mask1, mask2, lengthMask uint64, count int, rng *rand.Rand) string {
	s1, s2 := init1&lengthMask, init2&lengthMask
	var sb strings.Builder
	for i := 0; i < count; i++ {
		var o1, o2 byte
		s1, o1 = fixtureLFSRNext(s1, mask1, lengthMask)
		s2, o2 = fixtureLFSRNext(s2, mask2, lengthMask)
		if rng.Float64() > 0.1 {
			sb.WriteByte('0' + o1)
		} else {
			sb.WriteByte('0' + o2)
		}
	}
	return sb.String()
}

// buildLFSRFixture 按 FilterRandom.py 形态构建题面：脚本头（含 b'DASCTF{%d-%d}' 模板与
// N=64）+ 注释块内的 mask1、mask2 与混合输出。corrupt 非空时破坏对应要素。
func buildLFSRFixture(t *testing.T, flagTemplate string, corrupt string) string {
	t.Helper()
	const (
		init1 = uint64(1234567890123456789)
		init2 = uint64(987654321098765432)
		mask1 = uint64(17638491756192425134)
		mask2 = uint64(14623996511862197922)
	)
	// 固定 seed → 过滤器序列确定性（与求解器内部 ISD 的固定 seed 相互独立）。
	rng := rand.New(rand.NewSource(0xF117E))
	output := fixtureFilterOutput(init1, init2, mask1, mask2, ^uint64(0), 2048, rng)
	switch corrupt {
	case "short_output":
		output = output[:200] // < n*4=256 → 守卫分支
	case "no_template":
		flagTemplate = "print('no template here')"
	case "one_mask":
		// 只给 mask1，mask2 行删掉 → masks<2 → nil
		return fmt.Sprintf(`N=64
mask1=%d
%s`, mask1, output)
	}
	return fmt.Sprintf(`import random
N=64
mask1=%d
mask2=%d
assert flag==%s
%s`, mask1, mask2, flagTemplate, output)
}

func TestLFSRCorrelationSynthetic(t *testing.T) {
	const tmpl = "b'DASCTF{%d-%d}'"
	const want = "DASCTF{1234567890123456789-987654321098765432}"
	got := tryLFSRCorrelation(buildLFSRFixture(t, tmpl, ""))
	if len(got) == 0 || got[0] != want {
		t.Fatalf("lfsr_correlation 合成用例失手：got=%v want=%q", got, want)
	}
}

func TestLFSRCorrelationMutationFailClosed(t *testing.T) {
	// 输出过短（<4N）→ nil。
	if got := tryLFSRCorrelation(buildLFSRFixture(t, "b'DASCTF{%d-%d}'", "short_output")); len(got) != 0 {
		t.Errorf("输出过短应 fail-closed，实际 %v", got)
	}
	// 无 flag 模板 → nil（无法拼装 flag 外形）。
	if got := tryLFSRCorrelation(buildLFSRFixture(t, "", "no_template")); len(got) != 0 {
		t.Errorf("缺少 flag 模板应 fail-closed，实际 %v", got)
	}
	// 只给一个 mask → nil。
	if got := tryLFSRCorrelation(buildLFSRFixture(t, "b'DASCTF{%d-%d}'", "one_mask")); len(got) != 0 {
		t.Errorf("mask 不足应 fail-closed，实际 %v", got)
	}
}

// TestGF2SolveUnit 高斯-约当消元的三种结局：唯一解 / 秩不足 / 矛盾方程。
func TestGF2SolveUnit(t *testing.T) {
	// 唯一解系统：x0=1, x0^x1=1, x1^x2=1 → (1,0,1)=0b101=5。
	eqs := []gf2Eq{
		{coeff: 0b001, rhs: 1},
		{coeff: 0b011, rhs: 1},
		{coeff: 0b110, rhs: 1},
	}
	if sol, ok := gf2Solve(eqs, 3); !ok || sol != 5 {
		t.Errorf("已知系统求解错误：sol=%d ok=%v want sol=5 ok=true", sol, ok)
	}
	// 秩不足：只有 1 条方程、3 个未知数 → 解不唯一 → false。
	if _, ok := gf2Solve([]gf2Eq{{coeff: 0b011, rhs: 1}}, 3); ok {
		t.Error("秩不足系统应判不可解（fail-closed）")
	}
	// 矛盾：x0^x1=1 与 x0^x1=0 并存 → 验证循环必须抓到 → false。
	if _, ok := gf2Solve([]gf2Eq{
		{coeff: 0b011, rhs: 1},
		{coeff: 0b011, rhs: 0},
		{coeff: 0b110, rhs: 0},
	}, 3); ok {
		t.Error("矛盾系统应判不可解（fail-closed）")
	}
}

// TestLFSRStreamUnit 被测实现与独立实现（fixtureLFSRNext）在 512 步上逐位一致。
func TestLFSRStreamUnit(t *testing.T) {
	const (
		init = uint64(0x0123456789ABCDEF)
		mask = uint64(0x5A6B7C8D9EAF1357)
	)
	got := lfsrStream(init, mask, ^uint64(0), 512)
	s := init
	for i := 0; i < 512; i++ {
		var want byte
		s, want = fixtureLFSRNext(s, mask, ^uint64(0))
		if got[i] != want {
			t.Fatalf("第 %d 步不一致：got=%d want=%d", i, got[i], want)
		}
	}
}
