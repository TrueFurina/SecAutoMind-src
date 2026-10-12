package ctfplatform

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// fibLFSR 一个 Fibonacci 型 LFSR 前向生成器（真值来源）。
// taps 为参与反馈的抽头下标（0 = 最右/输入侧）；输出顺序为每拍移出的最右比特。
func fibLFSR(init []int, taps []int) func() int {
	reg := append([]int{}, init...)
	return func() int {
		out := reg[0]
		fb := 0
		for _, t := range taps {
			fb ^= reg[t]
		}
		reg = append(reg[1:], fb)
		return out
	}
}

// lfsrScenario 构造"泄露 2L+16 位，预测随后 16 位"的场景。
func lfsrScenario(t *testing.T, degree int, taps, init []int) (leak []int, trueNext []int) {
	t.Helper()
	if len(init) != degree {
		t.Fatalf("init 长度须等于 degree %d", degree)
	}
	for _, tp := range taps {
		if tp < 0 || tp >= degree {
			t.Fatalf("tap %d 越界 (degree=%d)", tp, degree)
		}
	}
	gen := fibLFSR(init, taps)
	leak = make([]int, 0, 2*degree+16)
	for i := 0; i < 2*degree+16; i++ {
		leak = append(leak, gen())
	}
	trueNext = make([]int, 16)
	for i := 0; i < 16; i++ {
		trueNext[i] = gen()
	}
	return
}

func bitsToInt(bs []int) int {
	v := 0
	for _, b := range bs {
		v = (v << 1) | b
	}
	return v
}

func bitsToStr(bs []int) string {
	var sb strings.Builder
	for _, b := range bs {
		sb.WriteByte(byte('0' + b))
	}
	return sb.String()
}

func TestLFSRBerlekampMasseyBasic(t *testing.T) {
	// 8 级 LFSR：泄露 2*8+16=32 位，预测 16 位；BM 线性复杂度应在 (0,8]。
	taps := []int{7, 6, 1, 0}
	init := []int{1, 1, 1, 1, 1, 1, 1, 1}
	gen := fibLFSR(init, taps)
	leak := make([]int, 32) // 2L+16 = 2*8+16
	for i := range leak {
		leak[i] = gen()
	}
	trueNext := make([]int, 16)
	for i := range trueNext {
		trueNext[i] = gen()
	}
	pred := lfsrPredictNext(leak, 16)
	if len(pred) != 16 {
		t.Fatalf("预测长度不对: %d", len(pred))
	}
	for i := range pred {
		if pred[i] != trueNext[i] {
			t.Fatalf("第 %d 位预测错: got %d want %d (leak=%s)", i, pred[i], trueNext[i], bitsToStr(leak))
		}
	}
	_, L := bmRecover(leak)
	if L < 1 || L > 8 {
		t.Fatalf("BM 线性复杂度应落在 (0,8], got %d", L)
	}
}

func TestLFSRPredictDegree32(t *testing.T) {
	// 32 级 LFSR：泄露 80 位，预测 16 位。
	taps := []int{31, 22, 2, 1}
	init := make([]int, 32)
	for i := range init {
		init[i] = 1
	}
	leak, trueNext := lfsrScenario(t, 32, taps, init)
	pred := lfsrPredictNext(leak, 16)
	if len(pred) != 16 {
		t.Fatalf("预测长度不对: %d", len(pred))
	}
	if bitsToInt(pred) != bitsToInt(trueNext) {
		t.Fatalf("32 级预测不匹配: got %d want %d", bitsToInt(pred), bitsToInt(trueNext))
	}
}

func TestLFSRSolverParses(t *testing.T) {
	// 构造与基准集同款的 description：LFSR 信号 + bits = <80 位 0/1>。
	taps := []int{31, 22, 2, 1}
	init := make([]int, 32)
	for i := range init {
		init[i] = 1
	}
	leak, trueNext := lfsrScenario(t, 32, taps, init)
	desc := "A server generates key stream bits with an LFSR (linear feedback shift register).\n" +
		"It leaked the following keystream bits. Predict the next 16 bits:\n" +
		"bits = " + bitsToStr(leak) + "\n"
	cands := solveLFSRPredict(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	want := fmt.Sprintf("flag{%d}", bitsToInt(trueNext))
	if cands[0] != want {
		t.Fatalf("复原 flag 不匹配: got %q want %q", cands[0], want)
	}
}

func TestLFSRSolverRegistered(t *testing.T) {
	// 反注水门禁：lfsr_predict 必须真实注册且启用。
	found := false
	enabled := false
	for _, s := range GetSolvers() {
		if s.Name == "lfsr_predict" {
			found = true
			enabled = s.Enabled
			break
		}
	}
	if !found {
		t.Fatal("lfsr_predict 未注册（反注水门禁）")
	}
	if !enabled {
		t.Fatal("lfsr_predict 已注册但被禁用")
	}
}

func TestLFSRNoFalsePositive(t *testing.T) {
	// 反误报：无 LFSR 信号但有二进制串的文本不得触发。
	random := "The pcap shows a base64 blob: 1100101011010010, then XOR single byte 0x7f applied twice."
	if got := solveLFSRPredict(context.Background(), random, nil); got != nil {
		t.Fatalf("不应在无信号文本上误报: %v", got)
	}
}

func TestLFSRShortLeakNoPredict(t *testing.T) {
	// 比特流太短（<48）不预测。
	short := "lfsr bits = 01010101010101010101010101010101" // 32 位
	if got := solveLFSRPredict(context.Background(), short, nil); got != nil {
		t.Fatalf("过短比特流不应预测: %v", got)
	}
}
