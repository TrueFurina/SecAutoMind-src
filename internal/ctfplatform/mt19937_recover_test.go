package ctfplatform

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// mtForward 一个标准 MT19937（32-bit）前向生成器，用于产生"真值"输出序列。
type mtForward struct {
	state [mtN]uint32
	idx   int
}

func mtInit(seed uint32) *mtForward {
	m := &mtForward{}
	m.state[0] = seed
	for i := 1; i < mtN; i++ {
		m.state[i] = 1812433253*(m.state[i-1]^(m.state[i-1]>>30)) + uint32(i)
	}
	m.idx = 0
	return m
}

func (m *mtForward) next() uint32 {
	if m.idx >= mtN {
		mtTwist(m.state[:])
		m.idx = 0
	}
	y := mtTemper(m.state[m.idx])
	m.idx++
	return y
}

// mtScenario 构造一个"泄露 624 个连续输出，预测第 625 个"的场景。
// 返回 (outputs[624], trueNext)。
func mtScenario(t *testing.T, seed uint32) (outputs []uint32, trueNext uint32) {
	t.Helper()
	m := mtInit(seed)
	outputs = make([]uint32, mtN)
	for i := 0; i < mtN; i++ {
		outputs[i] = m.next()
	}
	trueNext = m.next()
	return
}

func TestMT19937UntemperIsInverse(t *testing.T) {
	// untemper(temper(x)) == x 必须逐位成立。
	cases := []uint32{0, 1, 0x80000000, 0xFFFFFFFF, 0x12345678, 0x9abcdef0, 0x55555555, 0xaaaaaaaa}
	for _, c := range cases {
		if got := mtUntemper(mtTemper(c)); got != c {
			t.Fatalf("untemper(temper(%#x))=%#x", c, got)
		}
	}
	// 用前向生成器交叉验证：untemper(输出) 必须等于内部 state。
	m := mtInit(0xDEADBEEF)
	for i := 0; i < mtN; i++ {
		out := m.next()
		recovered := mtUntemper(out)
		if recovered != m.state[i] { // 注意 next() 已 temper，state[i] 未经 temper
			t.Fatalf("untemper 未还原内部 state[%d]: got %#x want %#x", i, recovered, m.state[i])
		}
	}
}

func TestMT19937PredictNext(t *testing.T) {
	for _, seed := range []uint32{1, 19650218, 0xCAFEBABE, 0x1234567} {
		outputs, trueNext := mtScenario(t, seed)
		got, ok := mtPredictNext(outputs)
		if !ok {
			t.Fatalf("seed=%d: 预测失败", seed)
		}
		if got != trueNext {
			t.Fatalf("seed=%d: 预测下一个输出 mismatch: got %d want %d", seed, got, trueNext)
		}
	}
}

func TestMT19937SolverParses(t *testing.T) {
	outputs, trueNext := mtScenario(t, 20260909)
	// 构造与基准集同款的 description：MT19937 信号 + [...] 列表字面量。
	var sb strings.Builder
	sb.WriteString("Mersenne Twister MT19937 prediction challenge.\n")
	sb.WriteString("The server leaked 624 consecutive 32-bit outputs of the RNG.\n")
	sb.WriteString("Predict the next output (the 625th value) — it is used as the secret.\n\n")
	sb.WriteString("outputs = [")
	for i, v := range outputs {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%d", v))
	}
	sb.WriteString("]\n")

	cands := solveMT19937(context.Background(), sb.String(), nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	want := fmt.Sprintf("flag{%d}", trueNext)
	if cands[0] != want {
		t.Fatalf("复原 flag 不匹配: got %q want %q", cands[0], want)
	}
}

func TestMT19937SolverRegistered(t *testing.T) {
	// 反注水门禁：mt19937_recover 必须真实注册且启用。
	found := false
	enabled := false
	for _, s := range GetSolvers() {
		if s.Name == "mt19937_recover" {
			found = true
			enabled = s.Enabled
			break
		}
	}
	if !found {
		t.Fatal("mt19937_recover 未注册（反注水门禁）")
	}
	if !enabled {
		t.Fatal("mt19937_recover 已注册但被禁用")
	}
}

func TestMT19937NoFalsePositive(t *testing.T) {
	// 反误报：无 mt19937 信号的随机文本必须不触发。
	random := "We analyzed the pcap and found base64 strings, an RSA modulus of 1337 bits, " +
		"and a CRC32 checksum. The flag format is flag{}, here are some numbers: 12, 34, 56, 78, 90."
	if got := solveMT19937(context.Background(), random, nil); got != nil {
		t.Fatalf("不应在无信号文本上误报: %v", got)
	}
}

func TestMT19937InsufficientOutputs(t *testing.T) {
	// 输出不足 624 个时不预测。
	outputs, _ := mtScenario(t, 7)
	_, ok := mtPredictNext(outputs[:100])
	if ok {
		t.Fatal("输出不足 624 时不应预测成功")
	}
}

// TestMT19937RecoverSha256Consistency 确认 flag 字符串的 SHA-256 与基准集口径一致。
func TestMT19937RecoverSha256Consistency(t *testing.T) {
	outputs, trueNext := mtScenario(t, 99)
	got, ok := mtPredictNext(outputs)
	if !ok || got != trueNext {
		t.Fatal("预测失败")
	}
	flagStr := fmt.Sprintf("flag{%d}", got)
	sum := sha256.Sum256([]byte(flagStr))
	if sum != sha256.Sum256([]byte(fmt.Sprintf("flag{%d}", trueNext))) {
		t.Fatal("SHA-256 不一致")
	}
}
