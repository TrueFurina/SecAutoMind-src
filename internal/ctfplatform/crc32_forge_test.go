package ctfplatform

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"testing"
)

// TestCRC32StdMatchesStdlib 手写 CRC32 必须与标准库逐字节一致（真值锚）。
func TestCRC32StdMatchesStdlib(t *testing.T) {
	seq := make([]byte, 65)
	for i := range seq {
		seq[i] = byte(i)
	}
	cases := [][]byte{
		{}, []byte("a"), []byte("hello"), []byte("The quick brown fox"),
		[]byte("\x00\x00\x00\x00"), seq,
	}
	for _, c := range cases {
		if got, want := crc32Std(c), crc32.ChecksumIEEE(c); got != want {
			t.Fatalf("crc32Std(%q)=%08x want %08x", c, got, want)
		}
	}
}

// TestCRC32ForgeProducesTarget 伪造后缀后整条消息 CRC32 必须等于目标。
func TestCRC32ForgeProducesTarget(t *testing.T) {
	msgs := [][]byte{
		[]byte("amount=100&to=alice"),
		[]byte("admin=0"),
		[]byte(""),
		[]byte("session=deadbeefcafe"),
	}
	targets := []uint32{0x00000000, 0xdeadbeef, 0xffffffff, 0x12345678, 0x0badf00d}
	for _, m := range msgs {
		for _, tg := range targets {
			x, ok := crc32ForgeSuffix(m, tg)
			if !ok {
				t.Fatalf("伪造失败 msg=%q target=%08x", m, tg)
			}
			if len(x) != 4 {
				t.Fatalf("后缀长度应为 4，得 %d", len(x))
			}
			full := append(append([]byte{}, m...), x...)
			if got := crc32Std(full); got != tg {
				t.Fatalf("伪造后 CRC32=%08x want %08x (msg=%q x=%x)", got, tg, m, x)
			}
		}
	}
}

// TestCRC32ForgeUniqueness 解唯一：再次求解应得到同一后缀。
func TestCRC32ForgeUniqueness(t *testing.T) {
	m := []byte("role=user")
	tg := uint32(0xcafebabe)
	x1, ok1 := crc32ForgeSuffix(m, tg)
	x2, ok2 := crc32ForgeSuffix(m, tg)
	if !ok1 || !ok2 || hex.EncodeToString(x1) != hex.EncodeToString(x2) {
		t.Fatalf("解不唯一或失败: %x vs %x", x1, x2)
	}
}

func TestCRC32SolverParses(t *testing.T) {
	msg := []byte("user=guest&admin=0")
	target := uint32(0x1a2b3c4d)
	x, _ := crc32ForgeSuffix(msg, target)
	want := "flag{" + hex.EncodeToString(x) + "}"

	desc := fmt.Sprintf(
		"Integrity is protected with a CRC32 checksum (not a MAC, it is linear).\n"+
			"message (hex) = %s\ncrc32 = %08x\ntarget = %08x\n"+
			"Append exactly 4 bytes so CRC32(message||suffix) = target.\n"+
			"Submit the 4 bytes as flag{<8 hex>}.\n",
		hex.EncodeToString(msg), crc32Std(msg), target)
	cands := solveCRC32Forge(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	if cands[0] != want {
		t.Fatalf("CRC32 伪造解析错: got %q want %q", cands[0], want)
	}
}

func TestCRC32SolverRegistered(t *testing.T) {
	found, enabled := false, false
	for _, s := range GetSolvers() {
		if s.Name == "crc32_forge" {
			found, enabled = true, s.Enabled
			break
		}
	}
	if !found {
		t.Fatal("crc32_forge 未注册（反注水门禁）")
	}
	if !enabled {
		t.Fatal("crc32_forge 已注册但被禁用")
	}
}

func TestCRC32NoFalsePositive(t *testing.T) {
	// 有 crc32 信号但没有 message/target → 不误报。
	a := "This firmware image is protected by a CRC32 checksum over the header."
	if got := solveCRC32Forge(context.Background(), a, nil); got != nil {
		t.Fatalf("不应误报: %v", got)
	}
	// 有 message/target 但没有 crc32 信号 → 不误报。
	b := "message (hex) = deadbeef\ntarget = 12345678\nCompute something."
	if got := solveCRC32Forge(context.Background(), b, nil); got != nil {
		t.Fatalf("不应在无 crc32 信号时误报: %v", got)
	}
}
