package ctfplatform

// presolve_crush_test.go —— 位置桶压缩解压器测试（2026-10-26）。
// 夹具全部合成（encode 逆操作），另含格式负例。

import (
	"encoding/binary"
	"testing"
)

func crushCompress(text string) []byte {
	// 正向编码（与逆向算法对偶）
	buckets := make([][]int, 256)
	for i, c := range []byte(text) {
		buckets[c] = append(buckets[c], i)
	}
	var out []byte
	var lenBuf [8]byte
	for ch := 0; ch < 255; ch++ { // crushing 实证：255 桶（末桶截断语义）
		binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(buckets[ch])))
		out = append(out, lenBuf[:]...)
		for _, off := range buckets[ch] {
			binary.LittleEndian.PutUint64(lenBuf[:], uint64(off))
			out = append(out, lenBuf[:]...)
		}
	}
	return out
}

func TestCrushRoundTrip(t *testing.T) {
	text := "Hello Crush! The flag is FlagExam{r0und_tr1p_0k} and more text follows here."
	enc := crushCompress(text)
	dec := crushDecompress(enc)
	if dec == nil {
		t.Fatal("合成文本解压失败")
	}
	if string(dec) != text {
		t.Fatalf("往返不一致:\n got %q\nwant %q", dec, text)
	}
	flags := scanFlags(string(dec))
	if len(flags) == 0 || flags[0] != "FlagExam{r0und_tr1p_0k}" {
		t.Fatalf("flag 提取失败: %v", flags)
	}
}

func TestCrushRejectsBadFormat(t *testing.T) {
	// 桶0 链长异常大 → 拒绝
	bad := make([]byte, 300)
	binary.LittleEndian.PutUint64(bad[0:8], 1<<40)
	if crushDecompress(bad) != nil {
		t.Fatal("异常链长未拒绝")
	}
	// 同一位置两个字符（冲突）→ 拒绝
	var dup []byte
	var b8 [8]byte
	for ch := 0; ch < 255; ch++ {
		n := int64(0)
		if ch == 'A' || ch == 'B' {
			n = 1
		}
		binary.LittleEndian.PutUint64(b8[:], uint64(n))
		dup = append(dup, b8[:]...)
		if n == 1 {
			binary.LittleEndian.PutUint64(b8[:], 7)
			dup = append(dup, b8[:]...)
		}
	}
	if crushDecompress(dup) != nil {
		t.Fatal("位置冲突未拒绝")
	}
}
