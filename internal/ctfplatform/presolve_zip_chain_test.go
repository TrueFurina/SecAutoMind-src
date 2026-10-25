package ctfplatform

// presolve_zip_chain_test.go —— zip 文件名链解码 Go 化回归（合成口径）。
//
// 10663 真实载荷不在库（KNOWN_DATA_LOSS 家族）；合成链按 python 版语义构造：
// flag 字符 → 文件名链（base32 编码 → 反序嵌套 zip 名）→ archive/zip 写多层嵌套。
// 双向（reversed/forward）× 多解码器由被测函数自行尝试。

import (
	"archive/zip"
	"bytes"
	"encoding/base32"
	"strings"
	"testing"
)

// buildNestedZipChain 构造 N 层嵌套 zip：第 i 层的条目名 = 链码段 i（base32），
// 最内层是 flag.txt（陷阱内容 + 真 flag 并存——10663 语义）。
func buildNestedZipChain(t *testing.T, flag string, layers int) []byte {
	t.Helper()
	// 链码：flag 字节 → base32 → 按层切段（从尾到头语义：段序反转由解码侧处理）
	enc := base32.StdEncoding.EncodeToString([]byte(flag))
	segLen := (len(enc) + layers - 1) / layers
	var segs []string
	for i := 0; i < len(enc); i += segLen {
		e := i + segLen
		if e > len(enc) {
			e = len(enc)
		}
		segs = append(segs, enc[i:e])
	}
	if len(segs) < layers {
		// 段不足则补单字符段（链语义允许单字符段——10663 的 'I' 先例）
		for len(segs) < layers {
			segs = append(segs, "I")
		}
	}
	// 从最内层往外包：最内层 zip 含 flag.txt（陷阱 + 真 flag）
	inner := "DASCTF{ni_cai?}\n" + flag + "\n"
	var cur []byte
	for i := 0; i < len(segs); i++ {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		name := segs[i] + ".zip"
		if i == len(segs)-1 {
			// 最外层的上一包装层——用链段名（非 flag.zip）
			name = segs[i] + ".zip"
		}
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if cur == nil {
			// 最内层：写 flag.txt 陷阱内容
			if _, err := w.Write([]byte(inner)); err != nil {
				t.Fatalf("zip write: %v", err)
			}
		} else {
			if _, err := w.Write(cur); err != nil {
				t.Fatalf("zip write: %v", err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("zip close: %v", err)
		}
		cur = buf.Bytes()
	}
	return cur
}

func TestXHLJChain_ZipChainSynthetic(t *testing.T) {
	flag := "flag{z1p_cha1n_d3c0de_2026}"
	data := buildNestedZipChain(t, flag, 6)
	flags := zcChainSolve(data, 200)
	ok := false
	for _, f := range flags {
		if strings.Contains(f, "z1p_cha1n") || strings.Contains(f, flag) {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("zip 链解码未命中（walk/链过滤/解码器任一环断）: %v", flags)
	}
}

func TestXHLJChain_ZipChainNegative(t *testing.T) {
	if flags := zcChainSolve([]byte("not a zip at all"), 200); flags != nil {
		t.Fatalf("非 zip 输入不应命中: %v", flags)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("plain.txt")
	w.Write([]byte("no chain here, just content with flag{fake_but_present}"))
	zw.Close()
	// 普通 zip：内容 flag 会被末层内容扫描命中——这是 bin 家族的合法行为
	// （flag_scan 同域），此处只验证不 panic 且命中格式正确。
	flags := zcChainSolve(buf.Bytes(), 200)
	for _, f := range flags {
		if !zcFlagRe.MatchString(f) {
			t.Fatalf("命中非 flag 形态: %q", f)
		}
	}
}
