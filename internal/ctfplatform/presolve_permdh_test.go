package ctfplatform

// presolve_permdh_test.go —— 置换 DH 求解器测试（2026-10-26）。
// 用小置换（可手算）验证轮换分解/移位/CRT 三件套；sha256 路径以
// PYTHONHASHSEED=0 采源场景的确定性替身（int64 LE 流）做端到端。

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"
)

func smallPermPow(p []int64, k int64) []int64 {
	out := make([]int64, len(p))
	for i := range p {
		// 沿轮换走 k 步：直接模拟 k 次（小规模够用）
			cur := int64(i)
		for j := int64(0); j < k; j++ {
			cur = p[cur]
		}
		out[i] = cur
	}
	return out
}

func TestPermCyclesAndPow(t *testing.T) {
	// g = [1,2,0, 4,5,3] → 轮换 (0 1 2)(3 4 5)，L=3
	g := []int64{1, 2, 0, 4, 5, 3}
	cyc := permCycles(g)
	if len(cyc) != 2 || len(cyc[0]) != 3 || len(cyc[1]) != 3 {
		t.Fatalf("轮换分解错: %v", cyc)
	}
	a := big.NewInt(7)
	A := permPow(g, a)
	want := smallPermPow(g, 7)
	for i := range want {
		if A[i] != want[i] {
			t.Fatalf("g^7 移位错 @%d: %v vs %v", i, A, want)
		}
	}
}

func TestRecoverA(t *testing.T) {
	g := []int64{1, 2, 0, 4, 5, 3}
	a := big.NewInt(7)
	A := permPow(g, a)
	got, ok := recoverA(g, A)
	if !ok {
		t.Fatal("a 恢复失败")
	}
	// a 只恢复到 mod lcm(3,3)=3 —— 7 mod 3 = 1
	if new(big.Int).Mod(got, big.NewInt(3)).Int64() != 7%3 {
		t.Fatalf("a 恢复值错: %v", got)
	}
}

func TestPermDHEndToEndDeterministicHash(t *testing.T) {
	// 端到端（确定性 hash 替身口径）：g/A/B + secb=int64 LE 流场景
	g := []int64{1, 2, 0, 4, 5, 3, 6, 7} // 含固定点
	a := big.NewInt(2) // 必须 < lcm(轮换长)：g 轮换 (0 1 2)(3 4 5)(6)(7)，lcm=3
	b := big.NewInt(5)
	A := permPow(g, a)
	B := permPow(g, b)
	C := permPow(B, a) // g^(ab)

	secb := permToBytes(C)
	h := sha256.Sum256(secb)
	key := h[16:32]
	plain := []byte("FlagExam{perm_dh_fixed_seed_ok}")
	padded := padPKCS7(plain, 16)
	_ = padded

	// 构造题面文本（g/A/B 列表 + iv + c，c 用本 key 加密）
	iv := []byte("0123456789abcdef")
	ct, err := permDhCBCEncrypt(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	text := "g = " + permDhListStr(g) + "\nA = " + permDhListStr(A) + "\nB = " + permDhListStr(B) + "\n" +
		"iv = b\"" + string(iv) + "\"\nc = b\"" + b64enc(ct) + "\"\n" +
		"key = sha256(sec_bytes)[16:32]\n"
	flags := tryPermutedDH(text)
	if len(flags) == 0 {
		// 逐层自证：解析→恢复→幂
		ms := permDhRe.FindAllStringSubmatch(text, -1)
		t.Logf("解析组数=%d", len(ms))
		var gg, aa, bb []int64
		for _, m := range ms {
			lst := parsePermList(m[2])
			switch m[1] {
			case "g":
				gg = lst
			case "A":
				aa = lst
			case "B":
				bb = lst
			}
		}
		t.Logf("aa==程序内A: %v, bb==程序内B: %v",
			bytes.Equal(permToBytes(aa), permToBytes(A)), bytes.Equal(permToBytes(bb), permToBytes(B)))
		got, ok := recoverA(gg, aa)
		t.Logf("recoverA ok=%v got=%v", ok, got)
		Cc := permPow(bb, got)
		t.Logf("B^a==C: %v", bytes.Equal(permToBytes(Cc), permToBytes(C)))
		t.Logf("B^5==C: %v", bytes.Equal(permToBytes(permPow(bb, big.NewInt(5))), permToBytes(C)))
		t.Logf("C 头8: %v", C[:8])
		t.Fatalf("端到端失败（text len=%d）", len(text))
	}
	if !bytes.Contains([]byte(flags[0]), []byte("perm_dh_fixed_seed_ok")) {
		t.Fatalf("锚错: %v", flags)
	}
}

func padPKCS7(b []byte, bs int) []byte {
	n := bs - len(b)%bs
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}
