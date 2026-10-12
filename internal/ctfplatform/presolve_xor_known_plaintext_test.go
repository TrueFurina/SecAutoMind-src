package ctfplatform

import "testing"

// presolve_xor_known_plaintext_test.go —— 锁死 XOR 已知明文攻击求解器。
//
// 正样本为 WolvCTF 2024 Crypto "Yors Truly" 实证密文（公开 writeup 可查）：
// flag 当时序密钥，key = ct XOR pt 恢复出的即 flag 本身。
// 负样本覆盖两类误报风险：普通 base64（模板不匹配）、非 base64 文本。

func TestXORKnownPlaintext_WolvCTF2024(t *testing.T) {
	// 题目描述只给密文（base64）；明文在模板库中。
	const ctB64 = "NkMHEgkxXjV/BlN/ElUKMVZQEzFtGzpsVTgGDw=="
	const want = "wctf{X0R_i5_f0rEv3r_My_L0Ve}"
	got := tryXORKnownPlaintext(ctB64)
	if len(got) == 0 {
		t.Fatalf("tryXORKnownPlaintext(%q) 未命中，want [%s]", ctB64, want)
	}
	if got[0] != want {
		t.Fatalf("tryXORKnownPlaintext(%q) = %v, want [%s]", ctB64, got, want)
	}
}

func TestXORKnownPlaintext_NoFalsePositive(t *testing.T) {
	negative := []string{
		"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==", // "Hello World! This is a test."
		"c2VjYXV0b21pbmQtYWktc2VjdXJpdHktcGxhdGZvcm0=", // 普通英文 base64
		"plain text without any base64 token at all",
		"MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", // 纯数字 base64
	}
	for _, in := range negative {
		if got := tryXORKnownPlaintext(in); len(got) != 0 {
			t.Errorf("输入 %q 不应误报，实际 %v", in, got)
		}
	}
}
