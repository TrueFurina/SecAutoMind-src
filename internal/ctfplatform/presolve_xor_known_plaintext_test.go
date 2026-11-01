package ctfplatform

import "testing"

// presolve_xor_known_plaintext_test.go —— 锁死 XOR 已知明文攻击求解器。
//
// ⚠️ 夹具是**合成**的，不是任何赛题的真答案。
//
// 原因（2026-10-28 实锤）：原先这里放的是 WolvCTF 2024 "Yors Truly" 的真实密文 + 真 flag。
// 但该题结构是「flag 当时序密钥、明文取自模板句」，即
//
//	ct XOR 模板句 == flag
//
// 也就是说「密文 + 本文件依赖的模板库」本身就等价于答案：任何人（包括跑批时的 agent）
// 只要读到这个 base64，跑一遍 tryXORKnownPlaintext 就能把 flag 算出来。
// 跑批时确实发生过模型 grep 出答案直接抄的事故，所以真实样本一律不留在仓库/主机上。
//
// 机制覆盖不变：仍用同一句模板（"The quick brown fox..."）构造等长合成实例，
// ct = tmpl XOR flag，len(ct) == len(tmpl) == len(flag) == 43。
// 真实赛题的回归由 benchmark 跑批（只喂 description、只对 flag_sha256）负责。

func TestXORKnownPlaintext_KnownTemplate(t *testing.T) {
	const ctB64 = "IwsRRgoeBwwcTj0CAxYHThIKAFQ1EwQIB1UdEzocTwA3F0UNDSVJEFReGg=="
	const want = "wctf{known_plaintext_fixture_not_real_0001}"
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
