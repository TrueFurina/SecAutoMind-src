package runnerl3

import (
	"strings"
	"testing"
)

// TestBuildSystemPromptMentionsCtfCrypto 锁住：R3 注入的 ctf_crypto 库必须在系统提示词里
// 以「签名级参考」形式给到模型——否则非推理模型(V3)会猜错参数名而调用失败，等于白注入。
func TestBuildSystemPromptMentionsCtfCrypto(t *testing.T) {
	sp := new(LLMFallback).buildSystemPrompt()

	must := []string{
		"import ctf_crypto as C",
		"ctf_crypto 即用原语",
		// 从 ctf_crypto_reference.go 抽几个关键签名，确保参考真的拼进了提示词
		"rsa_wiener(e, n)",
		"rsa_fermat(n, rounds=20000)",
		"rsa_common_modulus(c1, c2, e1, e2, n)",
		"rsa_broadcast(e, pairs)",
		"modinv(a, m)",
		"crt(rems, mods)",
		"lll(B, delta=0.75)",
		"identify_hash(s)",
		"hash_bytes(data: bytes, algo='sha256')",
		"xor_bytes(a, b)",
		"aes_ecb_decrypt(ct, key)",
		"aes_cbc_decrypt(ct, key, iv)",
		"des_decrypt(ct, key)",
		"ECPoint(x, y, a, b, p)",
		"bsgs(base, target, p, order=None)",
	}
	for _, m := range must {
		if !strings.Contains(sp, m) {
			t.Errorf("系统提示词缺少 ctf_crypto 参考项: %q", m)
		}
	}
}
