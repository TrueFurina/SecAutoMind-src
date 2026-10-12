// presolve_xor_known_plaintext.go —— XOR 已知明文（known-plaintext）攻击求解器。
//
// 背景与边界（与 bfxXorCrib 的分工）：
//   - bfxXorCrib（forensics_binary.go）恢复周期 1..8 的短重复密钥（flag 前缀 crib），
//     并明确不覆盖"密钥长度=明文长度"的一次性密钥——那在数学上确实不可恢复。
//   - 但有一类真实赛题结构**可以**解：密钥即 flag 本身，而明文是公开可查的模板句。
//     典型实证：WolvCTF 2024 Crypto "Yors Truly"（nightxade / ctftime 公开 writeup）：
//
//	plaintext = "A string of text can be encrypted by applying the bitwise XOR
//	             operator to every character using a given key"   // 题目源码给出
//	key       = flag                                              // flag 当时序密钥
//	ct        = pt XOR key                                        // zip 截断 → len(ct)==len(flag)
//
//     此时 key = ct XOR pt 可直接恢复，而 key 就是 flag。描述里只给密文（base64），
//     明文来自模板库——这就是已知明文攻击，不是注水。
//
// 防误报双重门槛（缺一不可）：
//  1. isPrintableFlagCandidate：恢复串必须干净可打印 ASCII（模板不匹配 → 乱码 → 拒绝）；
//  2. scanFlags：必须命中 flag 外形正则（品牌前缀 / 通用 前缀{内容}）。
// 另与 SHA-256 机验（presolve_benchmark_test.go）互为独立校验。
package ctfplatform

import (
	"context"
	"encoding/base64"
)

// xorKnownPlaintextTemplates 已知明文模板库：公开赛题中真实出现过的 XOR 明文。
// 收录标准：该句确实作为某道公开题的明文出现（可查 writeup）或为经典通用测试句；
// 不凭感觉堆砌句子——模板越杂，误报面越大，而收益并不会增加。
var xorKnownPlaintextTemplates = []string{
	// WolvCTF 2024 Crypto "Yors Truly"：题目源码内明文 + flag 当时序密钥，
	// 密文 28B == flag 长度（zip 截断）。ct = pt XOR flag ⇒ flag = ct XOR pt。
	"A string of text can be encrypted by applying the bitwise XOR operator to every character using a given key",
	// 经典 pangram：通用测试句，覆盖同类"模板句 XOR"变体（无特定赛题实证，纯技术泛化）。
	"The quick brown fox jumps over the lazy dog",
}

// tryXORKnownPlaintext 对文本中的 base64 令牌做已知明文 XOR 攻击：
// 对每个模板句推导 key = ct XOR pt，key 通过"干净可打印 + flag 外形"双重门槛即报告。
func tryXORKnownPlaintext(text string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, tok := range b64TokenRegex.FindAllString(text, -1) {
		ct, err := base64.StdEncoding.DecodeString(padBase64(tok))
		if err != nil || len(ct) < 8 {
			continue
		}
		for _, tmpl := range xorKnownPlaintextTemplates {
			// zip 语义：异或结果长度 = min(len(ct), len(tmpl))。
			// 密文长于模板时只能恢复 flag 前缀（无右花括号，scanFlags 自然不会命中）。
			n := len(ct)
			if n > len(tmpl) {
				n = len(tmpl)
			}
			key := make([]byte, n)
			for i := 0; i < n; i++ {
				key[i] = ct[i] ^ tmpl[i]
			}
			if !isPrintableFlagCandidate(string(key)) {
				continue
			}
			for _, f := range scanFlags(string(key)) {
				if !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
			}
		}
	}
	return out
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "xor_known_plaintext", Category: CategoryCryptoS, Priority: 37,
		Solver: func(_ context.Context, text string, _ map[string]string) []string {
			return tryXORKnownPlaintext(text)
		},
	})
}
