package ctfplatform

import (
	"context"
	"strings"
	"testing"
)

// ── presolve 确定性求解器单测 ──────────────────────────

func TestScanFlags(t *testing.T) {
	cases := []struct {
		in   string
		want int // 期望命中数量
	}{
		{"flag{hello_world}", 1},
		{"CTF{test123} and flag{another}", 2},
		{"no flags here", 0},
		{"key = flag{test_flag}", 1},
	}
	for _, c := range cases {
		got := scanFlags(c.in)
		if len(got) != c.want {
			t.Errorf("scanFlags(%q) = %d flags, want %d", c.in, len(got), c.want)
		}
	}
}

func TestPresolve_FlagScan(t *testing.T) {
	p := NewPresolver(nil)
	ch := &Challenge{Description: "请分析这段文本 flag{test_presolve}"}
	result := p.Presolve(context.Background(), ch, nil)
	if !result.Solved {
		t.Fatal("presolve 应该命中 flag")
	}
	// 并发扇出下 flag_scan 和 web_source_audit 都可能命中（都含 scanFlags），
	// 只检查 flag 被正确提取，不限定 engine 名
	found := false
	for _, f := range result.Flags {
		if strings.Contains(f, "flag{test_presolve}") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("presolve 命中但未包含正确 flag: %v", result.Flags)
	}
}

func TestPresolve_Base64Multilayer(t *testing.T) {
	p := NewPresolver(nil)
	// 两层 base64 包裹 flag
	inner := "flag{base64_test}"
	l1 := base64Encode(inner)
	l2 := base64Encode(l1)
	ch := &Challenge{Description: "解码: " + l2}
	result := p.Presolve(context.Background(), ch, nil)
	if !result.Solved {
		t.Fatal("presolve 应该通过 base64_multilayer 命中")
	}
}

func TestPresolve_Caesar(t *testing.T) {
	p := NewPresolver(nil)
	// 凯撒移位 3
	cipher := caesarEncrypt("flag{caesar_test}", 3)
	ch := &Challenge{Description: cipher}
	result := p.Presolve(context.Background(), ch, nil)
	if !result.Solved {
		t.Fatal("presolve 应该通过 caesar 命中")
	}
}

func TestPresolve_NoHit(t *testing.T) {
	p := NewPresolver(nil)
	ch := &Challenge{Description: "这是一段普通文本，没有任何CTF特征"}
	result := p.Presolve(context.Background(), ch, nil)
	if result.Solved {
		t.Error("presolve 不应该命中")
	}
}

// TestScanFlags_PreservesPrefix 品牌前缀必须完整保留（sha256 校验依赖完整 flag）。
// 这里只验证「前缀没有被截断」，用合成值即可，不需要真题答案。
func TestScanFlags_PreservesPrefix(t *testing.T) {
	const want = "picoCTF{PREFIX_PRESERVED_fixture}"
	got := scanFlags("token: " + want)
	if len(got) != 1 || got[0] != want {
		t.Errorf("scanFlags 应完整保留 picoCTF 前缀, got %v", got)
	}
}

// TestPresolve_RealQuestionChains 用真题基准集中因链式解码 MISS 的题回归。
//
// 断言用 sha256 而非明文：2026-10-28 实锤，旧版把 5 道真题的明文 flag 直接写成 wantFlag，
// 而跑批 agent 与测试文件同处一台主机 —— 模型 grep 一下就能抄答案（已实际发生）。
// 题库判分本来也只认 flag_sha256（见 scripts/experiments/flag_util.py），
// 测试沿用同一口径：断言哈希相等。哈希不可逆，抄不到答案。
// 题面（密文）保留——它本来就是要喂给模型的题。
func TestPresolve_RealQuestionChains(t *testing.T) {
	cases := []struct {
		name        string
		description string
		wantSHA256  string // 真题答案：只存哈希
		wantFlag    string // 合成夹具：直接比对明文
	}{
		{
			// picoCTF 2024 interencdec：b64 → b64 → caesar(19)（三层链式，已验证通过）
			name:        "interencdec_b64_b64_caesar",
			description: "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgyMHdNakV5TnpVNGZRPT0nCg==",
			wantSHA256:  "c02afc1d7e3c56d8bcba181d83a74b9fe15a42863e9d64c65a80b40a8ae1806d",
		},
		{
			// picoCTF 2024 CanYouSee：单层 b64，验证前缀完整保留
			name:        "canyousee_prefix",
			description: "cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg==",
			wantSHA256:  "af7ca42db24fe2d65b886a67d70bd65bc192bf32bfcbcf5581ad7a0838c3901e",
		},
		{
			// CyberConverge 2025 Layers：v6.1 重建后单层 b64（原始密文与 flag 不一致，已重建自洽）
			name:        "layers_b64",
			description: "Q0JDVntjUnk5VDBfTDR5M3I1XzRSRV9GdU5fMzEzNX0=",
			wantSHA256:  "2db6c8ce9ec69dfad2b02fd53e92174969516cfbb9a6414c3c66c57f3de52144",
		},
		{
			// base64_triple_real：v6.2 重建后三层 b64
			name:        "triple_base64",
			description: "V20xNGFGb3pkREJqYld4M1lrZFdabGx0Um5wYVZGa3dXREpTYkZreU9XdGFWMUk1",
			wantSHA256:  "501d16e3b2553f8a7591c8bf0f126d816f6b3cfb81f4c131303a8a023c5b9561",
		},
		{
			// ehaxctf2025_morse：v6.2 重建后已知密钥维吉尼亚（kagi）；密文形似 flag，必须先解密再扫
			name:        "vigenere_known_key",
			description: "维吉尼亚解密(密钥kagi): OHGF{w0ry3_d1q3n3x3_0x3b4t10t}",
			wantSHA256:  "66049fb8b6a21a77e56b360fee797ac7dc34734a91f5f97f0cbee681d1a811ad",
		},
		{
			// 单层 b64 + flag_scan（合成夹具：flag 直接在解码文本中）
			name:        "b64_flag_scan",
			description: "ZmxhZ3t0ZXN0X2Jhc2U2NF9mbGFnfQ==",
			wantFlag:    "flag{test_base64_flag}",
		},
	}
	p := NewPresolver(nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch := &Challenge{Description: c.description}
			result := p.Presolve(context.Background(), ch, nil)
			if !result.Solved {
				t.Fatalf("presolve 应命中 %s", c.name)
			}
			found := false
			for _, f := range result.Flags {
				if c.wantSHA256 != "" {
					if sha256Hex(f) == c.wantSHA256 {
						found = true
						break
					}
				} else if f == c.wantFlag {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("flags 中无期望答案（sha256=%s want=%q）: %v",
					c.wantSHA256, c.wantFlag, result.Flags)
			}
		})
	}
}

// ── analyzer 任务分析单测 ──────────────────────────────

func TestAnalyzer_RSADetection(t *testing.T) {
	a := NewTaskAnalyzer()
	ch := &Challenge{
		Description: "from Crypto.PublicKey import RSA\ne = 3\nn = 123456789\nc = 987654321",
	}
	routes := a.Analyze(ch, nil)
	if len(routes) == 0 {
		t.Fatal("应该检测到 RSA")
	}
	found := false
	for _, r := range routes {
		if r.Category == CategoryCrypto && r.SubType == "RSA" {
			found = true
			break
		}
	}
	if !found {
		t.Error("应该路由到 RSA")
	}
}

func TestAnalyzer_MorseDetection(t *testing.T) {
	a := NewTaskAnalyzer()
	ch := &Challenge{Description: ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."}
	routes := a.Analyze(ch, nil)
	if len(routes) == 0 {
		t.Fatal("应该检测到 Morse")
	}
}

func TestAnalyzer_ExplicitCategory(t *testing.T) {
	a := NewTaskAnalyzer()
	ch := &Challenge{Category: "web", Description: "SQL injection challenge"}
	routes := a.Analyze(ch, nil)
	if len(routes) == 0 {
		t.Fatal("应该有路由")
	}
	if routes[0].Category != CategoryWeb {
		t.Errorf("category = %s, want web", routes[0].Category)
	}
}

// ── 工具函数 ─────────────────────────────────────────────

func base64Encode(s string) string {
	import_b64 := [256]byte{}
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i, c := range std {
		import_b64[c] = byte(i)
	}
	// 简单实现
	encoded := ""
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var b [3]byte
		n := copy(b[:], data[i:])
		encoded += string(std[b[0]>>2])
		if n > 1 {
			encoded += string(std[((b[0]&0x03)<<4)|(b[1]>>4)])
		} else {
			encoded += "="
		}
		if n > 2 {
			encoded += string(std[((b[1]&0x0f)<<2)|(b[2]>>6)])
			encoded += string(std[b[2]&0x3f])
		} else if n > 1 {
			encoded += string(std[((b[1] & 0x0f) << 2)])
			encoded += "="
		} else {
			encoded += "=="
		}
	}
	return encoded
}

func caesarEncrypt(s string, shift int) string {
	var result []byte
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			result = append(result, byte('a'+(c-'a'+rune(shift))%26))
		} else if c >= 'A' && c <= 'Z' {
			result = append(result, byte('A'+(c-'A'+rune(shift))%26))
		} else {
			result = append(result, byte(c))
		}
	}
	return string(result)
}
