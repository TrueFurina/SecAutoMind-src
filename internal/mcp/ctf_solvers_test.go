package mcp

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// ctf_solvers_test.go —— 确定性求解器单元测试（样例输入 → 期望命中）

func TestFlagRegexScan(t *testing.T) {
	// 直接测 flagRegex（flag_scan 工具核心）
	cases := []struct {
		in   string
		want bool
	}{
		{"恭喜你！flag{Th1s_1s_a_t3st_fl4g}", true},
		{"CTF{easy_flag_2026}", true},
		{"源码注释: // key = mju{secaut0mind_r0cks}", true},
		{"这里没有任何 flag 内容", false},
	}
	for _, c := range cases {
		if got := flagRegex.MatchString(c.in); got != c.want {
			t.Errorf("flagRegex.MatchString(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestDecodeLayers_MultilayerBase64(t *testing.T) {
	// 三层 base64 包裹的 flag
	// flag{layer3_ok} -> base64 -> base64 -> base64
	flag := "flag{layer3_ok}"
	l1 := base64Std(flag)
	l2 := base64Std(l1)
	l3 := base64Std(l2)
	layers := decodeLayers(l3, 12)
	if len(layers) == 0 {
		t.Fatalf("decodeLayers 未解出任何层")
	}
	joined := strings.Join(layers, " ")
	if !strings.Contains(joined, "flag{layer3_ok}") {
		t.Errorf("解码链路未还原 flag: %v", layers)
	}
}

func TestCaesarBruteforce_FindsFlag(t *testing.T) {
	// 明文 "the flag is mju{caesar_ok}" 移位 3
	plain := "the flag is mju{caesar_ok}"
	cipher := caesarShift(plain, 3)
	cands := caesarBruteforce(cipher)
	if len(cands) == 0 {
		t.Fatalf("凯撒爆破无候选")
	}
	joined := strings.Join(cands, " ")
	if !strings.Contains(joined, "flag{caesar_ok}") && !strings.Contains(joined, plain) {
		t.Errorf("凯撒爆破未还原明文: %v", cands)
	}
}

func TestXORSingleByte_FindsPlain(t *testing.T) {
	plain := "the flag is mju{xor_ok} just text"
	data := make([]byte, len(plain))
	key := byte(0x42)
	for i := range plain {
		data[i] = plain[i] ^ key
	}
	cands := xorSingleByteBruteforce(data)
	if len(cands) == 0 {
		t.Fatalf("XOR 爆破无候选")
	}
	joined := strings.Join(cands, " ")
	if !strings.Contains(joined, "xor_ok") {
		t.Errorf("XOR 爆破未还原明文: %v", cands)
	}
}

// ───────── 测试辅助 ─────────

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// caesarShift 加密辅助（测试用）：字母移 shift 位
func caesarShift(s string, shift int) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune('a' + (r-'a'+rune(shift))%26)
		case r >= 'A' && r <= 'Z':
			sb.WriteRune('A' + (r-'A'+rune(shift))%26)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// ───────── S2-S7 新增求解器测试 ─────────

func TestCrackCommonHash_MD5(t *testing.T) {
	// md5("admin123")
	sum := md5.Sum([]byte("admin123"))
	hexHash := hex.EncodeToString(sum[:])
	plain, algo, ok := crackCommonHash(hexHash)
	if !ok || plain != "admin123" || algo != "md5" {
		t.Errorf("md5 爆破失败: plain=%q algo=%q ok=%v", plain, algo, ok)
	}
}

func TestCrackCommonHash_SHA256WithSuffix(t *testing.T) {
	// sha256("ctf2026") 在词表+后缀组合中
	sum := sha256.Sum256([]byte("ctf2026"))
	hexHash := hex.EncodeToString(sum[:])
	plain, algo, ok := crackCommonHash(hexHash)
	if !ok || algo != "sha256" {
		t.Errorf("sha256 爆破失败: plain=%q algo=%q ok=%v", plain, algo, ok)
	}
	if plain != "ctf2026" {
		t.Errorf("sha256 命中错误明文: %q", plain)
	}
}

func TestFermatAttack_FindsPlain(t *testing.T) {
	// 动态生成两个相近真素数 p/q（费马可解场景），flag 编码为明文整数
	base := new(big.Int).Exp(big.NewInt(2), big.NewInt(190), nil) // 2^190 量级
	p := nextPrimeFrom(base)
	q := nextPrimeFrom(new(big.Int).Add(p, big.NewInt(2))) // 紧跟的下一个素数 → 差距小
	n := new(big.Int).Mul(p, q)
	e := big.NewInt(65537)
	phi := new(big.Int).Mul(new(big.Int).Sub(new(big.Int).Set(p), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Set(q), big.NewInt(1)))
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		t.Fatal("测试数据构造失败：d 不可求")
	}
	flag := []byte("flag{fermat_works}")
	m := new(big.Int).SetBytes(flag)
	if m.Cmp(n) >= 0 {
		t.Fatal("flag 大于 n，需更大素数")
	}
	c := new(big.Int).Exp(m, e, n)
	out, err := fermatAttack(n.String(), e.String(), hex.EncodeToString(c.Bytes()))
	if err != nil {
		t.Fatalf("费马分解失败: %v", err)
	}
	if !strings.Contains(out, "flag{fermat_works}") {
		t.Errorf("费马未还原明文 flag: %s", out)
	}
}

// nextPrimeFrom 返回 >= start 的下一个（奇）素数（Miller-Rabin 概率素性）
func nextPrimeFrom(start *big.Int) *big.Int {
	cand := new(big.Int).Set(start)
	if cand.Bit(0) == 0 { // 偶数 → 变奇数
		cand.Add(cand, big.NewInt(1))
	}
	for {
		if cand.ProbablyPrime(24) {
			return cand
		}
		cand.Add(cand, big.NewInt(2))
	}
}

func TestCommonModulusAttack_FindsPlain(t *testing.T) {
	// 构造：同一 n（两真素数乘积）、两个互质 e1/e2、同一明文 m
	base := new(big.Int).Exp(big.NewInt(2), big.NewInt(200), nil)
	p := nextPrimeFrom(base)
	q := nextPrimeFrom(new(big.Int).Add(p, big.NewInt(1000))) // 拉开差距避免与费马重叠
	n := new(big.Int).Mul(p, q)
	e1 := big.NewInt(65537)
	e2 := big.NewInt(17) // gcd(65537,17)=1
	flag := []byte("flag{common_modulus_works}")
	m := new(big.Int).SetBytes(flag)
	if m.Cmp(n) >= 0 {
		t.Fatal("flag 大于 n，需更大素数")
	}
	c1 := new(big.Int).Exp(m, e1, n)
	c2 := new(big.Int).Exp(m, e2, n)
	out, err := commonModulusAttack(n.String(), e1.String(), hex.EncodeToString(c1.Bytes()),
		e2.String(), hex.EncodeToString(c2.Bytes()))
	if err != nil {
		t.Fatalf("共模攻击失败: %v", err)
	}
	if !strings.Contains(out, "flag{common_modulus_works}") {
		t.Errorf("共模攻击未还原明文: %s", out)
	}
}
