// presolve_chain_test.go —— 跨原语递归解码链测试（2026-10-23 能力提升）
package ctfplatform

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// 构造：Vigenère 加密 "flag{anwang_crypto1}"（key=FLagDecodeKeey）后整体做八进制 ASCII。
// 期望链：octal → ASCII("key:... data:...") → 提取 key/data → Vigenère 解出 flag。
func TestCodingChainAnwang(t *testing.T) {
	plain := "flag{anwang_crypto1}"
	key := "FLagDecodeKeey"
	ct := vigenereEncrypt(plain, key)
	inner := "key:" + key + " data:" + ct
	oct := ""
	for _, r := range inner {
		oct += strconv.FormatInt(int64(r), 8) + " "
	}
	oct = strings.TrimSpace(oct)

	flags := tryCodingChain(oct, nil)
	found := false
	for _, f := range flags {
		if f == plain {
			found = true
		}
	}
	if !found {
		t.Fatalf("anwang 链未解出 %q，候选: %v", plain, flags)
	}
}

// 构造：base64(ROT13("flag{ezmult_chain}"))。期望链：base64 → rot13。
func TestCodingChainEzmult(t *testing.T) {
	plain := "flag{ezmult_chain}"
	rot := rot13(plain)
	b64 := base64.StdEncoding.EncodeToString([]byte(rot))
	flags := tryCodingChain(b64, nil)
	found := false
	for _, f := range flags {
		if f == plain {
			found = true
		}
	}
	if !found {
		t.Fatalf("ezmult 链未解出 %q，候选: %v", plain, flags)
	}
}

// 构造：A/B 摩斯（A=点 B=划）编码纯字母消息，期望解码链还原出消息文本。
func TestCodingChainQiangwangABMorse(t *testing.T) {
	msg := "flagqiangwang"
	morse := encodeMorseAB(msg, 'A', 'B') // A=dot B=dash
	dec := chainDecodeOnce(morse)
	found := false
	for _, c := range dec {
		if c.name == "ab_morse_a=dot" && c.decoded == msg {
			found = true
		}
	}
	if !found {
		t.Fatalf("AB 摩斯原语未解出 %q，候选: %+v", msg, dec)
	}
}

// 普通英文文本不应产生 flag 形态误报。
func TestCodingChainNoFalsePositive(t *testing.T) {
	plain := "This is just a normal English sentence without any hidden flag inside it."
	if flags := tryCodingChain(plain, nil); len(flags) != 0 {
		t.Fatalf("普通文本不应命中，候选: %v", flags)
	}
}

// ── 测试辅助（标准库实现） ──

// vigenereEncrypt Vigenère 加密（与 vigenereDecode 互为逆运算）。
func vigenereEncrypt(cipher, key string) string {
	cipher = strings.ToLower(cipher)
	key = strings.ToLower(key)
	var sb strings.Builder
	ki := 0
	for _, r := range cipher {
		if r >= 'a' && r <= 'z' {
			k := rune(key[ki%len(key)] - 'a')
			enc := 'a' + (r-'a'+k)%26
			sb.WriteRune(enc)
			ki++
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// encodeMorseAB 用 A/B 表示摩斯（aChar=点 bChar=划），符号间空格。
func encodeMorseAB(msg string, aChar, bChar rune) string {
	var sb strings.Builder
	for _, ch := range msg {
		lower := ch
		if lower >= 'A' && lower <= 'Z' {
			lower += 32
		}
		code := ""
		for m, letter := range morseTable {
			if letter == string(rune(lower)) {
				code = m
				break
			}
		}
		if code == "" {
			continue
		}
		for _, c := range code {
			if c == '.' {
				sb.WriteRune(aChar)
			} else {
				sb.WriteRune(bChar)
			}
		}
		sb.WriteRune(' ')
	}
	return strings.TrimSpace(sb.String())
}
