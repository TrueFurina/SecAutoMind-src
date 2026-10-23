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

// ── 大输入防护（2026-10-23 实测回归）────────────────────────────────
//
// 背景：服务器上 `go test ./...` 在 600s 默认上限被撞死，panic 栈显示
// `chainCollect` 正在处理一个 **0x76c37 = 486,455 字节** 的字符串，且已递归到深度 7。
// 根因：递归链成本 ≈ 深度 × 分支 × 输入长度，题干几百字节时无感，但**附件**可达几百 KB
// → 单题 >5 分钟，整包测试直接超时（本机与 128 核服务器均复现）。
// 修法：输入 > chainMaxInputBytes 直接放弃 + 全局节点预算 chainNodeBudget。
// 本组用例钉住"大输入必须快速返回"，防止有人日后把这两道闸拆掉。

func TestCodingChainHugeAttachmentSkipsFast(t *testing.T) {
	// 构造 540KB 左右的"附件"（真实场景就是二进制/大文本被塞进 attachments）
	big := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 12000)
	if len(big) <= chainMaxInputBytes {
		t.Fatalf("前置：构造的输入 %d 字节必须超过阈值 %d", len(big), chainMaxInputBytes)
	}
	got, nodes, bytes := tryCodingChainStats("flag 格式 flag{test}", map[string]string{"blob.bin": big})
	// 判据用**消耗**而不是墙钟：-race 下墙钟会放大 5~10x，写死秒数必假红。
	if nodes != 0 || bytes != 0 {
		t.Fatalf("超阈值输入应直接放弃（消耗必须为 0），实际 nodes=%d bytes=%d", nodes, bytes)
	}
	// 放弃是"不解"，但**不得**返回假 flag（截断/硬解出的东西绝不能冒充结果）
	for _, f := range got {
		if f != "flag{test}" {
			t.Fatalf("大输入放弃时却返回了非预期候选 %q（可能是截断后解出的假 flag）", f)
		}
	}
}

// TestCodingChainJustUnderCapIsBounded 阈值以内的"大文本"也必须被预算收住，
// 不能出现"差 1 字节就爆炸"的悬崖。
//
// ⚠️ 判据刻意**不用墙钟**：同一输入非 race 实测 3.4s、`-race` 下 27.4s（5~8x），
// 用秒数断言会在 CI 的 -race 里假红（本轮真踩过）。节点数/扫描字节数与竞态无关，
// 才是"预算生效"的真判据。
func TestCodingChainJustUnderCapIsBounded(t *testing.T) {
	body := strings.Repeat("abcdefghij klmnopqrst uvwxyz0123 456789 ", 4000)
	if len(body) > chainMaxInputBytes {
		body = body[:chainMaxInputBytes-1]
	}
	_, nodes, bytes := tryCodingChainStats(body, nil)
	t.Logf("接近阈值（%d 字节）→ nodes=%d（预算 %d）/ bytes=%d（预算 %d）",
		len(body), nodes, chainNodeBudget, bytes, chainByteBudget)
	if nodes > chainNodeBudget {
		t.Fatalf("节点数 %d 超过预算 %d —— 节点闸失效", nodes, chainNodeBudget)
	}
	// 记账是"进入节点即扣 len(s)"，故最多超出最后一步的一个节点长度
	if bytes > chainByteBudget+len(body) {
		t.Fatalf("扫描字节 %d 超过预算 %d（+单节点容差）—— 字节闸失效", bytes, chainByteBudget+len(body))
	}
	// 必须真的被字节闸收住（而不是压根没展开）：否则这个用例什么也没验证
	if bytes < chainByteBudget {
		t.Fatalf("字节消耗 %d 未触及预算 %d —— 用例没覆盖到闸门，需换更重的输入",
			bytes, chainByteBudget)
	}
}
