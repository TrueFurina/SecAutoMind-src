package ctfplatform

// presolve_xhlj_chains_test.go —— 吞并链 Go 化回归基准（synthetic 口径）。
//
// 来源：data/ctf_benchmark/xhlj_legacy/verify_chains_synthetic.py 的三条文本链，
// 实例串按该脚本逐字重建（2026-10-24 并行会话 Python 侧全 PASS；本文件把同一批
// 实例钉进 **Go 链**（chainCollect），锁住"Go registry 优先、兜底只在 miss 后"
// 架构里 Go 侧的组合命中能力。原题附件已永久丢失（KNOWN_DATA_LOSS），合成口径
// 按 chain_verify_20261024.json 惯例，不得冒充原始题解出。
//
// 每条链 = 一个 REGRESS_PASS 基准项（吞并路线图 §五.2 口径）。

import (
	"strings"
	"testing"
)

// 链 1 anwang_crypto1：八进制(空格分隔) → "key:KEY data:CIPHER" → Vigenère。
// 构造：letters-only vigenere(PLAIN, "FLagDecodeKeey")，逐字符 oct(ord)[2:] 空格连接。
const xhljAnwangInstance = "153 145 171 72 106 114 141 147 104 145 143 157 144 145 113 145 145 171 40 144 141 164 141 72 153 167 141 155 173 126 103 120 110 113 137 105 130 101 105 114 114 137 116 110 107 114 122 137 121 131 137 62 60 62 66 175"

func TestXHLJChain_AnwangOctalVigenere(t *testing.T) {
	got := strings.Join(tryCodingChain(xhljAnwangInstance, nil), "\n")
	if !containsFold(got, "flag{SYNTH_ANWANG_CHAIN_OK_2026}") {
		t.Fatalf("anwang 链（octal→keydata→vigenere）未在 Go 侧命中：\n%s", got)
	}
}

// 链 2 ezmult：base64 → ROT13（caesar 13）。
const xhljEzmultInstance = "c3ludHtGTEFHVV9STVpIWUdfTzY0X0VCRzEzX0JYfQ=="

func TestXHLJChain_EzmultBase64Rot13(t *testing.T) {
	got := strings.Join(tryCodingChain(xhljEzmultInstance, nil), "\n")
	if !containsFold(got, "flag{synth_ezmult") {
		t.Fatalf("ezmult 链（base64→caesar 13）未在 Go 侧命中：\n%s", got)
	}
}

// 链 3 qiangwang_classic：A=划/B=点 → morse → UUID 定位（morse 表与
// skills/morse_ab_decode.py 逐字一致，词边界在构造时即丢失——逐字符组解码）。
const xhljQiangwangInstance = "ABAB A BBAB BB BBB BBAB BBA AB BAAAA ABB AAABB BAAAA AABBB BBAB BBAAA BBBAA ABBBBA BA ABBB ABAB ABB ABBBBA BBBBA BBAB AAAAA BAAAA ABBBBA AAAAB BA BBAAA B ABBBBA AAAAA BAAAA BBAAA BBBAA BBBBA BBBBB ABBBB AABBB AAABB AAAAB BA ABBB B AB ABB"

func TestXHLJChain_QiangwangABMorse(t *testing.T) {
	got := strings.Join(tryCodingChain(xhljQiangwangInstance, nil), "\n")
	// 原题 flag = flag{1d817f23-…}（台账锚 f4adf0d8…）：UUID 由解码产物包壳而来
	// （uuidWrapRe 原语，2026-10-25 Go 化）。
	if !containsFold(got, "flag{1d817f23-abcd-4f01-9a2e-0123456789ab}") {
		t.Fatalf("qiangwang 链（AB→morse→UUID→flag 壳）未在 Go 侧命中：\n%s", got)
	}
}

// containsFold 大小写不敏感包含（与 verify_chains_synthetic.py 的 ok 判据一致）。
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
