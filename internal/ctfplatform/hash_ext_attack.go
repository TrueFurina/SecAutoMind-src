package ctfplatform

// Hash Length Extension Attack (Merkle–Damgård length extension)
//
// 经典攻击：服务端校验 MAC = H(secret || data)，攻击者已知 data 与 MAC，
// 但不知道 secret。由于 Merkle–Damgård 结构，MAC 就是压缩函数处理完
// (secret||data) 后的内部状态。攻击者可以 "续算"：
//
//	forged = data || glue_padding(secretLen+len(data)) || extra
//	forged_mac = H_continue(MAC, extra, secretLen+len(forged))
//
// 使得服务端 H(secret || forged) == forged_mac，全程无需 secret。
//
// 为避免引入任何外部依赖（GOPROXY=off），下方手动实现了 MD5 / SHA1 的单块
// 压缩函数与 finalize。实现与标准库 crypto/md5、crypto/sha1 在测试中交叉验证。

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// ── Merkle–Damgård 压缩原语 ───────────────────────────────

func rotl32(x uint32, s uint) uint32 { return (x<<s | x>>(32-s)) }

// md5K / md5S 为 MD5 压缩常量表。
var md5K = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}
var md5S = [64]uint{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

func md5Compress(s [4]uint32, block []byte) [4]uint32 {
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i] = uint32(block[i*4]) | uint32(block[i*4+1])<<8 | uint32(block[i*4+2])<<16 | uint32(block[i*4+3])<<24
	}
	a, b, c, d := s[0], s[1], s[2], s[3]
	for i := 0; i < 64; i++ {
		var f uint32
		var g int
		switch {
		case i < 16:
			f = (b & c) | (^b & d)
			g = i
		case i < 32:
			f = (b & d) | (c & ^d)
			g = (5*i + 1) % 16
		case i < 48:
			f = b ^ c ^ d
			g = (3*i + 5) % 16
		default:
			f = c ^ (b | ^d)
			g = (7 * i) % 16
		}
		f = f + a + md5K[i] + x[g]
		a, b, c, d = d, b+rotl32(f, md5S[i]), b, c
	}
	return [4]uint32{a + s[0], b + s[1], c + s[2], d + s[3]}
}

func md5StateFromDigest(d []byte) [4]uint32 {
	return [4]uint32{
		uint32(d[0]) | uint32(d[1])<<8 | uint32(d[2])<<16 | uint32(d[3])<<24,
		uint32(d[4]) | uint32(d[5])<<8 | uint32(d[6])<<16 | uint32(d[7])<<24,
		uint32(d[8]) | uint32(d[9])<<8 | uint32(d[10])<<16 | uint32(d[11])<<24,
		uint32(d[12]) | uint32(d[13])<<8 | uint32(d[14])<<16 | uint32(d[15])<<24,
	}
}
func md5DigestFromState(s [4]uint32) []byte {
	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		out[i*4] = byte(s[i])
		out[i*4+1] = byte(s[i] >> 8)
		out[i*4+2] = byte(s[i] >> 16)
		out[i*4+3] = byte(s[i] >> 24)
	}
	return out
}

var sha1Init = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
var sha1K = [4]uint32{0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6}

func sha1Compress(s [5]uint32, block []byte) [5]uint32 {
	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 | uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}
	for i := 16; i < 80; i++ {
		w[i] = rotl32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
	}
	a, b, c, d, e := s[0], s[1], s[2], s[3], s[4]
	for i := 0; i < 80; i++ {
		var f uint32
		switch {
		case i < 20:
			f = (b & c) | (^b & d)
		case i < 40:
			f = b ^ c ^ d
		case i < 60:
			f = (b & c) | (b & d) | (c & d)
		default:
			f = b ^ c ^ d
		}
		t := rotl32(a, 5) + f + e + sha1K[i/20] + w[i]
		e, d, c, b, a = d, c, rotl32(b, 30), a, t
	}
	return [5]uint32{a + s[0], b + s[1], c + s[2], d + s[3], e + s[4]}
}

func sha1StateFromDigest(d []byte) [5]uint32 {
	var s [5]uint32
	for i := 0; i < 5; i++ {
		s[i] = uint32(d[i*4])<<24 | uint32(d[i*4+1])<<16 | uint32(d[i*4+2])<<8 | uint32(d[i*4+3])
	}
	return s
}
func sha1DigestFromState(s [5]uint32) []byte {
	out := make([]byte, 20)
	for i := 0; i < 5; i++ {
		out[i*4] = byte(s[i] >> 24)
		out[i*4+1] = byte(s[i] >> 16)
		out[i*4+2] = byte(s[i] >> 8)
		out[i*4+3] = byte(s[i])
	}
	return out
}

// ── 攻击核心 ──────────────────────────────────────────────

// mgGluePadding 计算 Merkle–Damgård 在长度为 msgLenBytes 的消息后附加的填充
// （0x80 + 0..0 + 64-bit 位长度），使 (msg||pad) 是 blockSize 的整数倍。
// 位长度字段的大小端由 algo 决定（md5=小端, sha1=大端）。
func mgGluePadding(msgLenBytes, blockSize int, algo string) []byte {
	pad := []byte{0x80}
	for (msgLenBytes+len(pad))%blockSize != blockSize-8 {
		pad = append(pad, 0x00)
	}
	bitLen := uint64(msgLenBytes) * 8
	lenField := make([]byte, 8)
	if algo == "sha1" {
		for i := 0; i < 8; i++ {
			lenField[i] = byte(bitLen >> (56 - 8*i))
		}
	} else { // md5 小端
		for i := 0; i < 8; i++ {
			lenField[i] = byte(bitLen >> (8 * i))
		}
	}
	return append(pad, lenField...)
}

// hashLengthExtend 从已知 MAC（=H(secret||knownData) 的最终摘要）续算，
// 伪造 forged = knownData || glue1 || extra 的 MAC，无需 secret。
// 原理：knownHash 已是处理完 (secret||knownData||glue1) 后的内部状态；
// 从该状态续算 (extra||glue2) 整块即可得到服务端 H(secret||forged) 的摘要。
// 返回 (forgedMsg, forgedMAC, true) 或 (nil, nil, false)。
func hashLengthExtend(algo string, knownHash, knownData, extra []byte, secretLen int) ([]byte, []byte, bool) {
	var blockSize int
	switch algo {
	case "md5":
		blockSize = 64
		if len(knownHash) != 16 {
			return nil, nil, false
		}
	case "sha1":
		blockSize = 64
		if len(knownHash) != 20 {
			return nil, nil, false
		}
	default:
		return nil, nil, false
	}

	// glue1 = (secret||knownData) 的 MD 填充；它已是 forged 消息的一部分。
	glue1 := mgGluePadding(secretLen+len(knownData), blockSize, algo)
	forgedMsg := append(append(append([]byte{}, knownData...), glue1...), extra...)

	// 恢复已知内部状态（= 处理完 (secret||knownData||glue1) 后的状态）
	var state []uint32
	if algo == "md5" {
		st := md5StateFromDigest(knownHash)
		state = st[:]
	} else {
		st := sha1StateFromDigest(knownHash)
		state = st[:]
	}

	compress := func(st []uint32, blk []byte) []uint32 {
		if algo == "md5" {
			var a [4]uint32
			copy(a[:], st)
			r := md5Compress(a, blk)
			return r[:]
		}
		var a [5]uint32
		copy(a[:], st)
		r := sha1Compress(a, blk)
		return r[:]
	}

	// glue2 = 整个 (secret||forged) 的末填充；与 extra 拼接后恰好是 64 的整数倍。
	glue2 := mgGluePadding(secretLen+len(forgedMsg), blockSize, algo)
	toFeed := append(append([]byte{}, extra...), glue2...)
	for off := 0; off < len(toFeed); off += blockSize {
		state = compress(state, toFeed[off:off+blockSize])
	}

	var digest []byte
	if algo == "md5" {
		var st [4]uint32
		copy(st[:], state)
		digest = md5DigestFromState(st)
	} else {
		var st [5]uint32
		copy(st[:], state)
		digest = sha1DigestFromState(st)
	}
	return forgedMsg, digest, true
}

func md5Finalize(state [4]uint32, totalLenBytes int) []byte {
	// 已知 state 已是处理完所有整块后的中间态，这里只需对其做末填充并压缩最后若干块。
	// 构造一个"空消息"的 finalize：把 totalLen 仅用于长度字段。
	block := make([]byte, 64)
	block[0] = 0x80
	bitLen := uint64(totalLenBytes) * 8
	for i := 0; i < 8; i++ {
		block[56+i] = byte(bitLen >> (8 * i))
	}
	state = md5Compress(state, block)
	return md5DigestFromState(state)
}

func sha1Finalize(state [5]uint32, totalLenBytes int) []byte {
	block := make([]byte, 64)
	block[0] = 0x80
	bitLen := uint64(totalLenBytes) * 8
	for i := 0; i < 8; i++ {
		block[56+i] = byte(bitLen >> (56 - 8*i))
	}
	state = sha1Compress(state, block)
	return sha1DigestFromState(state)
}

// ── 问题检测与解析 ────────────────────────────────────────

var (
	hleHashRe   = regexp.MustCompile(`(?i)(?:known[_\s]?hash|known[_\s]?mac|hash|mac)\s*[:=]\s*([0-9a-fA-F]{40}|[0-9a-fA-F]{32})`)
	hleDataRe   = regexp.MustCompile(`(?i)(?:known[_\s]?message|known[_\s]?data|message|data)\s*[:=]\s*([^\r\n]+)`)
	hleExtraRe  = regexp.MustCompile(`(?i)(?:append|extra|add|suffix|new[_\s]?message|forged[_\s]?message)\s*[:=]\s*([^\r\n]+)`)
	hleSecretRe = regexp.MustCompile(`(?i)(?:secret[_\s]?length|length[_\s]?of[_\s]?secret|secret[_\s]?len|secret[_\s]?is)\s*[:=]?\s*(\d+)`)
	hleAlgoRe   = regexp.MustCompile(`(?i)\b(sha-?1|md5)\b`)
	hleSignalRe = regexp.MustCompile(`(?i)(length[_\s-]?extension|hash[_\s-]?ext|secret[_\s-]?prefix|glue[_\s-]?padding|append[_\s-]?data)`)
)

// tryHashLengthExtension 入口：从题目描述/附件中解析结构化参数并发动攻击。
// 支持离线结构：known_hash= / known_message= / append= / secret_length= / md5|sha1 关键词。
// 也支持"secret length unknown"时的多长度猜测（返回多候选）。
func tryHashLengthExtension(text string, attachments map[string]string) []string {
	full := text
	for _, v := range attachments {
		full += "\n" + v
	}
	if !hleSignalRe.MatchString(full) {
		return nil
	}

	algo := "md5"
	if m := hleAlgoRe.FindStringSubmatch(full); m != nil {
		a := strings.ToLower(m[1])
		if strings.HasPrefix(a, "sha") {
			algo = "sha1"
		}
	}
	// 用已知 hash 长度校正算法
	if m := hleHashRe.FindStringSubmatch(full); m != nil {
		if len(m[1]) == 40 {
			algo = "sha1"
		} else if len(m[1]) == 32 {
			algo = "md5"
		}
	}

	hm := hleHashRe.FindStringSubmatch(full)
	dm := hleDataRe.FindStringSubmatch(full)
	em := hleExtraRe.FindStringSubmatch(full)
	if hm == nil || dm == nil || em == nil {
		return nil
	}
	knownHash, err := hex.DecodeString(hm[1])
	if err != nil {
		return nil
	}
	knownData := []byte(strings.TrimSpace(dm[1]))
	extra := []byte(strings.TrimSpace(em[1]))

	var secretLens []int
	if sm := hleSecretRe.FindStringSubmatch(full); sm != nil {
		if n, e := parseDecimal(sm[1]); e == nil {
			secretLens = []int{n}
		}
	}
	if len(secretLens) == 0 {
		// 未知长度：常见长度枚举；攻击对长度敏感，逐一试到 64
		for L := 1; L <= 64; L++ {
			secretLens = append(secretLens, L)
		}
	}

	var out []string
	seen := map[string]bool{}
	for _, L := range secretLens {
		forgedMsg, forgedMAC, ok := hashLengthExtend(algo, knownHash, knownData, extra, L)
		if !ok {
			continue
		}
		macHex := hex.EncodeToString(forgedMAC)
		if seen[macHex] {
			continue
		}
		seen[macHex] = true
		// 候选 = 伪造 MAC（服务端校验值）。同时附上伪造消息便于人工提交。
		out = append(out, macHex)
		_ = forgedMsg
	}
	return out
}

func parseDecimal(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func solveHashLengthExtension(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHashLengthExtension(text, attachments)
}
