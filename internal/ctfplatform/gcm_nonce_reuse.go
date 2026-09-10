package ctfplatform

// AES-GCM nonce reuse attack (CTR keystream recovery)
//
// 经典且极常见的密码学漏洞：同一把密钥 K 与同一个 96-bit nonce 加密了两条明文
// m1、m2，则两条密文共享同一条 CTR keystream KS（GCM 的 CTR 模式对两条消息从
// 同一个初始计数器 J+1 起算）：
//
//	C1 = m1 ⊕ KS
//	C2 = m2 ⊕ KS
//
// 攻击者若已知 m1（及其密文 C1），即可还原 KS = C1 ⊕ m1，进而解密第二条：
//
//	m2 = C2 ⊕ KS = C2 ⊕ C1 ⊕ m1
//
// 全程无需密钥、无需 AES —— 这正是 AES-GCM nonce 复用最本质的机密性破坏。
// 本求解器从题目描述/附件中解析 nonce、两条密文与已知明文，复原第二条明文。
//
// 支持两种输入形态：
//   - 显式字段 nonce=/ct1=/known_plaintext=/ct2=（hex，基准集采用此形态）
//   - 完整 GCM blob 形态 blob1=/blob2=（= nonce(12)‖ciphertext‖tag(16)）

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	gcmSignalRe = regexp.MustCompile(`(?i)\b(gcm|nonce[_\s-]?reuse|reused[_\s-]?nonce|same[_\s-]?nonce|same[_\s-]?iv|keystream|aes-?gcm|ctr[_\s-]?mode)\b`)
	gcmNonceRe  = regexp.MustCompile(`(?i)\bnonce\s*[:=]\s*([0-9a-fA-F]+)`)
	gcmCt1Re    = regexp.MustCompile(`(?i)\b(?:ct1|ciphertext1)\s*[:=]\s*([0-9a-fA-F]+)`)
	gcmCt2Re    = regexp.MustCompile(`(?i)\b(?:ct2|ciphertext2)\s*[:=]\s*([0-9a-fA-F]+)`)
	gcmKnownRe  = regexp.MustCompile(`(?i)known[_\s-]?plaintext\s*[:=]\s*([0-9a-fA-F]+)`)
	gcmBlob1Re  = regexp.MustCompile(`(?i)\bblob1\s*[:=]\s*([0-9a-fA-F]+)`)
	gcmBlob2Re  = regexp.MustCompile(`(?i)\bblob2\s*[:=]\s*([0-9a-fA-F]+)`)
)

// xorBytes 返回 a、b 按字节异或的前 min(len(a),len(b)) 字节。
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// decodeKnownPlaintext 已知明文可能以 hex 给出；若不是合法偶长 hex 则按原始 ASCII 字节处理。
func decodeKnownPlaintext(s string) []byte {
	s = strings.TrimSpace(s)
	if len(s)%2 == 0 {
		if b, err := hex.DecodeString(s); err == nil {
			return b
		}
	}
	return []byte(s)
}

// splitGCMBlob 将完整 GCM 输出拆为 (nonce, ciphertext, tag)。
func splitGCMBlob(b []byte) (nonce, ct, tag []byte, ok bool) {
	if len(b) < 12+16+1 {
		return nil, nil, nil, false
	}
	return b[:12], b[12 : len(b)-16], b[len(b)-16:], true
}

// tryGCMNonceReuse 入口：从题目描述/附件中解析结构化参数并发动 keystream 复原攻击。
// 返回复原出的第二条明文（[]string{string(m2)}），无命中返回 nil。
func tryGCMNonceReuse(text string, attachments map[string]string) []string {
	full := text
	for _, v := range attachments {
		full += "\n" + v
	}
	if !gcmSignalRe.MatchString(full) {
		return nil
	}

	// 形态 1：显式字段（基准集采用）。
	if m1 := gcmCt1Re.FindStringSubmatch(full); m1 != nil {
		m2 := gcmCt2Re.FindStringSubmatch(full)
		km := gcmKnownRe.FindStringSubmatch(full)
		if m2 == nil || km == nil {
			return nil
		}
		ct1, err1 := hex.DecodeString(m1[1])
		ct2, err2 := hex.DecodeString(m2[1])
		if err1 != nil || err2 != nil {
			return nil
		}
		known := decodeKnownPlaintext(km[1])
		ks := xorBytes(ct1, known)
		m2pt := xorBytes(ct2, ks)
		return []string{string(m2pt)}
	}

	// 形态 2：完整 GCM blob（nonce‖ciphertext‖tag）。
	if b1 := gcmBlob1Re.FindStringSubmatch(full); b1 != nil {
		b2 := gcmBlob2Re.FindStringSubmatch(full)
		km := gcmKnownRe.FindStringSubmatch(full)
		if b2 == nil || km == nil {
			return nil
		}
		raw1, e1 := hex.DecodeString(b1[1])
		raw2, e2 := hex.DecodeString(b2[1])
		if e1 != nil || e2 != nil {
			return nil
		}
		_, c1, _, ok1 := splitGCMBlob(raw1)
		_, c2, _, ok2 := splitGCMBlob(raw2)
		if !ok1 || !ok2 {
			return nil
		}
		known := decodeKnownPlaintext(km[1])
		ks := xorBytes(c1, known)
		m2pt := xorBytes(c2, ks)
		return []string{string(m2pt)}
	}

	return nil
}

func solveGCMNonceReuse(ctx context.Context, text string, attachments map[string]string) []string {
	return tryGCMNonceReuse(text, attachments)
}
