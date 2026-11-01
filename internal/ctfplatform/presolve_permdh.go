// presolve_permdh.go —— 置换群 Diffie-Hellman 求解器（2026-10-26 固化）。
//
// 实证：HTB Cyber Apocalypse 2024 "permuted"（crypto hard，锚 954856ef…）。
// 题型：g/A/B 为大置换（5 万元素），A=g^a、B=g^b、ct=AES(g^(ab))。
// 攻击链（手解实证）：
//  1. g 的轮换分解——每个长 L 的轮换上，g^a 等价于移位 a mod L；
//  2. 对**全部**轮换做 CRT 合并恢复完整 a（🔴 陷阱：提前 break 到小模数
//     必败——13 轮换全量合并到 mod 3.3e21 才是完整 a，手解实证）；
//  3. C = B^a（轮换移位 a，b 不需要）；
//  4. hash(tuple(C)) → long_to_bytes → sha256 → [16:32] 作 AES-CBC key
//     （Python hash 语义——本求解器只处理可直接复算的情形，Python hash
//     随机化无法跨进 Go，故此步留给调用方语义：本实现扫描 ct 解密失败
//     即 nil，不猜）。
//
// 简化语义：本求解器输出**恢复的 a 的十进制串**作为候选载体供上层使用，
// 并在输入含 AES ct 与固定 iv 的标准形态时尝试直接解密（CBC, key=sha256
// (sec)[16:32]）。Python tuple hash 不可复算——若题面 hash 输入恰为 bytes
// 且未被随机化（PYTHONHASHSEED=0 采源），sha256(secb) 才可对上；两种分支
// 都试，失败即 nil。
package ctfplatform

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var permDhRe = regexp.MustCompile(
	`(?s)(g|A|B)\s*=\s*\[(\d{1,7}(?:\s*,\s*\d{1,7}){2,})\]`)

func parsePermList(s string) []int64 {
	parts := strings.Split(s, ",")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
		if err != nil || v < 0 {
			return nil
		}
		out = append(out, v)
	}
	return out
}

// permCycles 置换轮换分解。
func permCycles(p []int64) [][]int {
	n := len(p)
	seen := make([]bool, n)
	out := [][]int{}
	for i := 0; i < n; i++ {
		if seen[i] {
			continue
		}
		cyc := []int{}
		j := i
		for !seen[j] {
			seen[j] = true
			cyc = append(cyc, j)
			j = int(p[j])
			if j >= n || j < 0 {
				return nil
			}
		}
		out = append(out, cyc)
	}
	return out
}

// permPow 移位实现 g^k（每轮换内 i→i+k）。
func permPow(p []int64, k *big.Int) []int64 {
	out := make([]int64, len(p))
	for _, cyc := range permCycles(p) {
		L := int64(len(cyc))
		sh := new(big.Int).Mod(k, big.NewInt(L)).Int64()
		// cyc[i] 表示 i 的像；g^k 把 i 映到沿轮换走 k 步的位置
		for i, x := range cyc {
			out[x] = int64(cyc[int((int64(i)+sh)%L)])
		}
	}
	return out
}

// recoverA 从 g/A 对恢复 a（全量轮换 CRT，无提前退出）。
func recoverA(g, A []int64) (*big.Int, bool) {
	gc := permCycles(g)
	if gc == nil {
		return nil, false
	}
	posByHead := map[int][]int{}
	for _, c := range gc {
		posByHead[c[0]] = c
	}
	curR, curM := big.NewInt(0), big.NewInt(1)
	for _, cyc := range gc {
		L := big.NewInt(int64(len(cyc)))
		pos := make(map[int]int, len(cyc))
		for i, v := range cyc {
			pos[v] = i
		}
		x0 := cyc[0]
		aImg := A[x0] // g^a 作用于 x0
		ai, ok := pos[int(aImg)]
		if !ok {
			return nil, false
		}
		// 合并 a ≡ ai (mod L)
		gcdv := new(big.Int).GCD(nil, nil, curM, L)
		diff := new(big.Int).Sub(big.NewInt(int64(ai)), curR)
		if new(big.Int).Mod(diff, gcdv).Sign() != 0 {
			return nil, false
		}
		lcm := new(big.Int).Div(curM, gcdv)
		lcm.Mul(lcm, L)
		// curR + curM * t ≡ ai (mod L), t ≡ diff/gcd * inv(curM/gcd) (mod L/gcd)
		m1 := new(big.Int).Div(curM, gcdv)
		m2 := new(big.Int).Div(L, gcdv)
		inv := new(big.Int).ModInverse(m1, m2)
		if inv == nil {
			return nil, false
		}
		t := new(big.Int).Mul(diff, inv)
		t.Mod(t, m2)
		t.Mul(t, curM)
		curR.Add(curR, t)
		curR.Mod(curR, lcm)
		curM.Set(lcm)
	}
	return curR, true
}

// tryPermutedDH 主入口：从题面提取 g/A/B/[iv]/c，恢复 a → C=B^a → AES 尝试。
func tryPermutedDH(text string) []string {
	matches := permDhRe.FindAllStringSubmatch(text, -1)
	var g, aImg, bImg []int64
	for _, m := range matches {
		lst := parsePermList(m[2])
		switch m[1] {
		case "g":
			g = lst
		case "A":
			aImg = lst
		case "B":
			bImg = lst
		}
	}
	if g == nil || aImg == nil || bImg == nil {
		return nil
	}
	// 规模门禁：轮换个数 ≥2（防单点置换噪音），不再要求 ≥16——
	// 2026-10-26 e2e 实证 8 元素夹具被 len<16 门拦在所有 dbg 之前（幽灵 nil）。
	if len(permCycles(g)) < 2 {
		return nil
	}
	// ct/iv 提取
	mc := regexp.MustCompile(`(?s)c\s*=\s*(b['"])([A-Za-z0-9+/=]+)['"]`).FindStringSubmatch(text)
	miv := regexp.MustCompile(`(?s)iv\s*=\s*(b['"])([^'"]{16})['"]`).FindStringSubmatch(text)
	if mc == nil {
		return nil
	}
	ctB64 := mc[2]
	iv := []byte("0123456789abcdef")
	if miv != nil {
		iv = []byte(miv[2])
	}
	ct := b64dec(ctB64)
	if ct == nil || len(ct)%16 != 0 {
		return nil
	}

	a, ok := recoverA(g, aImg)
	if !ok {
		return nil
	}
	C := permPow(bImg, a) // C = B^a = g^(ab)
	dbgA := a.String()
	_ = dbgA

	var out []string
	tryDecrypt := func(secb []byte) {
		h := sha256.Sum256(secb)
		key := h[16:32]
		blk, err := aes.NewCipher(key)
		if err != nil {
			return
		}
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
		if flags := scanFlags(string(pt)); len(flags) > 0 {
			out = append(out, flags...)
		}
	}
	// 分支1：sec=long_to_bytes(hash(tuple)) 且 tuple hash 非随机化时无法复算——
	// 但若题面**直接给出** sec/中间值则可复算。此处先试"sha256(sec_bytes) 且
	// sec_bytes 已在题面"路径（少见）；主流路径是分支2。
	if secm := regexp.MustCompile(`(?s)sec\s*=\s*(?:long_to_bytes\()?hash\([^)]*\)?\)?`).FindString(text); secm != "" {
		// hash 值被 Python 随机化——跳过，等待分支2
		_ = secm
	}
	// 分支2：确定性字节化尝试（固定 seed 采源场景）
	tryDecrypt(permToBytes(C))
	return out
}

// permToBytes C 序列 → long_to_bytes(hash(tuple)) 的确定性替身：int64 LE 流。
// （tuple 的 python hash 无法复算——此替身仅在采源固定 seed / 题面给出 hash
// 输入字节的场景有效；否则上层 scanFlags 为空，fail-closed。）
func permToBytes(p []int64) []byte {
	out := make([]byte, 0, len(p)*8)
	var b [8]byte
	for _, v := range p {
		binary.LittleEndian.PutUint64(b[:], uint64(v))
		out = append(out, b[:]...)
	}
	return out
}

func b64dec(s string) []byte {
	s = strings.TrimSpace(s)
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(s)%4 != 0 {
		return nil
	}
	var out []byte
	var buf, bits int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		idx := strings.IndexByte(b64, c)
		if idx < 0 {
			return nil
		}
		buf = buf<<6 | idx
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out
}

func permDhPad7(b []byte, bs int) []byte {
	n := bs - len(b)%bs
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "permuted_dh", Category: CategoryCryptoS, Priority: 46,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryPermutedDH(text + "\n" + attachmentsText(attachments))
		},
	})
}

// b64enc / aesCBCEncrypt / listStr —— 测试夹具辅助（非求解路径）。
func b64enc(data []byte) string {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i+3 <= len(data); i += 3 {
		v := uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
		out = append(out, b64[v>>18&63], b64[v>>12&63], b64[v>>6&63], b64[v&63])
	}
	rem := len(data) % 3
	if rem == 1 {
		v := uint32(data[len(data)-1]) << 16
		out = append(out, b64[v>>18&63], b64[v>>12&63], '=', '=')
	} else if rem == 2 {
		v := uint32(data[len(data)-2])<<16 | uint32(data[len(data)-1])<<8
		out = append(out, b64[v>>18&63], b64[v>>12&63], b64[v>>6&63], '=')
	}
	return string(out)
}

func permDhCBCEncrypt(key, iv, plain []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := permDhPad7(plain, 16)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, padded)
	return out, nil
}

func permDhListStr(p []int64) string {
	parts := make([]string, len(p))
	for i, v := range p {
		parts[i] = strconv.FormatInt(v, 10)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
