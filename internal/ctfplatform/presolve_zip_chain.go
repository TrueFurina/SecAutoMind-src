package ctfplatform

// presolve_zip_chain.go —— 多层嵌套 zip 文件名链解码
// （xhlj_legacy skills/zip_filename_chain_decode.py Go 化，刀锋账本 #8）。
//
// 场景：N 层嵌套 zip，每层一个 zip，最终 flag.txt（可能是陷阱）；真实 flag 藏在
// **文件名链的编码**里（reversed/forward × base32/64/hex/58/62/36/morse）。
// 🔴 10663 关键坑：文件名链须**从尾到头**拼接再解码；末层内容可能是陷阱。
//
// 范围（诚实口径）：Go 侧覆盖**未加密**嵌套链 + 多解码器 + flag 形态把关；
// 加密条目爆破分支（5/6 位数字+词表）不在 Go 侧——archive/zip 无解密支持，
// 该形态由 python 兜底通道覆盖（runner.py 同 skill）。注册表路径只回
// flag 形态命中（不回裸可读文本，防外部尺假阳性——外部尺教训）。

import (
	"archive/zip"
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"regexp"
	"strings"
)


var zcFlagRe = regexp.MustCompile(`(?i)(?:DASCTF|flag|ctf)\{[^}\s]{4,}\}`)

var zcMorse = map[string]string{
	".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
	"--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
	"--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
	"...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
	"-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
	"...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
	"---..": "8", "----.": "9",
}

func zcB32(s string) ([]byte, bool) {
	pad := (8 - len(s)%8) % 8
	out, err := base32.StdEncoding.DecodeString(strings.ToUpper(s) + strings.Repeat("=", pad))
	return out, err == nil && len(out) > 0
}

func zcB64(s string) ([]byte, bool) {
	pad := (4 - len(s)%4) % 4
	out, err := base64.StdEncoding.DecodeString(s + strings.Repeat("=", pad))
	return out, err == nil && len(out) > 0
}

func zcHex(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		return nil, false
	}
	out, err := hex.DecodeString(s)
	return out, err == nil && len(out) > 0
}

// zcBNDecode 任意进制（base58/62/36 共用大整数路线）。
func zcBNDecode(s string, base int, alphabet string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	n := new(big.Int)
	b := new(big.Int).SetInt64(int64(base))
	for _, c := range s {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return nil, false
		}
		n.Mul(n, b)
		n.Add(n, big.NewInt(int64(idx)))
	}
	if n.Sign() == 0 {
		return nil, false
	}
	return n.Bytes(), true
}

const zcB58Alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const zcB62Alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func zcMorseDecode(s string) string {
	var sb strings.Builder
	for _, tok := range strings.Fields(strings.TrimSpace(s)) {
		sb.WriteString(zcMorse[tok])
	}
	return sb.String()
}

// zcTryDecoders 尝试多编码，返回 (名称, 解码字节) 中能解出非空者。
func zcTryDecoders(s string) []struct {
	name string
	data []byte
} {
	type pair = struct {
		name string
		data []byte
	}
	var out []pair
	if b, ok := zcB32(s); ok {
		out = append(out, pair{"base32", b})
	}
	if b, ok := zcB64(s); ok {
		out = append(out, pair{"base64", b})
	}
	if b, ok := zcHex(s); ok {
		out = append(out, pair{"hex", b})
	}
	if b, ok := zcBNDecode(s, 58, zcB58Alpha); ok {
		out = append(out, pair{"base58", b})
	}
	if b, ok := zcBNDecode(s, 62, zcB62Alpha); ok {
		out = append(out, pair{"base62", b})
	}
	if b, ok := zcBNDecode(s, 36, "0123456789abcdefghijklmnopqrstuvwxyz"); ok {
		out = append(out, pair{"base36", b})
	}
	if txt := zcMorseDecode(s); txt != "" {
		out = append(out, pair{"morse", []byte(txt)})
	}
	return out
}

func zcIsReadable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 32 && c < 127 || c == 10 || c == 13 {
			printable++
		}
	}
	return printable*100 > 85*len(b)
}

// zcWalk 递归走嵌套 zip，返回文件名链 + 末层 flag 命中。
// 加密条目 → 返回 encrypted=true（Go 侧不支持解密，python 兜底域）。
func zcWalk(data []byte, maxLayers int) (chain []string, flags []string, encrypted bool, layers int) {
	cur := data
	for layer := 0; layer < maxLayers; layer++ {
		zr, err := zip.NewReader(bytes.NewReader(cur), int64(len(cur)))
		if err != nil {
			return chain, flags, encrypted, layer
		}
		enc := false
		for _, f := range zr.File {
			if f.Flags&0x1 != 0 {
				enc = true
			}
		}
		if enc {
			// 加密条目：Go 侧 archive/zip 不支持解密——python 兜底域
			encrypted = true
			return chain, flags, encrypted, layer + 1
		}
		var zipNames []string
		for _, f := range zr.File {
			if strings.HasSuffix(strings.ToLower(f.Name), ".zip") {
				zipNames = append(zipNames, f.Name)
			}
		}
		if len(zipNames) == 0 {
			// 末层：扫全部条目内容找 flag
			for _, f := range zr.File {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(rc)
				rc.Close()
				if m := zcFlagRe.FindString(buf.String()); m != "" {
					flags = append(flags, m)
				}
			}
			return chain, flags, encrypted, layer + 1
		}
		nxt := zipNames[0]
		chain = append(chain, strings.TrimSuffix(nxt, ".zip"))
		var nested *zip.File
		for _, cand := range zr.File {
			if strings.EqualFold(cand.Name, nxt) {
				nested = cand
				break
			}
		}
		if nested == nil {
			return chain, flags, encrypted, layer + 1
		}
		rc, err := nested.Open()
		if err != nil {
			return chain, flags, encrypted, layer + 1
		}
		next := new(bytes.Buffer)
		_, _ = next.ReadFrom(rc)
		rc.Close()
		cur = next.Bytes()
		layers = layer + 1
	}
	return chain, flags, encrypted, maxLayers
}

// solveZipChain 主解码：链过滤（去目录结构名/flag.zip 名）→ reversed+forward ×
// 多解码器 → flag 形态匹配 / 可读文本。
func zcChainSolve(data []byte, maxLayers int) []string {
	if maxLayers <= 0 {
		maxLayers = 200
	}
	chain, flags, encrypted, _ := zcWalk(data, maxLayers)
	var out []string
	seen := map[string]bool{}
	for _, f := range flags {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	codeChain := make([]string, 0, len(chain))
	for _, c := range chain {
		if !strings.ContainsAny(c, "/\\") && strings.ToLower(c) != "flag" && strings.ToLower(c) != "flag.txt" {
			codeChain = append(codeChain, c)
		}
	}
	if len(codeChain) == 0 || encrypted {
		return out
	}
	// 🔴 10663 关键坑：从尾到头拼接（完整链含单字符段，不过滤长度）
	for _, src := range []string{
		strings.Join(reverseStrings(codeChain), ""),
		strings.Join(codeChain, ""),
	} {
		for _, d := range zcTryDecoders(src) {
			txt := string(d.data)
			if m := zcFlagRe.FindString(txt); m != "" && !seen[m] {
				seen[m] = true
				out = append(out, m)
			} else if zcIsReadable(d.data) {
				t := strings.TrimSpace(txt)
				if t != "" && !seen[t] {
					seen[t] = true
					out = append(out, t)
				}
			}
		}
	}
	return out
}

func reverseStrings(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[len(ss)-1-i] = s
	}
	return out
}

// tryZipChainDecode 注册表入口：ZIP 触发门（真解码器；与 forensics 的关键词提示检测器互补）。
func tryZipChainDecode(text string, attachments map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range attachments {
		if len(raw) < 4 || !bytes.HasPrefix([]byte(raw), []byte("PK\x03\x04")) {
			continue
		}
		for _, f := range zcChainSolve([]byte(raw), 200) {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}
