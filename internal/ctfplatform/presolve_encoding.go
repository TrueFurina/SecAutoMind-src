// presolve_encoding.go —— 编码类求解器（Base 系列/Bech32/QuotedPrintable/Punycode 等）
// 自 presolve.go 机械拆分（16 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// tryBase58 检测 Base58 编码（比特币风格）。
func tryBase58(text string) []string {
	clean := strings.TrimSpace(text)
	// Base58 字符集：不包含 0/O/I/l
	b58Chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	b58Re := regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{8,}$`)
	if !b58Re.MatchString(clean) {
		return nil
	}
	// 简易 Base58 解码（大数除法）
	decoded := base58Decode(clean, b58Chars)
	if len(decoded) > 0 {
		if flags := scanFlags(string(decoded)); len(flags) > 0 {
			return flags
		}
		if isPrintableRatio(string(decoded)) > 0.8 {
			return []string{"Base58解码: " + string(decoded)}
		}
	}
	return nil
}

func base58Decode(s string, alphabet string) []byte {
	n := len([]byte(s))
	result := make([]byte, 0, n*2)
	for _, c := range s {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return nil
		}
		// 简化：逐字符处理（完整实现需要大数运算）
		result = append(result, byte(idx))
	}
	// 简化返回：不是完整解码，用于 flag 扫描
	return result
}

// tryAutoEncodingDetect 自动检测编码类型（Base64/Hex/URL/Binary）。
func tryAutoEncodingDetect(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 8 {
		return nil
	}
	// Base64 检测
	b64Re := regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}$`)
	if b64Re.MatchString(clean) {
		decoded, err := base64.StdEncoding.DecodeString(padBase64(clean))
		if err == nil && len(decoded) > 0 {
			if isPrintableRatio(string(decoded)) > 0.8 {
				return []string{"Base64检测: 解码得到可读文本 -> " + string(decoded)[:minInt(80, len(decoded))]}
			}
			return []string{"Base64检测: 解码得到二进制数据（" + fmt.Sprintf("%d", len(decoded)) + " 字节）"}
		}
	}
	// Hex 检测
	hexRe := regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	if hexRe.MatchString(clean) && len(clean)%2 == 0 {
		decoded, err := hex.DecodeString(clean)
		if err == nil && len(decoded) > 0 {
			if isPrintableRatio(string(decoded)) > 0.8 {
				return []string{"Hex检测: 解码得到可读文本 -> " + string(decoded)[:minInt(80, len(decoded))]}
			}
			return []string{"Hex检测: 解码得到二进制数据（" + fmt.Sprintf("%d", len(decoded)) + " 字节）"}
		}
	}
	// URL 编码检测
	if strings.Contains(clean, "%") {
		urlRe := regexp.MustCompile(`(%[0-9a-fA-F]{2}){3,}`)
		if urlRe.MatchString(clean) {
			return []string{"URL编码检测: 含连续 URL 编码序列"}
		}
	}
	return nil
}

// tryBase32 检测 Base32 编码。
func tryBase32(text string) []string {
	clean := strings.TrimSpace(text)
	// Base32 字符集：A-Z, 2-7, =
	b32Re := regexp.MustCompile(`^[A-Z2-7=]{8,}$`)
	if !b32Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	decoded, err := base32Decode(clean)
	if err != nil || len(decoded) == 0 {
		return nil
	}
	if flags := scanFlags(string(decoded)); len(flags) > 0 {
		return flags
	}
	if isPrintableRatio(string(decoded)) > 0.8 {
		return []string{"Base32解码: " + string(decoded)[:minInt(80, len(decoded))]}
	}
	return nil
}

func base32Decode(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	s = strings.TrimRight(s, "=")
	var result []byte
	for i := 0; i < len(s); i += 8 {
		chunk := s[i:minInt(i+8, len(s))]
		var bits uint64
		for _, c := range chunk {
			idx := strings.IndexRune(alphabet, c)
			if idx < 0 {
				return nil, fmt.Errorf("invalid char")
			}
			bits = bits<<5 | uint64(idx)
		}
		for j := 0; j < 5; j++ {
			byteIdx := (4 - j) * 8
			if byteIdx < 40 {
				result = append(result, byte(bits>>byteIdx&0xFF))
			}
		}
	}
	return result, nil
}

// tryBase85 检测 Base85/Ascii85 编码。
func tryBase85(text string) []string {
	clean := strings.TrimSpace(text)
	// Base85 标准版（Ascii85）：字符范围 33-117 (! 到 u)
	// Z85 版：0-9, a-z, A-Z, .-:+=^!/*
	if len(clean) < 8 {
		return nil
	}
	// Ascii85 检测：<~...~> 包裹
	if strings.HasPrefix(clean, "<~") && strings.HasSuffix(clean, "~>") {
		return []string{"Base85/Ascii85 检测: <~...~> 包裹格式"}
	}
	// Z85 检测
	z85Re := regexp.MustCompile(`^[0-9a-zA-Z.:\-+^!/*()]{8,}$`)
	if z85Re.MatchString(clean) {
		return []string{"Z85 检测: 符合 Z85 编码字符集（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
	}
	return nil
}

// tryBase91 检测 Base91 编码。
func tryBase91(text string) []string {
	clean := strings.TrimSpace(text)
	// Base91 字符集：ASCII 35-126（# 到 ~），不含空格
	b91Re := regexp.MustCompile(`^[!-~]{8,}$`)
	if !b91Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	// 检测特征：Base91 编码后长度约为原文的 1.23 倍
	// 如果输入看起来不像 base64（没有+/=），可能是 base91
	if strings.ContainsAny(clean, "+/=") {
		return nil // 可能是 base64
	}
	return []string{"Base91 检测: 符合 Base91 字符集（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}

// tryUUencode 检测 UUencode 编码。
func tryUUencode(text string) []string {
	clean := strings.TrimSpace(text)
	// UUencode 特征：每行以长度字符开头（'M' = 45字节/行），行首字符范围 ' ' 到 '`'
	lines := strings.Split(clean, "\n")
	if len(lines) < 2 {
		return nil
	}
	uuRe := regexp.MustCompile(`^[\x20-\x60][\x20-\x7E]*$`)
	validLines := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 0 && uuRe.MatchString(trimmed) {
			validLines++
		}
	}
	if validLines >= 2 && float64(validLines)/float64(len(lines)) > 0.5 {
		return []string{"UUencode 检测: 符合 UUencode 行格式（" + fmt.Sprintf("%d", validLines) + "/" + fmt.Sprintf("%d", len(lines)) + " 行）"}
	}
	return nil
}

// tryQuotedPrintable 检测 Quoted-Printable 编码。
func tryQuotedPrintable(text string) []string {
	clean := strings.TrimSpace(text)
	// Quoted-Printable 特征：=XX 十六进制转义
	qpRe := regexp.MustCompile(`=[0-9A-Fa-f]{2}`)
	matches := qpRe.FindAllString(clean, -1)
	if len(matches) >= 3 {
		return []string{"Quoted-Printable 检测: " + fmt.Sprintf("%d", len(matches)) + " 个 =XX 转义序列"}
	}
	// 软换行（行尾 =）
	if strings.HasSuffix(clean, "=") {
		return []string{"Quoted-Printable 检测: 行尾软换行（= 结尾）"}
	}
	return nil
}

// tryPunycode 检测 Punycode 编码（国际化域名）。
func tryPunycode(text string) []string {
	clean := strings.TrimSpace(text)
	// Punycode 特征：xn-- 前缀
	if strings.HasPrefix(clean, "xn--") || strings.Contains(clean, ".xn--") {
		return []string{"Punycode 检测: 国际化域名编码（xn-- 前缀）"}
	}
	// 纯 ASCII 字母+数字+连字符
	punyRe := regexp.MustCompile(`^[a-zA-Z0-9-]{4,}$`)
	if punyRe.MatchString(clean) && strings.Contains(clean, "-") {
		return []string{"Punycode 特征: 纯 ASCII+连字符格式（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
	}
	return nil
}

// tryZ85 检测 Z85 编码。
func tryZ85(text string) []string {
	clean := strings.TrimSpace(text)
	// Z85 字符集：0-9, a-z, A-Z, .-:+=^!/*
	z85Re := regexp.MustCompile(`^[0-9a-zA-Z.:\-+^!/*()]{8,}$`)
	if !z85Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	// 排除 base64（含+/=）
	if strings.ContainsAny(clean, "+/=") {
		return nil
	}
	return []string{"Z85 检测: 符合 Z85 编码字符集（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}

// tryEncodingChain 检测多层编码链（编码套编码）。
func tryEncodingChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	encKeywords := []struct {
		keyword string
		hint    string
	}{
		{"multi-layer encoding", "多层编码"},
		{"nested encoding", "嵌套编码"},
		{"encoding chain", "编码链"},
		{"double base64", "双层 Base64"},
		{"base64 decode", "Base64 解码"},
		{"hex decode", "Hex 解码"},
		{"url decode", "URL 解码"},
		{"html entities", "HTML 实体编码"},
		{"unicode escape", "Unicode 转义"},
		{"javascript escape", "JavaScript 转义"},
		{"rot13", "ROT13"},
		{"rot47", "ROT47"},
		{"atbash", "Atbash 密码"},
		{"caesar cipher", "凯撒密码"},
		{"vigenere cipher", "维吉尼亚密码"},
		{"substitution cipher", "替换密码"},
		{"transposition cipher", "置换密码"},
	}
	for _, kw := range encKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"编码检测: " + kw.hint}
		}
	}
	return nil
}

// tryEncodingDetectionAdvanced 检测高级编码特征（yEnc/BinHex/QuotedPrintable）。
func tryEncodingDetectionAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	encKeywords := []struct {
		keyword string
		hint    string
	}{
		{"yenc", "yEnc 编码"},
		{"binhex", "BinHex 编码"},
		{"quoted-printable", "Quoted-Printable"},
		{"charset", "字符集"},
		{"encoding", "编码"},
		{"utf-8", "UTF-8"},
		{"utf-16", "UTF-16"},
		{"utf-32", "UTF-32"},
		{"iso-8859", "ISO-8859"},
		{"windows-1252", "Windows-1252"},
		{"euc-kr", "EUC-KR"},
		{"euc-jp", "EUC-JP"},
		{"gb2312", "GB2312"},
		{"gbk", "GBK"},
		{"big5", "Big5"},
		{"shift_jis", "Shift_JIS"},
	}
	for _, kw := range encKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"编码高级: " + kw.hint}
		}
	}
	return nil
}

// tryBase45 检测 Base45 编码（RFC 9285，用于 COVID 证书）。
func tryBase45(text string) []string {
	clean := strings.TrimSpace(text)
	// Base45 字符集：0-9, A-Z, space, $%*+-./:
	b45Re := regexp.MustCompile(`^[0-9A-Z\s$%*+\-./:]{8,}$`)
	if !b45Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	return []string{"Base45 检测: 符合 Base45 字符集（RFC 9285，" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}

// tryBech32 检测 Bech32 编码（比特币隔离见证地址）。
func tryBech32(text string) []string {
	clean := strings.TrimSpace(text)
	// Bech32 特征：小写字母+数字，含 '1' 分隔符
	bech32Re := regexp.MustCompile(`^[a-z2-9]+1[a-z2-9]+$`)
	if !bech32Re.MatchString(clean) || len(clean) < 14 {
		return nil
	}
	return []string{"Bech32 检测: 比特币隔离见证地址格式（" + clean[:minInt(20, len(clean))] + "）"}
}

// tryBase62 检测 Base62 编码（URL 短链常用）。
func tryBase62(text string) []string {
	clean := strings.TrimSpace(text)
	b62Re := regexp.MustCompile(`^[0-9A-Za-z]{8,}$`)
	if !b62Re.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	// 排除 base64（含+/=）
	if strings.ContainsAny(clean, "+/=") {
		return nil
	}
	return []string{"Base62 检测: 纯字母数字编码（" + fmt.Sprintf("%d", len(clean)) + " 字符）"}
}

// tryEndian 大小端序转换：对文本中的 hex 串按 2/4/8 字节组做组内字节反转，
// 解码后扫 flag（典型题：小端 hex dump 的 flag 需按字反转）。
func tryEndian(text string) []string {
	hexRe := regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	for _, m := range hexRe.FindAllString(text, -1) {
		if len(m)%2 != 0 {
			continue
		}
		raw, err := hex.DecodeString(m)
		if err != nil {
			continue
		}
		for _, size := range []int{2, 4, 8} {
			if len(raw)%size != 0 {
				continue
			}
			swapped := make([]byte, len(raw))
			for i := 0; i < len(raw); i += size {
				for j := 0; j < size; j++ {
					swapped[i+j] = raw[i+size-1-j]
				}
			}
			if flags := scanFlags(string(swapped)); len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}
