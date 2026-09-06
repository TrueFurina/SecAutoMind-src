// presolve_classical.go —— 古典密码类求解器（凯撒/XOR/摩斯/维吉尼亚/栅栏/仿射/Brainfuck/DNA 等）
// 自 presolve.go 机械拆分（21 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// morseTable Morse 码映射。
var morseTable = map[string]string{
	".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e",
	"..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
	"-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o",
	".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
	"..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y",
	"--..": "z", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
	".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
	"-----": "0",
}

func guessVigenereKey(cipher string, keyLen int) string {
	cipher = strings.ToLower(cipher)
	var key []byte
	for i := 0; i < keyLen; i++ {
		freq := make(map[byte]int)
		for j := i; j < len(cipher); j += keyLen {
			if cipher[j] >= 'a' && cipher[j] <= 'z' {
				freq[cipher[j]]++
			}
		}
		maxFreq := 0
		maxChar := byte('a')
		for ch, f := range freq {
			if f > maxFreq {
				maxFreq = f
				maxChar = ch
			}
		}
		key = append(key, (maxChar-'e'+26)%26+'a')
	}
	return string(key)
}

func vigenereDecode(cipher, key string) string {
	cipher = strings.ToLower(cipher)
	key = strings.ToLower(key)
	var sb strings.Builder
	ki := 0
	for _, r := range cipher {
		if r >= 'a' && r <= 'z' {
			k := rune(key[ki%len(key)] - 'a')
			decoded := 'a' + (r-'a'-k+26)%26
			sb.WriteRune(decoded)
			ki++
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// tryKeyboardPath 检测键盘路径密码（如 QWERTY/ASDFG/ZXCVB 等键盘连续路径）。
func tryKeyboardPath(text string) []string {
	// 常见键盘路径模式
	keyboardPaths := []string{
		"qwerty", "asdfgh", "zxcvbn", "qazwsx", "edcrfv",
		"qweasdzxc", "1234567890", "qwertyuiop",
		"!@#$%^&*()", "zxcvbnm", "asdfghjkl",
	}
	lower := strings.ToLower(strings.TrimSpace(text))
	for _, path := range keyboardPaths {
		if strings.Contains(lower, path) {
			if flags := scanFlags(lower); len(flags) > 0 {
				return flags
			}
			return []string{"检测到键盘路径模式: " + path}
		}
	}
	return nil
}

// tryBacon 检测培根密码（A/B 二元编码）。
func tryBacon(text string) []string {
	clean := strings.TrimSpace(text)
	// 培根密码特征：仅含 a/b（大小写可混），长度为 5 的倍数
	baconRe := regexp.MustCompile(`^[abAB\s]+$`)
	if !baconRe.MatchString(clean) || len(clean) < 10 {
		return nil
	}
	// 移除空格，检查长度
	clean = strings.ReplaceAll(strings.ToLower(clean), " ", "")
	if len(clean)%5 != 0 {
		return nil
	}
	// 培根字典（26 字母）
	baconDict := map[string]string{
		"aaaaa": "a", "aaaab": "b", "aaaba": "c", "aaabb": "d", "aabaa": "e",
		"aabab": "f", "aabba": "g", "aabbb": "h", "abaaa": "i", "abaab": "j",
		"ababa": "k", "ababb": "l", "abbaa": "m", "abbab": "n", "abbba": "o",
		"abbbb": "p", "baaaa": "q", "baaab": "r", "baaba": "s", "baabb": "t",
		"babaa": "u", "babab": "v", "babba": "w", "babbb": "x", "bbaaa": "y",
		"bbaab": "z",
	}
	var decoded strings.Builder
	for i := 0; i+5 <= len(clean); i += 5 {
		chunk := clean[i : i+5]
		if ch, ok := baconDict[chunk]; ok {
			decoded.WriteString(ch)
		} else {
			decoded.WriteString("?")
		}
	}
	result := decoded.String()
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 {
		return []string{"培根解码: " + result}
	}
	return nil
}

// tryRailFence 检测栅栏密码（栏数 2-8 暴力）。
func tryRailFence(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 6 || len(clean) > 500 {
		return nil
	}
	// 仅对字母文本尝试
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	if !alphaRe.MatchString(clean) {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	for rails := 2; rails <= 8; rails++ {
		decoded := railFenceDecode(clean, rails)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

func railFenceDecode(cipher string, rails int) string {
	n := len(cipher)
	if rails <= 1 || rails >= n {
		return cipher
	}
	// 计算每行字符数
	pattern := make([]int, n)
	cycle := 2 * (rails - 1)
	for i := 0; i < n; i++ {
		pos := i % cycle
		if pos < rails {
			pattern[i] = pos
		} else {
			pattern[i] = cycle - pos
		}
	}
	// 按行收集
	rows := make([][]byte, rails)
	rowCounts := make([]int, rails)
	for _, r := range pattern {
		rowCounts[r]++
	}
	for i := range rows {
		rows[i] = make([]byte, 0, rowCounts[i])
	}
	// 按行填充密文
	idx := 0
	for r := 0; r < rails; r++ {
		for i := 0; i < n; i++ {
			if pattern[i] == r {
				rows[r] = append(rows[r], cipher[idx])
				idx++
			}
		}
	}
	// 按 zigzag 顺序还原
	result := make([]byte, n)
	rowIdx := make([]int, rails)
	for i := 0; i < n; i++ {
		r := pattern[i]
		result[i] = rows[r][rowIdx[r]]
		rowIdx[r]++
	}
	return string(result)
}

// tryAffine 检测仿射密码（E(x) = (ax + b) mod 26，暴力 a/b 组合）。
func tryAffine(text string) []string {
	clean := strings.TrimSpace(text)
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	if !alphaRe.MatchString(clean) || len(clean) < 6 {
		return nil
	}
	// a 必须与 26 互质
	validA := []int{1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}
	for _, a := range validA {
		for b := 0; b < 26; b++ {
			decoded := affineDecode(clean, a, b)
			if flags := scanFlags(decoded); len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}

func affineDecode(cipher string, a, b int) string {
	// a 的模逆
	aInv := 0
	for i := 0; i < 26; i++ {
		if (a*i)%26 == 1 {
			aInv = i
			break
		}
	}
	var sb strings.Builder
	for _, r := range cipher {
		if r >= 'a' && r <= 'z' {
			x := int(r - 'a')
			decoded := (aInv * (x - b + 26)) % 26
			sb.WriteRune(rune(decoded) + 'a')
		} else if r >= 'A' && r <= 'Z' {
			x := int(r - 'A')
			decoded := (aInv * (x - b + 26)) % 26
			sb.WriteRune(rune(decoded) + 'A')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// tryMorseVariant 检测 Morse 码变体格式（·/- 格式、长空格分隔等）。
func tryMorseVariant(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 10 {
		return nil
	}
	// 变体格式：使用 · 和 - 而非 . 和 -
	dotDashRe := regexp.MustCompile(`^[·\-\s/]+$`)
	if dotDashRe.MatchString(clean) {
		// 转换为标准格式后解码
		std := strings.ReplaceAll(clean, "·", ".")
		std = strings.ReplaceAll(std, "—", "--")
		std = strings.ReplaceAll(std, "−", "-")
		return tryMorse(std)
	}
	// 数字格式：0/1 编码（1=点, 0=划）
	binRe := regexp.MustCompile(`^[01\s/]+$`)
	if binRe.MatchString(clean) && len(clean) >= 10 {
		std := strings.ReplaceAll(clean, "1", ".")
		std = strings.ReplaceAll(std, "0", "-")
		std = strings.ReplaceAll(std, " ", " ")
		return tryMorse(std)
	}
	return nil
}

// tryBrainfuck 解释 Brainfuck 代码并提取 flag。
func tryBrainfuck(text string) []string {
	clean := strings.TrimSpace(text)
	// Brainfuck 仅含 8 种指令字符
	bfRe := regexp.MustCompile(`^[><+\-.,\[\]\s]+$`)
	if !bfRe.MatchString(clean) || len(clean) < 20 {
		return nil
	}
	// 简易解释器（最多执行 10000 步防死循环）
	tape := make([]byte, 3000)
	ptr := 0
	var output strings.Builder
	steps := 0
	code := clean
	codeIdx := 0
	bracketMap := buildBracketMap(code)

	for codeIdx < len(code) && steps < 10000 {
		steps++
		switch code[codeIdx] {
		case '>':
			ptr++
			if ptr >= len(tape) {
				ptr = len(tape) - 1
			}
		case '<':
			ptr--
			if ptr < 0 {
				ptr = 0
			}
		case '+':
			tape[ptr]++
		case '-':
			tape[ptr]--
		case '.':
			output.WriteByte(tape[ptr])
		case '[':
			if tape[ptr] == 0 {
				if end, ok := bracketMap[codeIdx]; ok {
					codeIdx = end
				}
			}
		case ']':
			if tape[ptr] != 0 {
				if start, ok := bracketMap[codeIdx]; ok {
					codeIdx = start
				}
			}
		}
		codeIdx++
	}
	result := output.String()
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 && isPrintableRatio(result) > 0.7 {
		return []string{"Brainfuck解码: " + result[:minInt(100, len(result))]}
	}
	return nil
}

// tryOok 检测 Ook! 语言（Brainfuck 的变体，用"Ook."等词）。
func tryOok(text string) []string {
	clean := strings.TrimSpace(text)
	// Ook 特征：连续的 "Ook" 词
	ookRe := regexp.MustCompile(`(?i)ook[.?!]`)
	matches := ookRe.FindAllString(clean, -1)
	if len(matches) < 8 {
		return nil
	}
	// 转换 Ook → Brainfuck
	bf := ookToBrainfuck(clean)
	if bf == "" {
		return nil
	}
	return tryBrainfuck(bf)
}

// ookToBrainfuck 将 Ook! 代码转换为 Brainfuck。
func ookToBrainfuck(ook string) string {
	re := regexp.MustCompile(`(?i)(ook)\s*([.?!])`)
	matches := re.FindAllStringSubmatch(ook, -1)
	if len(matches) < 2 {
		return ""
	}
	var bf strings.Builder
	for i := 0; i+1 < len(matches); i += 2 {
		pair := matches[i][2] + matches[i+1][2]
		switch pair {
		case "..":
			bf.WriteByte('+')
		case "!!":
			bf.WriteByte('-')
		case ".!":
			bf.WriteByte('>')
		case "!.":
			bf.WriteByte('<')
		case "!?":
			bf.WriteByte('[')
		case "?!":
			bf.WriteByte(']')
		case "?.":
			bf.WriteByte('.')
		case "??":
			bf.WriteByte(',')
		}
	}
	return bf.String()
}

// tryRailFenceVariant 栅栏密码变体（W 形 / 倒序 / 不同偏移）。
func tryRailFenceVariant(text string) []string {
	clean := strings.TrimSpace(text)
	alphaRe := regexp.MustCompile(`^[a-zA-Z\s]+$`)
	if !alphaRe.MatchString(clean) || len(clean) < 8 {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	// 标准栅栏（2-8 栏）
	for rails := 2; rails <= 8; rails++ {
		decoded := railFenceDecode(clean, rails)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	// W 形栅栏（从中间开始）
	for rails := 3; rails <= 6; rails++ {
		decoded := railFenceDecodeW(clean, rails)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// railFenceDecodeW W 形栅栏解码（从中间栏开始）。
func railFenceDecodeW(cipher string, rails int) string {
	n := len(cipher)
	if rails <= 1 || rails >= n {
		return cipher
	}
	// 构建 W 形模式
	rows := make([][]byte, rails)
	cycle := 2 * (rails - 1)
	for i := 0; i < n; i++ {
		pos := i % cycle
		var row int
		if pos < rails {
			row = pos
		} else {
			row = cycle - pos
		}
		rows[row] = append(rows[row], cipher[i])
	}
	// 还原
	result := make([]byte, n)
	idx := 0
	for r := 0; r < rails; r++ {
		for _, b := range rows[r] {
			result[idx] = b
			idx++
		}
	}
	return string(result)
}

// tryVigenereAutoKey 维吉尼亚自动密钥恢复（利用已知明文前缀恢复密钥）。
func tryVigenereAutoKey(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 10 {
		return nil
	}
	// 常见明文前缀（flag/Crypto/CTF等）
	prefixes := []string{"flag{", "FLAG{", "ctf{", "CTF{", "crypto{", "mctf{"}
	for _, prefix := range prefixes {
		if len(clean) < len(prefix) {
			continue
		}
		// 从密文和已知明文恢复密钥
		key := recoverVigenereKey(clean, prefix)
		if key == "" {
			continue
		}
		// 用恢复的密钥解密全文
		decoded := vigenereDecode(clean, key)
		if flags := scanFlags(decoded); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// recoverVigenereKey 从已知明文前缀恢复维吉尼亚密钥。
func recoverVigenereKey(cipher, knownPlain string) string {
	if len(cipher) < len(knownPlain) {
		return ""
	}
	var key []byte
	for i := 0; i < len(knownPlain); i++ {
		c := byte(0)
		if cipher[i] >= 'a' && cipher[i] <= 'z' {
			c = cipher[i]
		} else if cipher[i] >= 'A' && cipher[i] <= 'Z' {
			c = cipher[i] + 32 // 转小写
		} else {
			continue
		}
		p := byte(0)
		if knownPlain[i] >= 'a' && knownPlain[i] <= 'z' {
			p = knownPlain[i]
		} else if knownPlain[i] >= 'A' && knownPlain[i] <= 'Z' {
			p = knownPlain[i] + 32
		} else {
			continue
		}
		k := (c - p + 26) % 26
		key = append(key, k+'a')
	}
	if len(key) == 0 {
		return ""
	}
	return string(key)
}

// tryXORMultiByte 多字节 XOR / 重复密钥 XOR 检测。
func tryXORMultiByte(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	xorKeywords := []struct {
		keyword string
		hint    string
	}{
		{"multi-byte xor", "多字节 XOR 加密"},
		{"repeating key xor", "重复密钥 XOR"},
		{"fixed xor", "固定密钥 XOR"},
		{"single-byte xor", "单字节 XOR"},
		{"known plaintext", "已知明文攻击"},
		{"hamming distance", "汉明距离（密钥长度猜测）"},
		{"kasiski", "Kasiski 测试（密钥长度）"},
		{"index of coincidence", "重合指数"},
		{"ic ", "重合指数"},
		{"crib dragging", "Crib Dragging 已知明文攻击"},
		{"xor ", "XOR 运算"},
	}
	for _, kw := range xorKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"XOR攻击: " + kw.hint}
		}
	}
	// 检测 hex 串疑似 XOR 密文（重复模式）
	hexRe := regexp.MustCompile(`[0-9a-fA-F]{16,}`)
	for _, m := range hexRe.FindAllString(fullText, -1) {
		data, err := hex.DecodeString(m)
		if err != nil || len(data) < 8 {
			continue
		}
		// 检测重复 4 字节块（重复密钥特征）
		blocks := make(map[string]int)
		for i := 0; i+4 <= len(data); i += 4 {
			block := string(data[i : i+4])
			blocks[block]++
		}
		for _, count := range blocks {
			if count >= 3 {
				return []string{"XOR 重复密钥检测：hex 串中发现 " + fmt.Sprintf("%d", count) + " 个重复 4 字节块"}
			}
		}
	}
	return nil
}

// tryDNACoding 检测 DNA 编码密码（A/T/C/G 四字母编码）。
func tryDNACoding(text string) []string {
	clean := strings.TrimSpace(text)
	if len(clean) < 8 {
		return nil
	}
	// DNA 编码特征：仅含 A/T/C/G 四个字符，长度为偶数
	dnaRe := regexp.MustCompile(`^[ATCG\s]+$`)
	if !dnaRe.MatchString(clean) {
		return nil
	}
	clean = strings.ReplaceAll(clean, " ", "")
	if len(clean)%2 != 0 || len(clean) < 4 {
		return nil
	}
	// DNA 编码映射（常见变体）
	dnaMap := map[string]string{
		"AA": "00", "AC": "01", "AT": "10", "AG": "11",
		"CA": "00", "CC": "01", "CT": "10", "CG": "11",
		"TA": "00", "TC": "01", "TT": "10", "TG": "11",
		"GA": "00", "GC": "01", "GT": "10", "GG": "11",
	}
	var binary strings.Builder
	for i := 0; i+1 < len(clean); i += 2 {
		pair := clean[i : i+2]
		if bits, ok := dnaMap[pair]; ok {
			binary.WriteString(bits)
		}
	}
	// 二进制转 ASCII
	result := binaryToASCII(binary.String())
	if flags := scanFlags(result); len(flags) > 0 {
		return flags
	}
	if len(result) > 3 && isPrintableRatio(result) > 0.8 {
		return []string{"DNA解码: " + result}
	}
	return nil
}

// tryBraille 检测盲文编码（六点阵列模式）。
func tryBraille(text string) []string {
	clean := strings.TrimSpace(text)
	// 盲文特征：含 Unicode 盲文字符（U+2800 到 U+28FF）
	for _, r := range clean {
		if r >= 0x2800 && r <= 0x28FF {
			return []string{"盲文编码: 检测到 Unicode 盲文字符（U+2800-U+28FF），可用盲文解码器还原"}
		}
	}
	// 数字格式盲文（六点阵列用数字表示）
	brailleRe := regexp.MustCompile(`^[0-6\s/\-]{10,}$`)
	if brailleRe.MatchString(clean) && len(clean) >= 10 {
		return []string{"盲文数字编码: 检测到疑似盲文六点阵列数字表示"}
	}
	return nil
}

// tryBarcode 检测条形码/二维码特征。
func tryBarcode(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	barcodeKeywords := []struct {
		keyword string
		hint    string
	}{
		{"qr code", "二维码（QR Code）"},
		{"barcode", "条形码"},
		{"ean-13", "EAN-13 条形码"},
		{"ean-8", "EAN-8 条形码"},
		{"upc-a", "UPC-A 条形码"},
		{"code 128", "Code 128 条形码"},
		{"code 39", "Code 39 条形码"},
		{"data matrix", "Data Matrix 二维码"},
		{"aztec", "Aztec 二维码"},
		{"pdf417", "PDF417 二维码"},
		{"zxing", "ZXing 二维码识别库"},
		{"qrcode", "二维码"},
	}
	for _, kw := range barcodeKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"条码特征: " + kw.hint}
		}
	}
	return nil
}
