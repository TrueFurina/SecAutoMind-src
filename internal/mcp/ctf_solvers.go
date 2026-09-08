package mcp

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// CTF 确定性求解器（第一批，纯 Go 标准库，零外部依赖）
//
// 背景：第一环节人机协同实战赛为客观判分（平台自动判分），CTF 类题目
// 需要"确定性优先"的快速求解能力 —— 参考西湖论剑 CTF-Agent 方法论：
// 在消耗任何 LLM token 之前先跑确定性求解器；命中即返回候选 flag。
//
// 设计纪律：
//   - 全部纯 Go 标准库实现，不引入外部二进制/脚本 → 保住"单文件分发"
//   - 每个工具 run(params) 同构：输入 content，输出 candidate_flags（含来源与置信度）
//   - 命中带 [presolve:<engine>] 标记，便于审计日志追踪

// 工具名（确定性求解器命名空间 ctf_*，避免与 90 个 YAML 工具冲突）
const (
	toolCTFFlagScan         = "ctf_flag_scan"
	toolCTFBase64AutoDecode = "ctf_base64_auto_decode"
	toolCTFCaesarBruteforce = "ctf_caesar_bruteforce"
	toolCTFXORSingleByte    = "ctf_xor_single_byte"
)

// flagRegex 宽松版：flag{...}/ctf{...} 或 ≥8 位 base64 串候选（flag_scan 找候选用）
var flagRegex = regexp.MustCompile(`(?i)(?:flag|ctf|key)\s*[=:：]?\s*\{([^}]{4,})\}|([A-Za-z0-9+/=_\-]{8,})`)

// strictFlagRegex 严格 flag 形态（flag{...}/ctf{...}/key=...）：解码链路"是否已还原真 flag"的终止判断
var strictFlagRegex = regexp.MustCompile(`(?i)(?:flag|ctf|key)\s*[=:：]?\s*\{([^}]{4,})\}`)

// RegisterCTFSolvers 注册 CTF 确定性求解工具到 MCP 服务器。
// 调用点：internal/app/app.go（与其他 registerXxxTools 并列，紧随 executor.RegisterTools 之后）。
func RegisterCTFSolvers(server *Server) {
	if server == nil {
		return
	}

	// 1) flag 正则扫描：全题型兜底（源码注释/HTML/输出文本里的明文 flag）
	server.RegisterTool(Tool{
		Name:             toolCTFFlagScan,
		Description:      "确定性扫描文本中的 flag（flag{...}/ctf{...} 等常见格式）。零 token 消耗，先于任何 LLM 推理执行。输入题目文本/工具输出，返回命中的候选 flag 列表。",
		ShortDescription: "正则扫描 flag 明文",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"content": map[string]interface{}{"type": "string", "description": "待扫描的文本内容（题目描述、工具输出、文件内容等）"},
			},
			"required": []string{"content"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*ToolResult, error) {
		content := stringArg(args, "content")
		if strings.TrimSpace(content) == "" {
			return textToolResult("content 为空", true), nil
		}
		matches := flagRegex.FindAllString(content, -1)
		if len(matches) == 0 {
			return textToolResult("未发现 flag 候选", false), nil
		}
		cands := make([]string, 0, len(matches))
		for _, m := range matches {
			cands = append(cands, strings.TrimSpace(m))
		}
		return textToolResult("[presolve:flag_scan] 命中候选: "+jsonString(cands), false), nil
	})

	// 2) 多层 base64/URL/hex 自动解码：crypto/misc 高频题型
	server.RegisterTool(Tool{
		Name:             toolCTFBase64AutoDecode,
		Description:      "对疑似多层编码的字符串自动循环解码（base64 标准/URL 安全/hex），直到不可再解或达到层数上限。零 token 消耗。输入编码串，返回各层解码结果与最终候选。",
		ShortDescription: "多层 base64/hex 自动解码",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"content": map[string]interface{}{"type": "string", "description": "疑似多层编码的字符串"},
			},
			"required": []string{"content"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*ToolResult, error) {
		s := strings.TrimSpace(stringArg(args, "content"))
		if s == "" {
			return textToolResult("content 为空", true), nil
		}
		layers := decodeLayers(s, 12)
		if len(layers) == 0 {
			return textToolResult("未识别为可解码内容", false), nil
		}
		return textToolResult("[presolve:base64_auto] 解码过程: "+jsonString(layers), false), nil
	})

	// 3) 凯撒移位爆破：古典密码
	server.RegisterTool(Tool{
		Name:             toolCTFCaesarBruteforce,
		Description:      "对疑似凯撒加密的英文字符串进行 26 位移暴力破解，输出可读性最高的候选（含可打印/空格比例启发）。零 token 消耗。输入密文，返回候选明文列表。",
		ShortDescription: "凯撒密码 26 位移爆破",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"content": map[string]interface{}{"type": "string", "description": "疑似凯撒加密的密文（仅处理字母，其余字符保留）"},
			},
			"required": []string{"content"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*ToolResult, error) {
		s := strings.TrimSpace(stringArg(args, "content"))
		if s == "" {
			return textToolResult("content 为空", true), nil
		}
		cands := caesarBruteforce(s)
		if len(cands) == 0 {
			return textToolResult("无可读候选", false), nil
		}
		return textToolResult("[presolve:caesar] 候选明文(按可读性排序): "+jsonString(cands), false), nil
	})

	// 4) 单字节 XOR 爆破：misc 高频
	server.RegisterTool(Tool{
		Name:             toolCTFXORSingleByte,
		Description:      "对疑似单字节 XOR 加密的字节序列进行 256 key 暴力破解，输出可读性评分最高的候选明文。输入支持 hex 串或普通文本。零 token 消耗。",
		ShortDescription: "单字节 XOR 爆破",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"content": map[string]interface{}{"type": "string", "description": "待破解内容：hex 字符串（如 1b3c2d…）或原始文本"},
			},
			"required": []string{"content"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*ToolResult, error) {
		s := strings.TrimSpace(stringArg(args, "content"))
		if s == "" {
			return textToolResult("content 为空", true), nil
		}
		data, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil || len(data) == 0 {
			// 不是 hex：把原文当字节
			data = []byte(s)
		}
		cands := xorSingleByteBruteforce(data)
		if len(cands) == 0 {
			return textToolResult("无可读候选", false), nil
		}
		return textToolResult("[presolve:xor_single] 候选明文(按可读性排序): "+jsonString(cands), false), nil
	})
	// 5) 哈希爆破：md5/sha1/sha256 常见弱口令（crypto 高频）
	server.RegisterTool(Tool{
		Name:             "ctf_hash_crack",
		Description:      "对常见哈希（md5 32位/sha1 40位/sha256 64位）爆破弱口令：内置常见口令词表 + 数字后缀组合。零 token 消耗。输入十六进制哈希，命中返回明文。",
		ShortDescription: "常见哈希弱口令爆破",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"content": map[string]interface{}{"type": "string", "description": "十六进制哈希值（md5/sha1/sha256）"},
			},
			"required": []string{"content"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*ToolResult, error) {
		s := strings.ToLower(strings.TrimSpace(stringArg(args, "content")))
		if s == "" {
			return textToolResult("content 为空", true), nil
		}
		plain, algo, ok := crackCommonHash(s)
		if !ok {
			return textToolResult("内置词表未命中（可尝试 wordlist 工具或在线破解）", false), nil
		}
		return textToolResult("[presolve:hash_crack] 命中 "+algo+" => 明文: "+plain, false), nil
	})

	// 6) RSA 费马分解：n 为相近素数乘积（crypto 经典题）
	server.RegisterTool(Tool{
		Name:             "ctf_rsa_fermat",
		Description:      "RSA 费马分解攻击：当模数 n 的两个素因子相近时，用费马分解求出 p/q，进而还原明文。零 token 消耗。输入 n（十进制）、e（十进制）、ciphertext（十六进制，可空——空则只输出 d/私钥）。",
		ShortDescription: "RSA 费马分解还原明文",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"n":      map[string]interface{}{"type": "string", "description": "模数 n（十进制）"},
				"e":      map[string]interface{}{"type": "string", "description": "公钥指数 e（十进制，默认 65537）"},
				"cipher": map[string]interface{}{"type": "string", "description": "密文（十六进制，可空）"},
			},
			"required": []string{"n"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*ToolResult, error) {
		nStr := strings.TrimSpace(stringArg(args, "n"))
		if nStr == "" {
			return textToolResult("n 为空", true), nil
		}
		eStr := strings.TrimSpace(stringArg(args, "e"))
		if eStr == "" {
			eStr = "65537"
		}
		cipherHex := strings.TrimSpace(stringArg(args, "cipher"))
		out, err := fermatAttack(nStr, eStr, cipherHex)
		if err != nil {
			return textToolResult("[presolve:rsa_fermat] "+err.Error(), false), nil
		}
		return textToolResult("[presolve:rsa_fermat] "+out, false), nil
	})

	// 7) RSA 共模攻击：同一明文同一模数 n、两组 (e1,c1) 且 gcd(e1,e2)=1
	server.RegisterTool(Tool{
		Name:             "ctf_rsa_common_modulus",
		Description:      "RSA 共模攻击：当同一明文 m 用同一模数 n、不同公钥指数 e1/e2 加密得到 c1/c2（gcd(e1,e2)=1）时，用扩展欧几里得还原明文。零 token 消耗。输入 n（十进制）、e1/e2（十进制）、c1/c2（十六进制）。",
		ShortDescription: "RSA 共模攻击还原明文",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"n":  map[string]interface{}{"type": "string", "description": "模数 n（十进制）"},
				"e1": map[string]interface{}{"type": "string", "description": "公钥指数 e1（十进制）"},
				"c1": map[string]interface{}{"type": "string", "description": "密文 c1（十六进制）"},
				"e2": map[string]interface{}{"type": "string", "description": "公钥指数 e2（十进制）"},
				"c2": map[string]interface{}{"type": "string", "description": "密文 c2（十六进制）"},
			},
			"required": []string{"n", "e1", "c1", "e2", "c2"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*ToolResult, error) {
		nStr := strings.TrimSpace(stringArg(args, "n"))
		e1Str := strings.TrimSpace(stringArg(args, "e1"))
		c1Hex := strings.TrimSpace(stringArg(args, "c1"))
		e2Str := strings.TrimSpace(stringArg(args, "e2"))
		c2Hex := strings.TrimSpace(stringArg(args, "c2"))
		if nStr == "" || e1Str == "" || c1Hex == "" || e2Str == "" || c2Hex == "" {
			return textToolResult("参数缺失：n/e1/c1/e2/c2 均必填", true), nil
		}
		out, err := commonModulusAttack(nStr, e1Str, c1Hex, e2Str, c2Hex)
		if err != nil {
			return textToolResult("[presolve:rsa_common_modulus] "+err.Error(), false), nil
		}
		return textToolResult("[presolve:rsa_common_modulus] "+out, false), nil
	})
}

// jsonString 将字符串列表序列化为紧凑 JSON（供模型阅读）
func jsonString(items []string) string {
	b, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// decodeLayers 逐层尝试 base64(标准/URL) 与 hex 解码，直到不可再解或层数上限。
// 返回每层结果字符串（含解码方式前缀），调用方用于候选 flag 判定。
func decodeLayers(s string, maxLayers int) []string {
	layers := make([]string, 0, maxLayers)
	cur := s
	for i := 0; i < maxLayers; i++ {
		decoded, method, ok := tryDecodeOne(cur)
		if !ok || decoded == cur {
			break
		}
		layers = append(layers, method+" => "+decoded)
		cur = decoded
		// 命中 flag 形态即停（后续层通常是噪声）
		if strictFlagRegex.MatchString(cur) {
			break
		}
	}
	return layers
}

// tryDecodeOne 尝试一种解码：URL-safe base64 > 标准 base64 > hex。
// 均失败时尝试 base64 去 padding 补全重试一次。
func tryDecodeOne(s string) (string, string, bool) {
	trimmed := strings.TrimSpace(s)
	// 标准 base64（要求有效 padding 或长度合法）
	if b, err := base64.StdEncoding.DecodeString(padBase64(trimmed)); err == nil {
		if out := string(b); isPrintableRatio(out) >= 0.85 || strings.Contains(out, "{") {
			return out, "b64", true
		}
	}
	if b, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		if out := string(b); isPrintableRatio(out) >= 0.85 || strings.Contains(out, "{") {
			return out, "b64url", true
		}
	}
	if b, err := hex.DecodeString(strings.ReplaceAll(trimmed, " ", "")); err == nil {
		if out := string(b); isPrintableRatio(out) >= 0.85 {
			return out, "hex", true
		}
	}
	return "", "", false
}

// padBase64 补全 base64 padding 到合法长度（部分题目省略 '='）。
// 先去除已有 '=' 再按数据长度补，避免对已含 padding 的串补过头。
func padBase64(s string) string {
	s = strings.TrimRight(s, "=")
	if m := len(s) % 4; m != 0 {
		return s + strings.Repeat("=", 4-m)
	}
	return s
}

// isPrintableRatio 返回可打印字符占比（0~1），用于判断"解码成功且是文本"
func isPrintableRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	printable := 0
	for _, r := range s {
		if (r >= 32 && r < 127) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return float64(printable) / float64(len(s))
}

// caesarBruteforce 26 位移爆破，按可读性排序返回 top 候选（无条件返回，宁可多给候选让上层判定）
func caesarBruteforce(cipher string) []string {
	type scored struct {
		shift int
		text  string
		score int
	}
	results := make([]scored, 0, 26)
	for shift := 1; shift <= 25; shift++ {
		var sb strings.Builder
		for _, r := range cipher {
			switch {
			case r >= 'a' && r <= 'z':
				sb.WriteRune('a' + (r-'a'+rune(shift))%26)
			case r >= 'A' && r <= 'Z':
				sb.WriteRune('A' + (r-'A'+rune(shift))%26)
			default:
				sb.WriteRune(r)
			}
		}
		text := sb.String()
		results = append(results, scored{shift: shift, text: text, score: readabilityScore(text)})
	}
	// 按可读性降序（插入排序，26 项规模足够）
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].score > results[j-1].score; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}
	// 无条件取 top3（带 shift 号），flag/关键词命中者上浮到首位
	cands := make([]string, 0, 3)
	for i, r := range results {
		s := r.text
		marker := ""
		for _, c := range []string{"flag", "ctf", "key", " the ", " is "} {
			if strings.Contains(strings.ToLower(s), c) {
				marker = " ★命中"
				break
			}
		}
		cands = append(cands, "shift="+strconv.Itoa(r.shift)+" | "+s+marker)
		if len(cands) >= 3 {
			break
		}
		_ = i
	}
	return cands
}

// readabilityScore 粗略可读性评分：空格数 + 常见字母频率
func readabilityScore(s string) int {
	score := 0
	lower := strings.ToLower(s)
	score += strings.Count(lower, " ") * 3
	for _, ch := range "etaoin shrdlu" {
		score += strings.Count(lower, string(ch))
	}
	return score
}

// xorSingleByteBruteforce 单字节 XOR：256 key 全试，无条件按可读性取 top3
func xorSingleByteBruteforce(data []byte) []string {
	type scored struct {
		key   byte
		text  string
		score int
	}
	results := make([]scored, 0, 256)
	for k := byte(0); k < 255; k++ {
		out := make([]byte, len(data))
		for i, b := range data {
			out[i] = b ^ k
		}
		text := string(out)
		results = append(results, scored{key: k, text: text, score: readabilityScore(text)})
	}
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].score > results[j-1].score; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}
	cands := make([]string, 0, 3)
	for _, r := range results {
		// 只保留可打印文本候选（二进制噪声无意义）
		if isPrintableRatio(r.text) < 0.85 {
			continue
		}
		cands = append(cands, "key=0x"+hex.EncodeToString([]byte{r.key})+" | "+r.text)
		if len(cands) >= 3 {
			break
		}
	}
	return cands
}

// commonPasswords 内置常见弱口令词表（CTF hash 题高频）
var commonPasswords = []string{
	"password", "123456", "12345678", "123456789", "qwerty", "admin",
	"admin123", "root", "root123", "toor", "ctf", "ctf2026", "flag",
	"passw0rd", "p@ssw0rd", "letmein", "welcome", "monkey", "dragon",
	"iloveyou", "secret", "secauto", "secautomind", "test", "test123",
	"user", "guest", "666666", "888888", "1qaz2wsx", "abc123",
}

// crackCommonHash 对 md5/sha1/sha256 hex 哈希爆破弱口令；命中返回 (明文, 算法, true)
func crackCommonHash(hashHex string) (string, string, bool) {
	hashHex = strings.ToLower(strings.TrimSpace(hashHex))
	if len(hashHex) == 0 {
		return "", "", false
	}
	// 按长度判断算法
	var algo string
	switch len(hashHex) {
	case 32:
		algo = "md5"
	case 40:
		algo = "sha1"
	case 64:
		algo = "sha256"
	default:
		return "", "", false
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", "", false
	}
	digest := func(data string) string {
		switch algo {
		case "md5":
			s := md5.Sum([]byte(data))
			return hex.EncodeToString(s[:])
		case "sha1":
			s := sha1.Sum([]byte(data))
			return hex.EncodeToString(s[:])
		case "sha256":
			s := sha256.Sum256([]byte(data))
			return hex.EncodeToString(s[:])
		}
		return ""
	}
	_ = hashBytes
	// 基础词表 + 常见数字/符号后缀组合
	candidates := make([]string, 0, len(commonPasswords)*4)
	for _, p := range commonPasswords {
		candidates = append(candidates, p)
		candidates = append(candidates, p+"123", p+"2026", p+"1")
	}
	seen := make(map[string]bool)
	for _, cand := range candidates {
		if seen[cand] {
			continue
		}
		seen[cand] = true
		if digest(cand) == hashHex {
			return cand, algo, true
		}
	}
	return "", algo, false
}

// fermatAttack RSA 费马分解：n=p*q 且 |p-q| 较小时还原 p/q/d，若有密文则还原明文
func fermatAttack(nStr, eStr, cipherHex string) (string, error) {
	n, ok := new(big.Int).SetString(nStr, 10)
	if !ok || n.Sign() <= 0 {
		return "", fmt.Errorf("无效 n")
	}
	e, ok := new(big.Int).SetString(eStr, 10)
	if !ok || e.Sign() <= 0 {
		return "", fmt.Errorf("无效 e")
	}
	// 费马分解：a = ceil(sqrt(n))，b² = a² - n，直到 b 为完全平方
	a := new(big.Int).Sqrt(n)
	if new(big.Int).Mul(a, a).Cmp(n) < 0 {
		a.Add(a, big.NewInt(1))
	}
	limit := new(big.Int).Set(a)
	limit.Add(limit, big.NewInt(1_000_000)) // 迭代上限，防止长时间盲跑
	p := new(big.Int)
	q := new(big.Int)
	found := false
	for a.Cmp(limit) <= 0 {
		a2 := new(big.Int).Mul(a, a)
		b2 := new(big.Int).Sub(a2, n)
		if b2.Sign() < 0 {
			a.Add(a, big.NewInt(1))
			continue
		}
		b := new(big.Int).Sqrt(b2)
		if new(big.Int).Mul(b, b).Cmp(b2) == 0 {
			// a² - b² = n → (a-b)(a+b) = n
			p.Sub(a, b)
			q.Add(a, b)
			if p.Sign() > 0 && q.Sign() > 0 && new(big.Int).Mul(p, q).Cmp(n) == 0 {
				found = true
				break
			}
		}
		a.Add(a, big.NewInt(1))
	}
	if !found {
		return "", fmt.Errorf("费马分解未命中（素因子差距过大？）")
	}
	// φ(n) = (p-1)(q-1)
	phi := new(big.Int).Mul(new(big.Int).Sub(new(big.Int).Set(p), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Set(q), big.NewInt(1)))
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return "", fmt.Errorf("e 与 φ(n) 不互质，无法求 d")
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("p=%s\nq=%s\nd=%s\n", p.String(), q.String(), d.String()))
	// 若有密文则解密
	if cipherHex != "" {
		cBytes, err := hex.DecodeString(strings.TrimSpace(cipherHex))
		if err != nil || len(cBytes) == 0 {
			return sb.String(), nil // 密文无效，仅返回私钥
		}
		c := new(big.Int).SetBytes(cBytes)
		m := new(big.Int).Exp(c, d, n)
		mBytes := m.Bytes()
		// 尝试作为 ASCII/UTF-8 输出
		printable := isPrintableRatio(string(mBytes))
		sb.WriteString(fmt.Sprintf("\n明文(hex): %s\n明文(文本): %q (可打印率 %.0f%%)\n",
			hex.EncodeToString(mBytes), string(mBytes), printable*100))
	}
	return sb.String(), nil
}

// egcd 扩展欧几里得：返回 (g, x, y) 使 ax + by = g = gcd(a, b)
func egcd(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if b.Sign() == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}
	g, x1, y1 := egcd(b, new(big.Int).Mod(a, b))
	q := new(big.Int).Div(a, b)
	x := new(big.Int).Sub(x1, new(big.Int).Mul(q, y1))
	y := y1
	return g, y, x
}

// commonModulusAttack RSA 共模攻击：同 n、两组 (e1,c1)/(e2,c2)，gcd(e1,e2)=1 时还原明文
func commonModulusAttack(nStr, e1Str, c1Hex, e2Str, c2Hex string) (string, error) {
	n, ok := new(big.Int).SetString(nStr, 10)
	if !ok || n.Sign() <= 0 {
		return "", fmt.Errorf("无效 n")
	}
	e1, ok1 := new(big.Int).SetString(e1Str, 10)
	e2, ok2 := new(big.Int).SetString(e2Str, 10)
	if !ok1 || !ok2 || e1.Sign() <= 0 || e2.Sign() <= 0 {
		return "", fmt.Errorf("无效 e1/e2")
	}
	c1Bytes, err1 := hex.DecodeString(c1Hex)
	c2Bytes, err2 := hex.DecodeString(c2Hex)
	if err1 != nil || err2 != nil || len(c1Bytes) == 0 || len(c2Bytes) == 0 {
		return "", fmt.Errorf("无效 c1/c2（需十六进制）")
	}
	c1 := new(big.Int).SetBytes(c1Bytes)
	c2 := new(big.Int).SetBytes(c2Bytes)

	// 扩展欧几里得：s*e1 + t*e2 = gcd(e1,e2)
	g, s, t := egcd(e1, e2)
	if g.Cmp(big.NewInt(1)) != 0 {
		return "", fmt.Errorf("gcd(e1,e2)=%s ≠ 1，共模攻击不适用", g.String())
	}
	// 若 s<0 则 c1^s = (c1^-1)^(-s)，需模逆
	c1p := new(big.Int)
	c2p := new(big.Int)
	if s.Sign() < 0 {
		inv, err := modInverse(c1, n)
		if err != nil {
			return "", fmt.Errorf("c1 模逆失败: %v", err)
		}
		c1p.Exp(inv, new(big.Int).Neg(s), n)
	} else {
		c1p.Exp(c1, s, n)
	}
	if t.Sign() < 0 {
		inv, err := modInverse(c2, n)
		if err != nil {
			return "", fmt.Errorf("c2 模逆失败: %v", err)
		}
		c2p.Exp(inv, new(big.Int).Neg(t), n)
	} else {
		c2p.Exp(c2, t, n)
	}
	m := new(big.Int).Mul(c1p, c2p)
	m.Mod(m, n)
	mBytes := m.Bytes()
	printable := isPrintableRatio(string(mBytes))
	return fmt.Sprintf("明文(hex): %s\n明文(文本): %q (可打印率 %.0f%%)",
		hex.EncodeToString(mBytes), string(mBytes), printable*100), nil
}

// modInverse 模逆（a*x ≡ 1 mod m），无逆时报错
func modInverse(a, m *big.Int) (*big.Int, error) {
	inv := new(big.Int).ModInverse(a, m)
	if inv == nil {
		return nil, fmt.Errorf("a 与 m 不互质")
	}
	return inv, nil
}
