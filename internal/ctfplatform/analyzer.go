// Package ctfplatform 提供任务分析/路由模块。
//
// 功能：自动识别 CTF 题型（crypto/misc/web/reverse/pwn），
// 并路由到对应的确定性求解器或 LLM 推理。
//
// 设计参考西湖论剑 task_analyzer.py：读取题目描述/附件 →
// 识别算法特征 → 提取参数 → 路由到最佳求解器。
package ctfplatform

import (
	"regexp"
	"strings"
)

// TaskCategory 表示题目分类。
type TaskCategory string

const (
	CategoryCrypto TaskCategory = "crypto"
	CategoryMisc   TaskCategory = "misc"
	CategoryWeb    TaskCategory = "web"
	CategoryReverse TaskCategory = "reverse"
	CategoryPwn    TaskCategory = "pwn"
	CategoryUnknown TaskCategory = "unknown"
)

// SolveRoute 表示求解路由建议。
type SolveRoute struct {
	Category    TaskCategory `json:"category"`
	SubType     string       `json:"sub_type"`      // 子类型（如 RSA 小指数）
	Solver      string       `json:"solver"`         // 推荐求解器名
	Reason      string       `json:"reason"`         // 路由原因
	Params      map[string]interface{} `json:"params"` // 提取的参数（如 e, n, c）
	Confidence  float64      `json:"confidence"`     // 路由置信度 0-1
}

// TaskAnalyzer 任务分析器。
type TaskAnalyzer struct{}

// NewTaskAnalyzer 创建任务分析器。
func NewTaskAnalyzer() *TaskAnalyzer {
	return &TaskAnalyzer{}
}

// Analyze 分析题目并返回路由建议。
func (a *TaskAnalyzer) Analyze(ch *Challenge, attachments map[string]string) []SolveRoute {
	text := ch.Description
	for _, v := range attachments {
		text += "\n" + v
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}

	var routes []SolveRoute

	// 1. 显式分类（题目自带 category 字段）
	if ch.Category != "" {
		cat := TaskCategory(strings.ToLower(ch.Category))
		if cat != CategoryUnknown {
			routes = append(routes, SolveRoute{
				Category:   cat,
				Solver:     string(cat) + "_default",
				Reason:     "题目显式分类: " + ch.Category,
				Confidence: 0.9,
			})
		}
	}

	// 2. 关键词模板匹配（对齐西湖论剑 _FAST_SOLVE_KEYWORDS）
	routes = append(routes, a.analyzeKeywords(text)...)

	// 3. RSA 参数提取与子类型路由
	if rsaRoute := a.analyzeRSA(text); rsaRoute != nil {
		routes = append(routes, *rsaRoute)
	}

	// 4. Web 特征检测
	if webRoute := a.analyzeWeb(text); webRoute != nil {
		routes = append(routes, *webRoute)
	}

	// 5. Misc 特征检测
	if miscRoute := a.analyzeMisc(text); miscRoute != nil {
		routes = append(routes, *miscRoute)
	}

	// 去重并按置信度排序
	return deduplicateRoutes(routes)
}

// ── 关键词模板匹配 ──────────────────────────────────────

var keywordPatterns = []struct {
	kind      string
	keywords  []string
	category  TaskCategory
	solver    string
	confidence float64
}{
	{"caesar", []string{"caesar", "凯撒"}, CategoryCrypto, "caesar", 0.8},
	{"base64", []string{"base64", "b64", "编码", "解码"}, CategoryCrypto, "base64_multilayer", 0.7},
	{"morse", []string{"morse", "摩斯"}, CategoryMisc, "morse", 0.8},
	{"hash", []string{"hash", "md5", "sha", "哈希"}, CategoryCrypto, "hash_crack", 0.7},
	{"vigenere", []string{"vigenere", "维吉尼亚"}, CategoryCrypto, "vigenere", 0.8},
	{"xor", []string{"xor", "异或"}, CategoryCrypto, "xor_single", 0.7},
	{"rail", []string{"rail", "栅栏", "fence"}, CategoryCrypto, "rail_fence", 0.7},
	{"fermat", []string{"fermat", "费马"}, CategoryCrypto, "rsa_fermat", 0.8},
	{"rsa", []string{"rsa", "RSA"}, CategoryCrypto, "rsa_template", 0.6},
	{"common_modulus", []string{"共模", "common modulus"}, CategoryCrypto, "rsa_common_modulus", 0.8},
	{"small_e", []string{"小指数", "small e"}, CategoryCrypto, "rsa_small_e", 0.8},
	{"ssti", []string{"ssti", "模板注入"}, CategoryWeb, "ssti", 0.8},
	{"sqli", []string{"sql注入", "sql injection", "sqli"}, CategoryWeb, "sqli", 0.8},
	{"xxe", []string{"xxe", "xml外部实体"}, CategoryWeb, "xxe", 0.7},
	{"jwt", []string{"jwt", "json web token"}, CategoryWeb, "jwt", 0.7},
	{"zip", []string{"zip", "伪加密"}, CategoryMisc, "zip_fake_enc", 0.7},
	{"lsb", []string{"lsb", "隐写", "steganography"}, CategoryMisc, "lsb_extract", 0.7},
	{"traffic", []string{"pcap", "流量", "traffic"}, CategoryMisc, "traffic_analysis", 0.7},
	{"reverse", []string{"逆向", "reverse", "反编译"}, CategoryReverse, "reverse_default", 0.6},
	{"pwn", []string{"pwn", "漏洞利用", "exploit"}, CategoryPwn, "pwn_default", 0.6},
}

func (a *TaskAnalyzer) analyzeKeywords(text string) []SolveRoute {
	lower := strings.ToLower(text)
	var routes []SolveRoute
	for _, kp := range keywordPatterns {
		for _, kw := range kp.keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				routes = append(routes, SolveRoute{
					Category:   kp.category,
					SubType:    kp.kind,
					Solver:     kp.solver,
					Reason:     "关键词匹配: " + kw,
					Confidence: kp.confidence,
				})
				break
			}
		}
	}
	return routes
}

// ── RSA 参数提取与子类型路由 ────────────────────────────

var (
	rsaImportRe = regexp.MustCompile(`(?i)(from\s+Crypto\.PublicKey\s+import\s+RSA|Crypto\.PublicKey\.RSA|getPrime|PKCS1|import\s+RSA|gmpy2)`)
	eRe         = regexp.MustCompile(`(?i)\be\s*=\s*(\d+)`)
	nRe         = regexp.MustCompile(`(?i)\bn\s*=\s*(\d+)`)
	hintRe      = regexp.MustCompile(`(?i)\bhint\s*=\s*(\d+)`)
)

func (a *TaskAnalyzer) analyzeRSA(text string) *SolveRoute {
	if !rsaImportRe.MatchString(text) {
		return nil
	}

	params := make(map[string]interface{})
	params["algorithm"] = "RSA"

	eMatch := eRe.FindStringSubmatch(text)
	nMatch := nRe.FindStringSubmatch(text)
	hintMatch := hintRe.FindStringSubmatch(text)

	if eMatch != nil {
		params["e"] = eMatch[1]
	}
	if nMatch != nil {
		params["n"] = nMatch[1]
	}
	if hintMatch != nil {
		params["hint"] = hintMatch[1]
	}

	route := &SolveRoute{
		Category:   CategoryCrypto,
		SubType:    "RSA",
		Params:     params,
		Confidence: 0.9,
	}

	// 路由到具体 RSA 攻击
	if hintMatch != nil {
		route.Solver = "rsa_pkcs1_hint"
		route.Reason = "RSA hint=(e*p+e^2)^q mod n 型"
	} else if eMatch != nil {
		ev := eMatch[1]
		switch ev {
		case "3", "5", "7":
			route.Solver = "rsa_small_e"
			route.Reason = "RSA e=" + ev + " 小指数攻击"
		case "65536", "65537":
			route.Solver = "rsa_template"
			route.Reason = "RSA 标准指数"
		default:
			route.Solver = "rsa_fermat"
			route.Reason = "RSA 默认费马分解"
		}
	} else {
		route.Solver = "rsa_fermat"
		route.Reason = "RSA 默认费马分解"
	}

	return route
}

// ── Web 特征检测 ────────────────────────────────────────

func (a *TaskAnalyzer) analyzeWeb(text string) *SolveRoute {
	lower := strings.ToLower(text)

	// SQL 注入特征
	sqlPatterns := []string{"select ", "union ", "insert ", "update ", "delete ", "from ", "where "}
	sqlCount := 0
	for _, p := range sqlPatterns {
		if strings.Contains(lower, p) {
			sqlCount++
		}
	}
	if sqlCount >= 2 {
		return &SolveRoute{
			Category:   CategoryWeb,
			SubType:    "sqli",
			Solver:     "sqli",
			Reason:     "SQL 语法特征检测",
			Confidence: 0.7,
		}
	}

	// SSTI 特征
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		return &SolveRoute{
			Category:   CategoryWeb,
			SubType:    "ssti",
			Solver:     "ssti",
			Reason:     "模板注入语法特征",
			Confidence: 0.7,
		}
	}

	// XXE 特征
	if strings.Contains(lower, "<!entity") || strings.Contains(lower, "xml") {
		return &SolveRoute{
			Category:   CategoryWeb,
			SubType:    "xxe",
			Solver:     "xxe",
			Reason:     "XML/XXE 特征检测",
			Confidence: 0.6,
		}
	}

	return nil
}

// ── Misc 特征检测 ────────────────────────────────────────

func (a *TaskAnalyzer) analyzeMisc(text string) *SolveRoute {
	// Morse 特征
	morseRe := regexp.MustCompile(`^[\.\-\s/]{10,}$`)
	if morseRe.MatchString(strings.TrimSpace(text)) {
		return &SolveRoute{
			Category:   CategoryMisc,
			SubType:    "morse",
			Solver:     "morse",
			Reason:     "Morse 码特征",
			Confidence: 0.9,
		}
	}

	// 多层 base64 特征
	b64Re := regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`)
	if b64Re.MatchString(strings.TrimSpace(text)) {
		return &SolveRoute{
			Category:   CategoryCrypto,
			SubType:    "base64",
			Solver:     "base64_multilayer",
			Reason:     "Base64 编码特征",
			Confidence: 0.8,
		}
	}

	return nil
}

// ── 工具函数 ─────────────────────────────────────────────

func deduplicateRoutes(routes []SolveRoute) []SolveRoute {
	seen := make(map[string]bool)
	var result []SolveRoute
	for _, r := range routes {
		key := string(r.Category) + ":" + r.Solver
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}
	return result
}
