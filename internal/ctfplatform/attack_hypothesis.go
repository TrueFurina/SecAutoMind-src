package ctfplatform

import (
	"sort"
	"strconv"
	"strings"
)

// ── P1-1 攻击向量编排层（2026-10-26）────────────────────────────────────────
//
// 计划依据（求解能力深化计划 L151-153）：hint 求解器 → 结构化「攻击假设」对象
// （attack_type + preconditions + 所需参数 + 验证方式），随题面注入 LLM。
// 治失败模式①②（两路调研共同头号失败模式：不看题面盲扫 / 选错攻击面）。
//
// 与「在 prompt 里罗列攻击类型表」的本质区别（基线文档 §六已实证罗列式的失败）：
//   - 罗列式 = 静态清单 + 低温解码 → **首项锁死**（每道题都选列表第一项 source-leak）；
//   - 本文件 = **从本题题面线索推导** → 假设带着"证据"（端点/参数名来自题目原文），
//     并按命中信号数排序。模型拿到的是"这道题该往哪打"，不是"通用攻击类型目录"。
//
// 红线：只给**方法与参数位置**，不给可直接提交的成品 exploit；也不含任何真 flag。

// AttackHypothesis 一条结构化攻击假设。
type AttackHypothesis struct {
	AttackType    string   // sqli / ssti / lfi / ssrf / cmdi / nosql / xxe / upload
	Endpoint      string   // 目标端点（题面线索优先；空=题面未给）
	Method        string   // GET / POST（未知为空）
	Params        []string // 需要的参数名（题面线索优先）
	Preconditions []string // 成立前提（用于让模型自己判断"该不该打"）
	Approach      string   // 构造方法（给思路，不给成品 payload）
	Verify        string   // 验证方式（怎么确认打中了）
	Signals       int      // 命中的独立信号数（排序依据 = 线索强度）
}

// hypothesisSpec 每种攻击类型的编排模板。
type hypothesisSpec struct {
	attackType    string
	preconditions []string
	approach      string
	verify        string
}

// attackHypothesisSpecs 类型 → 编排模板。顺序**不参与排序**（排序只看 Signals），
// 避免重蹈"罗列式首项锁死"的覆辙。
var attackHypothesisSpecs = map[string]hypothesisSpec{
	"sqli": {
		attackType:    "sqli",
		preconditions: []string{"该端点接受用户输入并拼进 SQL", "参数值会影响响应内容或报错"},
		approach:      "在给定参数里构造恒真/联合查询：先试 ' 触发报错确认拼接点，再用 ' OR 1=1-- 或 UNION SELECT 取数据",
		verify:        "响应出现额外数据行/报错信息变化/登录绕过成功",
	},
	"ssti": {
		attackType:    "ssti",
		preconditions: []string{"参数值被当作模板渲染（回显了运算结果或原样回显）"},
		approach:      "先投 {{7*7}} 看是否回显 49 确认渲染点，再沿模板引擎的对象链取到文件读取/命令执行",
		verify:        "响应出现 49 或运算结果，说明表达式被求值",
	},
	"lfi": {
		attackType:    "lfi",
		preconditions: []string{"参数值被拼进文件路径"},
		approach:      "用 ../ 逐层回退或直接给绝对路径读取目标文件；必要时用 php://filter 等包装器绕过后缀拼接",
		// 注意：不得写出 flag 明文前缀字面量（会污染仓库 flag 明文基线，见 secret_guard）
		verify: "响应体出现目标文件内容（如 root:x: 或题面要求的内容）",
	},
	"cmdi": {
		attackType:    "cmdi",
		preconditions: []string{"参数值被拼进 shell 命令"},
		approach:      "用 ; && | 或换行分隔注入命令；无回显时用延时或外带确认",
		verify:        "响应出现命令输出（uid=、文件内容）",
	},
	"ssrf": {
		attackType:    "ssrf",
		preconditions: []string{"服务端会按给定 URL 发起请求"},
		approach:      "让服务端请求内网地址/本地文件协议，把响应内容带回；必要时绕过黑名单（十进制 IP、重定向）",
		verify:        "响应出现内网服务或本地文件内容",
	},
	"nosql": {
		attackType:    "nosql",
		preconditions: []string{"后端是 MongoDB 类查询", "参数支持 JSON/结构化输入"},
		approach:      "把等值条件换成操作符对象（$ne/$gt/$regex）使条件恒真；注意 Content-Type 用 application/json",
		verify:        "认证被绕过或返回了额外记录",
	},
	"xxe": {
		attackType:    "xxe",
		preconditions: []string{"服务端解析 XML 输入"},
		approach:      "在 XML 里声明外部实体指向目标文件，再让解析结果回显到响应",
		verify:        "响应出现目标文件内容",
	},
	"upload": {
		attackType:    "upload",
		preconditions: []string{"存在上传接口", "上传目录可执行脚本或存在解析差异"},
		approach:      "绕过扩展名/MIME/内容检测（双扩展、image/png MIME、内容头）后访问上传路径执行",
		verify:        "上传文件路径可直接访问且脚本被执行",
	},
}

// typeEndpointHints / typeParamHints 是「该类型典型端点名 / 参数名」。
// 用途：让 Signals 成为**类型级**证据而不是题面级公共分。
// 🔴 为什么必须类型级：初版按「题面是否给了端点/参数/载荷」计分，结果同一题面下
//   所有假设得分完全相同（这些信号是题面级的，与类型无关），排序退化成字典序，
//   「按线索强度排序」形同虚设 —— 由变异测试（把排序改成升序）暴露：测试没变红。
var typeEndpointHints = map[string][]string{
	"sqli":   {"login", "search", "user", "auth", "query", "id"},
	"ssti":   {"page", "render", "template", "name", "view"},
	"lfi":    {"file", "page", "path", "include", "download", "read"},
	"cmdi":   {"cmd", "ping", "exec", "run", "shell", "system"},
	"ssrf":   {"fetch", "url", "proxy", "request", "internal", "load"},
	"nosql":  {"login", "auth", "user", "find", "query"},
	"xxe":    {"xml", "parse", "upload", "import"},
	"upload": {"upload", "file", "avatar", "image"},
}

var typeParamHints = map[string][]string{
	"sqli":   {"user", "pass", "id", "name", "username", "password", "q", "keyword"},
	"ssti":   {"name", "page", "content", "template", "msg"},
	"lfi":    {"file", "page", "path", "filename", "include", "doc"},
	"cmdi":   {"ip", "host", "cmd", "command", "target", "addr"},
	"ssrf":   {"url", "uri", "target", "link", "site", "host"},
	"nosql":  {"user", "username", "pass", "password", "query"},
	"xxe":    {"xml", "data", "file"},
	"upload": {"file", "upload", "filename", "avatar"},
}

// BuildAttackHypotheses 把题面线索（WebHints）编排成结构化攻击假设，按线索强度降序。
//
// Signals 计分（**类型级**证据，四条独立）：
//   +1 该类型的关键词在描述里命中（ParseWebHints 的类型判定）
//   +1 题面端点名符合该类型的典型端点（如 /cmd.php 对 cmdi）
//   +1 题面参数名符合该类型的典型参数（如 ip 对 cmdi、file 对 lfi）
//   +1 题面给出的载荷片段命中该类型特征（如 ;cat 对 cmdi）
// 同分时按 attack_type 字典序，保证输出**稳定可复现**。
func BuildAttackHypotheses(text string, hints WebHints) []AttackHypothesis {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	types := hints.Types
	if len(types) == 0 {
		return nil // 无线索 → 不给假设（宁缺勿猜，避免把模型导向盲扫）
	}

	endpoint := ""
	if len(hints.Endpoints) > 0 {
		endpoint = hints.Endpoints[0]
	}
	method := detectMethod(text, endpoint)
	params := hints.Params
	if len(params) > 1 {
		params = params[:min(len(params), 4)] // 最多给 4 个，避免噪声
	}

	out := make([]AttackHypothesis, 0, len(types))
	for _, typ := range types {
		spec, ok := attackHypothesisSpecs[typ]
		if !ok {
			continue // 未登记类型 → 不编排（不给没把握的假设）
		}
		signals := 1 // 类型关键词命中
		if matchesAny(endpoint, typeEndpointHints[typ]) {
			signals++
		}
		if paramsMatchAny(params, typeParamHints[typ]) {
			signals++
		}
		if payloadMatchesType(hints.Payloads, typ) {
			signals++
		}
		out = append(out, AttackHypothesis{
			AttackType:    spec.attackType,
			Endpoint:      endpoint,
			Method:        method,
			Params:        params,
			Preconditions: spec.preconditions,
			Approach:      spec.approach,
			Verify:        spec.verify,
			Signals:       signals,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Signals != out[j].Signals {
			return out[i].Signals > out[j].Signals
		}
		return out[i].AttackType < out[j].AttackType
	})
	return out
}

// detectMethod 从描述里判断端点对应的 HTTP 方法（只认题面明写的 GET/POST）。
func detectMethod(text, endpoint string) string {
	if endpoint == "" {
		return ""
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, endpoint) {
			continue
		}
		upper := strings.ToUpper(line)
		pi := strings.Index(upper, "POST")
		gi := strings.Index(upper, "GET")
		switch {
		case pi >= 0 && (gi < 0 || pi < gi):
			return "POST"
		case gi >= 0:
			return "GET"
		}
	}
	return ""
}

// RenderAttackHypotheses 把假设渲染成注入 LLM 的提示片段（紧凑、可机检）。
// 只给方法与验证方式 —— 不含任何成品 exploit、不含真 flag。
func RenderAttackHypotheses(hs []AttackHypothesis) string {
	if len(hs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("【攻击假设】（由本题描述推导，按线索强度排序 —— 这是**证据**不是通用类型目录）\n")
	for i, h := range hs {
		b.WriteString(strings.Repeat("-", 3) + " ")
		b.WriteString("假设" + strconv.Itoa(i+1) + "：" + h.AttackType)
		if h.Method != "" {
			b.WriteString(" · " + h.Method)
		}
		if h.Endpoint != "" {
			b.WriteString(" " + h.Endpoint)
		}
		b.WriteString("（线索 " + strconv.Itoa(h.Signals) + " 条）\n")
		if len(h.Params) > 0 {
			b.WriteString("    参数：" + strings.Join(h.Params, ", ") + "\n")
		}
		if len(h.Preconditions) > 0 {
			b.WriteString("    前提：" + strings.Join(h.Preconditions, "；") + "\n")
		}
		if h.Approach != "" {
			b.WriteString("    构造：" + h.Approach + "\n")
		}
		if h.Verify != "" {
			b.WriteString("    验证：" + h.Verify + "\n")
		}
	}
	b.WriteString("用法：先按**线索最强的假设**发第一个针对性请求；" +
		"若验证点不成立再换下一条。不要跳过假设去枚举通用路径。")
	return b.String()
}



// matchesAny 判断文本是否包含任一关键词（大小写不敏感）。
func matchesAny(text string, keywords []string) bool {
	low := strings.ToLower(text)
	for _, k := range keywords {
		if k != "" && strings.Contains(low, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// paramsMatchAny 判断参数名列表是否命中该类型的典型参数名。
func paramsMatchAny(params []string, typical []string) bool {
	for _, p := range params {
		for _, t := range typical {
			if strings.EqualFold(strings.TrimSpace(p), t) {
				return true
			}
		}
	}
	return false
}

// payloadMatchesType 判断题面给出的载荷片段是否命中该类型特征。
func payloadMatchesType(payloads []string, typ string) bool {
	if len(payloads) == 0 {
		return false
	}
	for _, p := range hintTypePatterns {
		if p.typ != typ {
			continue
		}
		for _, payload := range payloads {
			if p.re.MatchString(payload) {
				return true
			}
		}
	}
	return false
}
