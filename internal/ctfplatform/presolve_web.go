// presolve_web.go —— Web 类求解器（SQLi/SSRF/XSS/JWT/GraphQL/反序列化等）
// 自 presolve.go 机械拆分（25 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"fmt"
	"regexp"
	"strings"
)

// trySQLi 检测 SQL 注入特征与 payload 回显。
func trySQLi(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// SQL 注入 payload 回显检测
	sqliPatterns := []struct {
		pattern string
		hint    string
	}{
		{`union\s+select`, "UNION SELECT 注入"},
		{`order\s+by\s+\d+`, "ORDER BY 注入（列数探测）"},
		{`or\s+1\s*=\s*1`, "OR 1=1 永真注入"},
		{`and\s+1\s*=\s*1`, "AND 1=1 逻辑探测"},
		{`'\s*or\s*'`, "单引号 OR 注入"},
		{`"\s*or\s*"`, "双引号 OR 注入"},
		{`sleep\s*\(\s*\d+\s*\)`, "时间盲注（SLEEP）"},
		{`benchmark\s*\(`, "时间盲注（BENCHMARK）"},
		{`waitfor\s+delay`, "时间盲注（WAITFOR）"},
		{`if\s*\(\s*\d+\s*=\s*\d+`, "条件盲注（IF）"},
		{`information_schema`, "INFORMATION_SCHEMA 枚举"},
		{`table_name`, "表名枚举"},
		{`column_name`, "列名枚举"},
		{`load_file\s*\(`, "LOAD_FILE 读文件"},
		{`into\s+outfile`, "INTO OUTFILE 写文件"},
		{`into\s+dumpfile`, "INTO DUMPFILE 写文件"},
		{`extractvalue\s*\(`, "EXTRACTVALUE 报错注入"},
		{`updatexml\s*\(`, "UPDATEXML 报错注入"},
		{`floor\s*\(\s*rand`, "FLOOR/RAND 报错注入"},
		{`group\s+by\s+`, "GROUP BY 报错注入"},
	}
	for _, p := range sqliPatterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		if m := re.FindString(fullText); m != "" {
			results = append(results, "SQLi特征: "+p.hint+" ("+m[:minInt(30, len(m))]+")")
		}
	}
	if len(results) > 0 {
		return results
	}

	// SQL 错误信息泄露
	sqlErrors := []string{"sql syntax", "mysql_fetch", "sqlite_error", "ORA-", "SQLSTATE", "postgresql", "mssql"}
	for _, e := range sqlErrors {
		if strings.Contains(lower, strings.ToLower(e)) {
			return []string{"SQL错误泄露: " + e + " (可能存在注入点)"}
		}
	}
	return nil
}

// trySSRF 检测 SSRF 特征与内网地址探测。
func trySSRF(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	ssrfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ssrf", "SSRF：服务器端请求伪造"},
		{"server-side request forgery", "服务器端请求伪造攻击"},
		{"127.0.0.1", "本地回环地址探测"},
		{"localhost", "localhost 探测"},
		{"0.0.0.0", "全接口地址探测"},
		{"169.254.169.254", "云元数据服务探测（AWS/GCP/Azure）"},
		{"metadata.google.internal", "GCP 元数据服务"},
		{"100.100.100.200", "阿里云元数据服务"},
		{"file://", "FILE 协议读取本地文件"},
		{"gopher://", "GOPHER 协议利用"},
		{"dict://", "DICT 协议利用"},
		{"url redirect", "URL 重定向漏洞"},
		{"dns rebinding", "DNS 重绑定攻击"},
	}
	for _, kw := range ssrfKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "SSRF特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}
	// 检测内网 IP 模式
	privateIPRe := regexp.MustCompile(`(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}`)
	if m := privateIPRe.FindString(fullText); m != "" {
		return []string{"检测到内网 IP 地址: " + m + "（可能 SSRF 目标）"}
	}
	return nil
}

// tryXXE 检测 XML 外部实体注入特征。
func tryXXE(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}

	xxePatterns := []struct {
		pattern string
		hint    string
	}{
		{`<!entity`, "XXE 实体定义"},
		{`system\s+[\"']`, "SYSTEM 实体（读取本地文件）"},
		{`public\s+[\"']`, "PUBLIC 实体"},
		{`expect://`, "expect:// 协议利用"},
		{`php://`, "PHP 流包装器利用"},
		{`/etc/passwd`, "/etc/passwd 文件读取"},
		{`/etc/shadow`, "/etc/shadow 文件读取"},
		{`c:/windows`, "Windows 系统文件读取"},
		{`<!doctype`, "DOCTYPE 声明（可能含实体）"},
		{`xxe`, "XXE 注入关键词"},
		{`xml external entity`, "XML 外部实体注入"},
		{`billion laughs`, "Billion Laughs 攻击（XML 炸弹）"},
		{`parameter entity`, "参数实体注入"},
	}
	for _, p := range xxePatterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		if re.MatchString(fullText) {
			return []string{"XXE特征: " + p.hint}
		}
	}

	// 检测 XML 结构（可能含 XXE 注入点）
	if strings.Contains(fullText, "<?xml") || strings.Contains(fullText, "<!DOCTYPE") {
		return []string{"检测到 XML 结构，可能存在 XXE 注入点"}
	}
	return nil
}

// tryJWT 检测 JWT 特征与常见攻击模式。
func tryJWT(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)

	jwtKeywords := []struct {
		keyword string
		hint    string
	}{
		{"jwt", "JWT（JSON Web Token）"},
		{"json web token", "JSON Web Token"},
		{"eyJ", "Base64 编码的 JWT 头部（eyJ = {'typ':...}）"},
		{"bearer ", "Bearer Token 认证"},
		{"alg:none", "JWT alg:none 攻击（禁用签名验证）"},
		{"alg: none", "JWT alg:none 攻击"},
		{"hs256", "HMAC-SHA256 签名"},
		{"rs256", "RSA-SHA256 签名"},
		{"public key", "RSA 公钥泄露"},
		{"kid", "JWT kid 注入"},
		{"jwk", "JWK 注入攻击"},
		{"jku", "JWKS URL 注入"},
		{"kid injection", "JWT kid 参数注入"},
		{"jwt.io", "JWT 调试工具"},
		{"refresh token", "Refresh Token"},
	}
	for _, kw := range jwtKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"JWT特征: " + kw.hint}
		}
	}
	// 检测 JWT 格式（三段 base64 用点分隔）
	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	if m := jwtRe.FindString(fullText); m != "" {
		return []string{"检测到 JWT Token 格式: " + m[:minInt(60, len(m))] + "..."}
	}
	return nil
}

// tryRaceCondition 检测竞态条件特征。
func tryRaceCondition(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)

	raceKeywords := []struct {
		keyword string
		hint    string
	}{
		{"race condition", "竞态条件：并发请求利用时序漏洞"},
		{"race", "竞态攻击"},
		{"toctou", "TOCTOU（Time-of-Check Time-of-Use）漏洞"},
		{"time of check", "TOC 时间点检查"},
		{"time of use", "TOU 时间点使用"},
		{"concurrent", "并发请求"},
		{"parallel request", "并行请求"},
		{"thread safety", "线程安全问题"},
		{"atomic", "原子性问题"},
		{"double spend", "双重消费"},
		{"replay", "重放攻击"},
	}
	for _, kw := range raceKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"竞态特征: " + kw.hint}
		}
	}
	// 检测并发请求模式（多次请求同一端点）
	urlRe := regexp.MustCompile(`https?://[^\s"']+`)
	urls := urlRe.FindAllString(fullText, -1)
	if len(urls) >= 5 {
		return []string{fmt.Sprintf("检测到 %d 个 URL（可能并发请求场景）", len(urls))}
	}
	return nil
}

// tryWebAdvanced 检测高级 Web 漏洞特征（上传绕过/目录遍历/CSRF/CORS/Header注入）。
func tryWebAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	webPatterns := []struct {
		keyword string
		hint    string
	}{
		// 上传绕过
		{"file upload", "文件上传功能"},
		{"multipart/form-data", "文件上传表单"},
		{".php", "PHP 文件上传"},
		{".jsp", "JSP 文件上传"},
		{".asp", "ASP 文件上传"},
		{"content-type", "Content-Type 绕过（MIME 类型欺骗）"},
		{"image/jpeg", "伪造图片 MIME 绕过"},
		{"move_uploaded_file", "PHP 文件移动函数"},
		{"upload", "文件上传关键词"},
		// 目录遍历
		{"../", "目录遍历路径（../）"},
		{"..\\", "Windows目录遍历"},
		{"/etc/passwd", "Linux 密码文件读取"},
		{"/etc/shadow", "Linux 密码哈希读取"},
		{"c:\\windows", "Windows 系统目录"},
		{"directory listing", "目录列表暴露"},
		{"index of /", "Apache 目录列表"},
		{"path traversal", "路径遍历漏洞"},
		{"dotdotpwn", "DotDotPwn 目录遍历工具"},
		{"lfi", "本地文件包含（LFI）"},
		{"rfi", "远程文件包含（RFI）"},
		{"file inclusion", "文件包含漏洞"},
		{"php://filter", "PHP 流包装器利用"},
		{"php://input", "PHP 输入流利用"},
		{"expect://", "expect 协议利用"},
		{"data://", "data 协议利用"},
		{"zip://", "zip 协议利用"},
		// CSRF
		{"csrf", "CSRF 跨站请求伪造"},
		{"cross-site request", "跨站请求伪造"},
		{"csrf token", "CSRF Token 保护"},
		{"xsrf", "XSRF（同 CSRF）"},
		{"anti-forgery", "反伪造 Token"},
		{"samesite", "SameSite Cookie 属性（CSRF 防护）"},
		// CORS
		{"cors", "CORS 跨域资源共享"},
		{"access-control-allow-origin", "CORS Access-Control-Allow-Origin"},
		{"access-control-allow-credentials", "CORS 允许凭证"},
		{"origin:", "Origin 请求头（CORS 代理）"},
		{"preflight", "CORS 预检请求"},
		// Header 分析
		{"content-security-policy", "CSP 内容安全策略"},
		{"strict-transport-security", "HSTS 严格传输安全"},
		{"x-frame-options", "X-Frame-Options 点击劫持防护"},
		{"x-content-type-options", "X-Content-Type-Options MIME 嗅探防护"},
		{"x-xss-protection", "X-XSS-Protection 浏览器 XSS 过滤"},
		{"referrer-policy", "Referrer-Policy 策略"},
		{"permissions-policy", "Permissions-Policy 权限策略"},
		{"server:", "Server 响应头（版本信息泄露）"},
		{"x-powered-by", "X-Powered-By 响应头（技术栈泄露）"},
		{"set-cookie", "Set-Cookie 响应头"},
		{"httponly", "HttpOnly Cookie 属性"},
		{"secure", "Secure Cookie 属性"},
	}
	for _, kw := range webPatterns {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "Web特征: "+kw.hint)
		}
	}

	// 检测 URL 中的注入点
	urlRe := regexp.MustCompile(`(?i)(?:url|redirect|next|return|goto|continue|dest|destination|redir|link|target)\s*[=:]\s*https?://`)
	if m := urlRe.FindString(fullText); m != "" {
		results = append(results, "开放重定向参数: "+m[:minInt(60, len(m))])
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// tryJavaDeserialization 检测 Java 反序列化漏洞特征。
func tryJavaDeserialization(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	javaKeywords := []struct {
		keyword string
		hint    string
	}{
		{"java deserialization", "Java 反序列化漏洞"},
		{"ysoserial", "Ysoserial：Java 反序列化 payload 生成工具"},
		{"rce", "远程代码执行（RCE）"},
		{"runtime.exec", "Runtime.exec 命令执行"},
		{"processbuilder", "ProcessBuilder 命令执行"},
		{"commons collections", "Apache Commons Collections 反序列化"},
		{"spring", "Spring 框架漏洞"},
		{"tomcat", "Apache Tomcat 服务器"},
		{"log4j", "Log4j 漏洞（Log4Shell）"},
		{"jndi", "JNDI 注入"},
		{"ldap", "LDAP 注入"},
		{"rmi", "Java RMI 远程方法调用"},
		{"jmx", "Java 管理扩展（JMX）"},
		{"fastjson", "Fastjson 反序列化"},
		{"jackson", "Jackson 反序列化"},
		{"xstream", "XStream 反序列化"},
		{"protobuf", "Protocol Buffers"},
		{"thrift", "Apache Thrift"},
		{"weblogic", "Oracle WebLogic 漏洞"},
		{"struts", "Apache Struts 漏洞"},
	}
	for _, kw := range javaKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Java特征: " + kw.hint}
		}
	}
	return nil
}

// tryGraphQL 检测 GraphQL 注入/内省特征。
func tryGraphQL(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gqlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"graphql", "GraphQL API"},
		{"__schema", "GraphQL 内省查询（__schema）"},
		{"__type", "GraphQL 类型内省"},
		{"query {", "GraphQL 查询"},
		{"mutation {", "GraphQL 变更"},
		{"subscription {", "GraphQL 订阅"},
		{"introspection", "GraphQL 内省攻击"},
		{"field injection", "GraphQL 字段注入"},
		{"batch query", "GraphQL 批量查询攻击"},
		{"depth limit", "GraphQL 深度限制绕过"},
		{"alias", "GraphQL 别名攻击"},
	}
	for _, kw := range gqlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"GraphQL: " + kw.hint}
		}
	}
	return nil
}

// tryWebSocket 检测 WebSocket 特征。
func tryWebSocket(text string) []string {
	lower := strings.ToLower(text)
	wsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"websocket", "WebSocket 协议"},
		{"wss://", "WebSocket Secure 连接"},
		{"ws://", "WebSocket 连接"},
		{"upgrade: websocket", "WebSocket 升级握手"},
		{"sec-websocket-key", "WebSocket 握手密钥"},
		{"socket.io", "Socket.IO 实时通信"},
		{"signalr", "SignalR 实时通信"},
		{"server-sent events", "SSE 服务器推送"},
	}
	for _, kw := range wsKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"WebSocket: " + kw.hint}
		}
	}
	return nil
}

// tryAPISecurity 检测 API 安全关键词。
func tryAPISecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	apiKeywords := []struct {
		keyword string
		hint    string
	}{
		{"api key", "API 密钥"},
		{"bearer token", "Bearer Token 认证"},
		{"oauth", "OAuth 认证"},
		{"rate limit", "API 速率限制"},
		{"swagger", "Swagger/OpenAPI 文档"},
		{"openapi", "OpenAPI 规范"},
		{"endpoint", "API 端点"},
		{"microservice", "微服务架构"},
		{"api gateway", "API 网关"},
	}
	for _, kw := range apiKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"API安全: " + kw.hint}
		}
	}
	return nil
}

// tryWebTemplateInjection 检测模板注入高级特征（SSTI/服务端模板注入）。
func tryWebTemplateInjection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	tplKeywords := []struct {
		keyword string
		hint    string
	}{
		{"template injection", "服务端模板注入（SSTI）"},
		{"server-side template", "服务端模板"},
		{"jinja2", "Jinja2 模板引擎"},
		{"twig", "Twig 模板引擎"},
		{"freemarker", "FreeMarker 模板引擎"},
		{"velocity", "Apache Velocity 模板"},
		{"thymeleaf", "Thymeleaf 模板引擎"},
		{"mustache", "Mustache 模板引擎"},
		{"handlebars", "Handlebars 模板引擎"},
		{"ejs", "EJS 模板引擎"},
		{"pug", "Pug 模板引擎"},
		{"erb", "ERB 模板引擎"},
		{"smarty", "Smarty 模板引擎"},
		{"blade", "Blade 模板引擎"},
		{"liquid", "Liquid 模板引擎"},
		{"sandbox escape", "沙箱逃逸"},
		{"expression language", "表达式语言注入"},
		{"ognl", "OGNL 表达式注入"},
		{"mvel", "MVEL 表达式注入"},
		{"spel", "Spring 表达式语言（SpEL）"},
		{"el injection", "表达式语言注入"},
	}
	for _, kw := range tplKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"模板注入: " + kw.hint}
		}
	}
	return nil
}

// tryPrototypePollution 检测原型链污染特征（Node.js/JavaScript 对象注入）。
func tryPrototypePollution(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ppKeywords := []struct {
		keyword string
		hint    string
	}{
		{"prototype pollution", "原型链污染攻击"},
		{"__proto__", "__proto__ 原型链注入"},
		{"constructor.prototype", "constructor.prototype 污染"},
		{"object.assign", "Object.assign 合并漏洞"},
		{"deep merge", "深合并漏洞"},
		{"lodash", "Lodash 深合并漏洞"},
		{"merge()", "merge 函数漏洞"},
		{"extend()", "extend 函数漏洞"},
		{"json.parse", "JSON.parse 与原型链"},
		{"polluted", "污染检测"},
		{"gadget chain", "利用链（原型污染→RCE）"},
		{"code execution", "代码执行（通过原型链）"},
		{"remote code execution", "远程代码执行"},
		{"rce", "RCE 漏洞"},
	}
	for _, kw := range ppKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"原型链污染: " + kw.hint}
		}
	}
	// 检测 JSON 中的 __proto__ 键
	if strings.Contains(fullText, "__proto__") || strings.Contains(fullText, "constructor") {
		if strings.Contains(lower, "pollution") || strings.Contains(lower, "inject") {
			return []string{"原型链污染: 检测到 __proto__ 注入特征"}
		}
	}
	return nil
}

// tryGraphQLBatch 检测 GraphQL 批量注入/深度攻击特征。
func tryGraphQLBatch(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gqlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"graphql injection", "GraphQL 注入攻击"},
		{"graphql batching", "GraphQL 批量查询攻击"},
		{"query batching", "查询批量发送"},
		{"aliasing attack", "别名攻击（绕过查询复杂度限制）"},
		{"nested query", "嵌套查询攻击"},
		{"circular reference", "循环引用攻击"},
		{"depth attack", "查询深度攻击"},
		{"complexity attack", "查询复杂度攻击"},
		{"field duplication", "字段重复攻击"},
		{"fragment injection", "Fragment 注入"},
		{"inline fragment", "内联 Fragment"},
		{"defer directive", "defer 延迟指令"},
		{"stream directive", "stream 流式指令"},
	}
	for _, kw := range gqlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"GraphQL攻击: " + kw.hint}
		}
	}
	// 检测 GraphQL 查询中的批量特征
	if strings.Contains(fullText, "[{") && strings.Contains(fullText, "query") {
		return []string{"GraphQL 批量查询: 检测到数组格式 GraphQL 请求"}
	}
	return nil
}

// tryHTTPRequestSmuggling 检测 HTTP 请求走私特征。
func tryHTTPRequestSmuggling(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	smugKeywords := []struct {
		keyword string
		hint    string
	}{
		{"request smuggling", "HTTP 请求走私"},
		{"http request smuggling", "HTTP 请求走私攻击"},
		{"cl.te", "CL.TE 走私（Content-Length vs Transfer-Encoding）"},
		{"te.cl", "TE.CL 走私"},
		{"te.te", "TE.TE 走私（Transfer-Encoding 混淆）"},
		{"transfer-encoding", "Transfer-Encoding 头"},
		{"content-length", "Content-Length 头"},
		{"chunked encoding", "分块传输编码"},
		{"header injection", "HTTP 头注入"},
		{"crlf injection", "CRLF 注入"},
		{"host header", "Host 头注入"},
		{"hop-by-hop", "逐跳头攻击"},
		{"reverse proxy", "反向代理漏洞"},
		{"nginx", "Nginx 配置漏洞"},
		{"apache", "Apache 配置漏洞"},
		{"cache poisoning", "Web 缓存投毒"},
		{"web cache deception", "Web 缓存欺骗"},
		{"response splitting", "HTTP 响应拆分"},
	}
	for _, kw := range smugKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"HTTP走私: " + kw.hint}
		}
	}
	// 检测异常 Transfer-Encoding（走私的直接证据）
	teRe := regexp.MustCompile(`(?i)transfer-encoding\s*:\s*(.+)`)
	if m := teRe.FindString(fullText); m != "" {
		val := strings.TrimSpace(strings.SplitN(m, ":", 2)[1])
		if strings.Contains(strings.ToLower(val), "chunked") && strings.Contains(val, " ") {
			return []string{"HTTP 走私特征: Transfer-Encoding 值含异常空格（混淆攻击）"}
		}
	}
	return nil
}

// tryWebSocketHijack 检测 WebSocket 劫持/跨站特征。
func tryWebSocketHijack(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"websocket hijacking", "WebSocket 劫持"},
		{"cross-site websocket", "跨站 WebSocket 劫持"},
		{"cswh", "CSWH（跨站 WebSocket 劫持）"},
		{"ws poisoning", "WebSocket 投毒"},
		{"ws injection", "WebSocket 注入"},
		{"websocket frame", "WebSocket 帧分析"},
		{"binary frame", "二进制帧"},
		{"text frame", "文本帧"},
		{"ping pong", "Ping/Pong 帧"},
		{"close frame", "关闭帧"},
		{"websocket subprotocol", "WebSocket 子协议"},
	}
	for _, kw := range wsKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"WebSocket安全: " + kw.hint}
		}
	}
	return nil
}

// tryPrototypePollutionVariant 检测原型链污染变体（Node.js/Express/Koa 特定）。
func tryPrototypePollutionVariant(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ppKeywords := []struct {
		keyword string
		hint    string
	}{
		{"express", "Express.js 框架"},
		{"koa", "Koa.js 框架"},
		{"hapi", "Hapi.js 框架"},
		{"fastify", "Fastify 框架"},
		{"nest.js", "NestJS 框架"},
		{"next.js", "Next.js 框架"},
		{"nuxt.js", "Nuxt.js 框架"},
		{"object.assign", "Object.assign 合并"},
		{"deep clone", "深克隆"},
		{"json.parse", "JSON.parse"},
		{"extend", "extend/merge 函数"},
		{"polluted", "污染检测标志"},
		{"__defineGetter__", "__defineGetter__ 方法"},
		{"__defineSetter__", "__defineSetter__ 方法"},
		{"__lookupGetter__", "__lookupGetter__ 方法"},
		{"__lookupSetter__", "__lookupSetter__ 方法"},
	}
	for _, kw := range ppKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"JS框架: " + kw.hint}
		}
	}
	return nil
}

// tryWAFBypass 检测 WAF 绕过特征。
func tryWAFBypass(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wafKeywords := []struct {
		keyword string
		hint    string
	}{
		{"waf bypass", "WAF 绕过"},
		{"web application firewall", "Web 应用防火墙"},
		{"bypass waf", "WAF 绕过"},
		{"sql injection bypass", "SQL 注入绕过"},
		{"xss filter bypass", "XSS 过滤绕过"},
		{"payload encoding", "Payload 编码绕过"},
		{"double encoding", "双重编码"},
		{"unicode bypass", "Unicode 绕过"},
		{"case manipulation", "大小写变换"},
		{"comment injection", "注释注入"},
		{"null byte", "空字节注入"},
		{"chunked transfer", "分块传输绕过"},
		{"ip rotation", "IP 轮换"},
		{"user-agent rotation", "UA 轮换"},
		{"rate limit bypass", "速率限制绕过"},
	}
	for _, kw := range wafKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"WAF绕过: " + kw.hint}
		}
	}
	return nil
}

// tryRCEDetection 检测远程代码执行（RCE）特征。
func tryRCEDetection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	rceKeywords := []struct {
		keyword string
		hint    string
	}{
		{"remote code execution", "远程代码执行（RCE）"},
		{"command injection", "命令注入"},
		{"os command", "操作系统命令"},
		{"shell command", "Shell 命令"},
		{"exec(", "exec 函数调用"},
		{"system(", "system 函数调用"},
		{"popen", "popen 命令执行"},
		{"subprocess", "子进程调用"},
		{"eval(", "eval 动态执行"},
		{"runtime.exec", "Runtime.exec"},
		{"processbuilder", "ProcessBuilder"},
		{"deserialization", "反序列化"},
		{"pickle", "Python pickle 反序列化"},
		{"yaml.load", "YAML 反序列化"},
		{"unserialize", "PHP 反序列化"},
		{"template injection", "模板注入"},
		{"server-side include", "服务端包含（SSI）"},
		{"code injection", "代码注入"},
	}
	for _, kw := range rceKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"RCE特征: " + kw.hint}
		}
	}
	return nil
}

// tryFileInclusion 检测文件包含漏洞链（LFI/RFI/路径遍历）。
func tryFileInclusion(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	fiKeywords := []struct {
		keyword string
		hint    string
	}{
		{"file inclusion", "文件包含漏洞"},
		{"local file inclusion", "本地文件包含（LFI）"},
		{"remote file inclusion", "远程文件包含（RFI）"},
		{"path traversal", "路径遍历"},
		{"directory traversal", "目录遍历"},
		{"dot dot slash", "目录遍历（../）"},
		{"null byte", "空字节截断"},
		{"php://filter", "PHP 流包装器"},
		{"php://input", "PHP 输入流"},
		{"data://", "data:// 协议"},
		{"expect://", "expect:// 协议"},
		{"zip://", "zip:// 协议"},
		{"phar://", "phar:// 协议"},
		{"file://", "file:// 协议"},
		{"log poisoning", "日志投毒"},
		{"log injection", "日志注入"},
	}
	for _, kw := range fiKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"文件包含: " + kw.hint}
		}
	}
	return nil
}

// tryDeserialization 检测反序列化漏洞特征（Java/Python/PHP/Ruby/.NET）。
func tryDeserialization(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	deserKeywords := []struct {
		keyword string
		hint    string
	}{
		{"deserialization", "反序列化漏洞"},
		{"ysoserial", "Ysoserial（Java 反序列化）"},
		{"commons collections", "Commons Collections"},
		{"pickle", "Python pickle"},
		{"yaml.load", "YAML 反序列化"},
		{"unserialize", "PHP 反序列化"},
		{"gadget chain", "利用链"},
		{"magic method", "魔术方法"},
		{"__wakeup", "__wakeup 方法"},
		{"__destruct", "__destruct 方法"},
	}
	for _, kw := range deserKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"反序列化: " + kw.hint}
		}
	}
	return nil
}

// trySSRFChain 检测 SSRF 链/高级 SSRF 特征。
func trySSRFChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ssrfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ssrf chain", "SSRF 链攻击"},
		{"server-side request forgery", "服务端请求伪造"},
		{"dns rebinding", "DNS 重绑定"},
		{"time-of-check", "TOCTOU 漏洞"},
		{"url redirect", "URL 重定向"},
		{"open redirect", "开放重定向"},
		{"ssrf to rce", "SSRF → RCE 链"},
		{"cloud metadata", "云元数据服务"},
		{"169.254.169.254", "AWS/GCP 元数据"},
		{"metadata.google.internal", "GCP 元数据"},
		{"100.100.100.200", "阿里云元数据"},
		{"internal service", "内网服务探测"},
		{"service discovery", "服务发现"},
		{"gopher://", "Gopher 协议利用"},
		{"file://", "FILE 协议读取"},
		{"dict://", "DICT 协议利用"},
	}
	for _, kw := range ssrfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"SSRF高级: " + kw.hint}
		}
	}
	privateIPRe := regexp.MustCompile(`(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}`)
	if m := privateIPRe.FindString(fullText); m != "" {
		return []string{"SSRF目标: " + m}
	}
	return nil
}

// tryDOMXSS 检测 DOM 型 XSS 特征。
func tryDOMXSS(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	domKeywords := []struct {
		keyword string
		hint    string
	}{
		{"document.write", "document.write（XSS sink）"},
		{"innerhtml", "innerHTML（XSS sink）"},
		{"outerhtml", "outerHTML"},
		{"eval(", "eval() 执行"},
		{"settimeout", "setTimeout 字符串执行"},
		{"setinterval", "setInterval 字符串执行"},
		{"location.href", "location.href 重定向"},
		{"location.hash", "location.hash（DOM XSS 源）"},
		{"location.search", "location.search（DOM XSS 源）"},
		{"postmessage", "postMessage"},
		{"dom clobbering", "DOM 碰撞攻击"},
		{"mutation xss", "Mutation XSS"},
		{"trusted types", "Trusted Types 防护"},
	}
	for _, kw := range domKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"DOM XSS: " + kw.hint}
		}
	}
	return nil
}

// tryStoredXSS 检测存储型 XSS 特征。
func tryStoredXSS(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	sxssKeywords := []struct {
		keyword string
		hint    string
	}{
		{"stored xss", "存储型 XSS"},
		{"persistent xss", "持久型 XSS"},
		{"reflected xss", "反射型 XSS"},
		{"blind xss", "盲 XSS"},
		{"<script>", "Script 标签注入"},
		{"javascript:", "JavaScript 协议注入"},
		{"onerror", "onerror 事件处理器"},
		{"onload", "onload 事件处理器"},
		{"csp bypass", "CSP 绕过"},
		{"content security policy", "内容安全策略"},
		{"httponly", "HttpOnly Cookie 防护"},
	}
	for _, kw := range sxssKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"存储型XSS: " + kw.hint}
		}
	}
	return nil
}

// tryWebAssemblyReverse 检测 WebAssembly 逆向特征。
func tryWebAssemblyReverse(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wk := []struct{ k, h string }{
		{"wasm", "WebAssembly"}, {"webassembly", "WebAssembly"}, {"wat", "WAT格式"},
		{"wasmtime", "Wasmtime"}, {"wasmer", "Wasmer"}, {"emscripten", "Emscripten"},
	}
	for _, kw := range wk {
		if strings.Contains(lower, kw.k) {
			return []string{"WASM: " + kw.h}
		}
	}
	return nil
}

// tryWeb3Security 检测 Web3/智能合约安全特征。
func tryWeb3Security(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	web3Keywords := []struct {
		keyword string
		hint    string
	}{
		{"solidity", "Solidity 智能合约"},
		{"smart contract", "智能合约"},
		{"evm", "以太坊虚拟机"},
		{"ethereum", "以太坊"},
		{"erc20", "ERC-20 代币"},
		{"erc721", "ERC-721 NFT"},
		{"erc1155", "ERC-1155 多代币"},
		{"reentrancy", "重入攻击"},
		{"integer overflow", "整数溢出"},
		{"delegatecall", "Delegatecall 漏洞"},
		{"selfdestruct", "Selfdestruct 攻击"},
		{"tx.origin", "tx.origin 钓鱼"},
		{"flash loan", "闪电贷攻击"},
		{"frontrunning", "抢跑交易"},
		{"sandwich attack", "三明治攻击"},
		{"oracle manipulation", "预言机操纵"},
		{"rug pull", "Rug Pull"},
		{"honeypot", "蜜罐合约"},
		{"abi encoding", "ABI 编码"},
		{"calldata", "Calldata 注入"},
		{"proxy contract", "代理合约"},
		{"upgradeable", "可升级合约"},
		{"diamond pattern", "Diamond 模式"},
		{"mev", "MEV（最大可提取价值）"},
		{"cross-chain", "跨链安全"},
		{"bridge", "跨链桥安全"},
		{"l2 security", "L2 安全"},
		{"rollup", "Rollup"},
		{"zero knowledge proof", "零知识证明"},
		{"zk-snark", "zk-SNARK"},
		{"zk-stark", "zk-STARK"},
		{"plonk", "PLONK"},
		{"groth16", "Groth16"},
	}
	for _, kw := range web3Keywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Web3安全: " + kw.hint}
		}
	}
	return nil
}
