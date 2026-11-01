package runnerl3

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/cloudwego/eino/schema"
)

// ── P0-3 MCP 硬约束层（2026-10-26）──────────────────────────────────────────
//
// 计划依据（docs/zh-CN/competition-2026/求解能力深化计划_20261023.md L137-142）：
//   「CTF 工具调用过 schema 强校验 + 环境事实源（文件/进程/连接状态以工具返回为准，
//     禁止 LLM 声称"已读取/已连接"而无对应工具记录）」
//   实证：STRIATUM-CTF 靠这套组合拿下真实多队 CTF 第一；D-CIPHER VI-B 日志显示
//   **幻觉文件/函数/服务端是工程失败主因**（失败模式 ⑨⑪）。
//   验收：LLM 输出引用不存在的文件路径时，编排层必须**打回**而非放行。
//
// 本文件两件事：
//   ① validateToolCall —— 工具名/必填参数/未知参数强校验，非法调用直接变成工具错误回给模型，
//      绝不"猜着执行"（旧行为：只判缺字段，未知参数静默忽略 → 模型乱加参数无从发现）。
//   ② factLedger + extractUnbackedFileClaims —— 环境事实源：只认工具**真实返回**的路径；
//      模型声称读过/打开/下载了某文件却没有对应工具记录 → 打回（fail-closed）。

// toolSchema 单个工具的 schema 约束。
type toolSchema struct {
	required []string // 必填参数名
	optional []string // 允许出现的可选参数名
}

// toolSchemas 工具白名单 + schema。未登记的工具一律拒绝。
var toolSchemas = map[string]toolSchema{
	"execute_python": {
		required: []string{"skill_name"},
		optional: []string{"params"},
	},
	"read_attachment": {
		required: []string{"attachment_url"},
	},
	// P1-2 有状态会话：code 必填，reset 选填（清空变量但保留 cwd）
	"python_session": {
		required: []string{"code"},
		optional: []string{"reset"},
	},
}

// validateToolCall 强校验一次工具调用。返回非空错误 = 拒绝执行。
//
// 判据（每条都可测）：
//  1. 工具名必须在白名单内（模型发明的工具名不放行）；
//  2. 必填参数必须存在且为非空字符串（空串 = 没给）；
//  3. 出现 schema 未登记的参数 → 拒绝（模型乱加参数是真实现象，
//     旧实现静默忽略，等于鼓励幻觉参数且无从留痕）。
func validateToolCall(name string, args map[string]any) error {
	sch, ok := toolSchemas[name]
	if !ok {
		return fmt.Errorf("未知工具 %q（可用：%s）", name, allowedToolNames())
	}
	for _, k := range sch.required {
		v, ok := args[k]
		if !ok {
			return fmt.Errorf("缺少必填参数 %q", k)
		}
		s, isStr := v.(string)
		if !isStr || strings.TrimSpace(s) == "" {
			return fmt.Errorf("参数 %q 必须是非空字符串", k)
		}
	}
	allowed := map[string]bool{}
	for _, k := range sch.required {
		allowed[k] = true
	}
	for _, k := range sch.optional {
		allowed[k] = true
	}
	unknown := make([]string, 0, 2)
	for k := range args {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("参数 %q 不在工具 schema 内（允许：%s）",
			strings.Join(unknown, ","), strings.Join(allowedKeys(sch), ","))
	}
	return nil
}

func allowedKeys(sch toolSchema) []string {
	out := make([]string, 0, len(sch.required)+len(sch.optional))
	out = append(out, sch.required...)
	out = append(out, sch.optional...)
	sort.Strings(out)
	return out
}

func allowedToolNames() string {
	names := make([]string, 0, len(toolSchemas))
	for n := range toolSchemas {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// ── 环境事实源 ────────────────────────────────────────────────────────────

// factLedger 记录本轮解题中**由工具真实返回**的环境事实。
// 唯一写入口是 executeTool（工具成功返回时解析），模型说什么都不算数。
type factLedger struct {
	mu    sync.Mutex
	files map[string]bool
}

func newFactLedger() *factLedger {
	return &factLedger{files: map[string]bool{}}
}

func (l *factLedger) addFile(path string) {
	p := strings.TrimSpace(path)
	if p == "" {
		return
	}
	l.mu.Lock()
	l.files[p] = true
	l.mu.Unlock()
}

func (l *factLedger) has(path string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.files[strings.TrimSpace(path)]
}

func (l *factLedger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.files)
}

// attPathRe 从 read_attachment 的返回里抽真实落盘路径（工具契约：
// "附件下载成功:\n路径: <p>"）。事实源只认这一条 —— 不猜文件名、不信模型复述。
var attPathRe = regexp.MustCompile(`(?m)^路径:\s*(.+?)\s*$`)

// recordFactsFromToolResult 从工具成功返回中抽取环境事实。
// 只处理有明确契约的格式；抽不到就诚实地不记（宁可少记，不可伪造事实）。
func (l *factLedger) recordFactsFromToolResult(toolName, result string) {
	if l == nil {
		return
	}
	switch toolName {
	case "read_attachment":
		if m := attPathRe.FindStringSubmatch(result); len(m) == 2 {
			l.addFile(m[1])
		}
	}
}

// claimVerbRe 命中"声称访问过"的动词（中英双语，覆盖模型常见措辞）。
var claimVerbRe = regexp.MustCompile(`(?i)(读取|打开|下载|保存|生成|解压|写入|查看|载入|加载|cat|open|read|download|save|wrote|wrote to|load|extract|unzip)`)

// pathTokenRe 路径形 token，要求 ≥2 段（/a/b 形态）；单段（/tmp、/root）不参与判定。
var pathTokenRe = regexp.MustCompile(`(?:/[\w.\-]+){2,}`)

// systemPathRoots 系统目录前缀白名单（不参与幻觉判定）。
// 为什么必须排除：CTF 的 flag 正文里出现 /etc/passwd、/usr/bin/xx 这类系统路径
// 是**常见且合法**的（题目本身就常拿它们当梗），判成幻觉会误杀真答案。
// 而幻觉文件几乎总是落在 /tmp、/home、工作目录等"临时/数据"位置 —— 那才是我们要抓的。
var systemPathRoots = map[string]bool{
	"etc": true, "usr": true, "bin": true, "sbin": true, "var": true,
	"proc": true, "sys": true, "dev": true, "lib": true, "lib64": true,
	"opt": true, "boot": true, "srv": true, "run": true, "mnt": true, "media": true,
}

// isSystemPath 判定路径是否落在系统目录下（是 → 不做幻觉判定）。
func isSystemPath(p string) bool {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) == 0 {
		return false
	}
	return systemPathRoots[strings.ToLower(parts[0])]
}

// extractUnbackedFileClaims 找出模型文本里"声称访问过、但工具记录中没有"的文件路径。
//
// 判据：同一行内既有声称动词又有 ≥2 段路径，且该路径不在 factLedger 中 → 视为幻觉。
// 返回命中的路径列表（空 = 无幻觉）。
func extractUnbackedFileClaims(text string, l *factLedger) []string {
	if l == nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if !claimVerbRe.MatchString(line) {
			continue
		}
		for _, m := range pathTokenRe.FindAllString(line, -1) {
			p := strings.TrimRight(m, ".,;:!?)]}'\"")
			if l.has(p) || isSystemPath(p) {
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

// toolCallHint 给模型的打回说明（P0-3 ① 的回执文本由 executeTool 生成）。
func toolCallRejectText(name string, err error) string {
	return fmt.Sprintf("[工具 %s 参数校验失败] %v", name, err)
}

// ensureSchema 保证接口的编译期约束（防止将来新增工具忘记登记 schema）。
var _ = func(tc schema.ToolCall) error { return validateToolCall(tc.Function.Name, nil) }

// ── execute_python 的第二道围栏（2026-11-01）────────────────────────────────
//
// `python_session` 的路径围栏只覆盖会话执行；`execute_python` 是**另一个进程**
// （cmd/runner 的 pySkillRunner 起子进程跑 skill 模块），完全不吃那条围栏。
// 于是它构成两条绕过路径，且都不需要模型"攻破"任何东西，只是正常调用参数：
//
//  ① **代码注入**：skill_name 被 `fmt.Sprintf` 拼进 Python 源码的
//     `import %s as s`（见 cmd/runner/pyskill_bridge.go execSkillSubprocess）。
//     旧实现只校验"非空字符串"⇒ 名字里带换行即可注入任意 Python：
//     `"os as s\nprint(open('/data/answers/…').read())\nsys.exit(0)\nimport os"`
//     进程以 0 退出 ⇒ 输出被当作"skill 成功结果"原样返回给模型。
//     性质与 `python_session` 读到真值文件完全同级（伪造分数通道），
//     区别只是入口换了。
//  ② **参数夹带路径**：RunSkillRich 把模型给的 params 原样并进 skill 入参，
//     而 zip_crack / image_steg / pcap_analyze 这类 skill 就是按 `path` 读文件的
//     ⇒ `params={"path":"/…/real_benchmark.json"}` 等于让 skill 替模型越权读文件。
//
// 对应两道：skill_name 必须是**合法 Python 标识符**（结构上不可能拼出代码）；
// params 里出现的绝对路径过**同一条 pathFence**（与 python_session 同口径同白名单）。

// pythonIdentRe 合法 Python 标识符（足以承载 skill 模块名：全是小写+下划线）。
var pythonIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateSkillName 拒掉一切"能拼出代码"的技能名。
//
// 为什么用结构校验而不是白名单枚举：工具描述里给模型的名字（angr_decompile、
// zip_crack、ctf_sage_t1_coppersmith…）与 skills/ 里的模块文件名并非一一对应，
// 硬枚举白名单会误杀文档里承诺可用的别名（那是功能回归）。
// 结构校验只砍掉"根本不是标识符"的输入，合法别名一律放行；拼错的模块名
// 会在 import 阶段自然失败（ModuleNotFoundError → 工具错误步），信息也够模型自纠。
func validateSkillName(name string) error {
	if pythonIdentRe.MatchString(name) {
		return nil
	}
	return fmt.Errorf("skill_name 必须是 Python 标识符（字母/数字/下划线，不以数字开头），拒绝 %q", truncate(name, 60))
}

// paramPathViolations 扫描模型透传的 params 里的越界绝对路径。
//
// 与 python_session 用**同一套** pathFence（同白名单：本题工作目录 + 附件收件箱 +
// 只读系统路径；同 deny 表：答案目录/密钥/版本库），避免"两个入口两套口径"。
func paramPathViolations(extra map[string]any) []string {
	if len(extra) == 0 {
		return nil
	}
	fence := newPathFence(fenceWorkdir(), attachmentInboxFenceRoot())
	if fence == nil || !fence.enabled {
		return nil
	}
	var sb strings.Builder
	collectParamStrings(extra, &sb)
	if sb.Len() == 0 {
		return nil
	}
	return fence.violations(sb.String())
}

// collectParamStrings 递归收集 params 里的所有字符串值（含 key，防"路径藏在键里"）。
// 每项单独一行：absPathRe 的左边界要求空白/引号/等号等，换行正好满足。
func collectParamStrings(v any, sb *strings.Builder) {
	switch t := v.(type) {
	case string:
		sb.WriteString(t)
		sb.WriteString("\n")
	case map[string]any:
		for k, vv := range t {
			sb.WriteString(k)
			sb.WriteString("\n")
			collectParamStrings(vv, sb)
		}
	case []any:
		for _, vv := range t {
			collectParamStrings(vv, sb)
		}
	}
}
