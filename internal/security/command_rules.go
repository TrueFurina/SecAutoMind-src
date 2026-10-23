package security

import (
	_ "embed"
	"regexp"
	"strconv"
	"sync"

	"gopkg.in/yaml.v3"
)

// command_rules.yaml 是 isDangerousShellCommand 的唯一数据源：规则从 Go 代码
// 外置为可评审的数据，改拦截口径不再需要动 executor.go 的逻辑。
//
// 之所以用 go:embed 而不是从数据根加载：这是**安全边界**，运行时读外部文件会引入
// "文件被改写即静默削弱防护" 的风险面，且需要新增一个配置项（违背仓库 AGENTS.md
// 的 Simplicity first）。编译期嵌入使规则与二进制同生同死，改规则必须走发版。
// 若将来确需用户自定义，再做数据根覆盖（优先级高于嵌入副本），并配套校验与告警。

//go:embed command_rules.yaml
var commandRulesYAML []byte

// commandRule 对应 command_rules.yaml 中的单条规则。
type commandRule struct {
	// Pattern 为 Go regexp（RE2）正则。
	Pattern string `yaml:"pattern"`
	// Reason 命中后返回给调用方的原因文案（最终出现在拦截提示里）。
	Reason string `yaml:"reason"`
	// UnlessContains 非空时，命令包含该子串则跳过本规则。
	UnlessContains string `yaml:"unless_contains"`
}

// commandRuleFile 是 command_rules.yaml 的顶层结构。
type commandRuleFile struct {
	Rules []commandRule `yaml:"rules"`
}

// compiledCommandRule 是编译后的规则；re 永不为 nil（加载失败会直接 panic，
// 因为嵌入文件损坏等价于构建产物损坏，不应带病运行）。
type compiledCommandRule struct {
	re             *regexp.Regexp
	reason         string
	unlessContains string
}

var (
	commandRulesOnce sync.Once
	commandRules     []compiledCommandRule
)

// loadCommandRules 解析并编译嵌入的规则文件。线程安全，结果缓存。
//
// 失败即 panic：嵌入 YAML 损坏或正则无法编译都属于构建期缺陷（文件随源码走 CI），
// 静默返回空规则集会让保底拦截形同虚设——安全控件必须 fail-closed。
func loadCommandRules() []compiledCommandRule {
	commandRulesOnce.Do(func() {
		var file commandRuleFile
		if err := yaml.Unmarshal(commandRulesYAML, &file); err != nil {
			panic("security: 解析 command_rules.yaml 失败: " + err.Error())
		}
		if len(file.Rules) == 0 {
			panic("security: command_rules.yaml 未定义任何规则")
		}
		rules := make([]compiledCommandRule, 0, len(file.Rules))
		for i, r := range file.Rules {
			no := strconv.Itoa(i + 1)
			if r.Pattern == "" {
				panic("security: command_rules.yaml 第 " + no + " 条规则缺少 pattern")
			}
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				panic("security: command_rules.yaml 第 " + no + " 条规则正则无效: " + err.Error())
			}
			if r.Reason == "" {
				panic("security: command_rules.yaml 第 " + no + " 条规则缺少 reason")
			}
			rules = append(rules, compiledCommandRule{
				re:             re,
				reason:         r.Reason,
				unlessContains: r.UnlessContains,
			})
		}
		commandRules = rules
	})
	return commandRules
}
