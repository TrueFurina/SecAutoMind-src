package handler

import (
	"fmt"
	"strings"
	"testing"

	"secautomind-ai/internal/config"
	"secautomind-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func newDoctorTestHandler(tools []config.ToolConfig) *RobotHandler {
	return &RobotHandler{
		config: &config.Config{
			Security: config.SecurityConfig{Tools: tools},
		},
		logger: zap.NewNop(),
	}
}

// TestCmdDoctor_SeparatesGoBuiltinFromYamlTools 锁死 2026-10-04 修正的口径分层。
//
// 背景：`诊断` 原先把 config.Security.Tools（tools/ 目录的 YAML 声明）标成「内置 MCP 工具」，
// 而材料/证据包口径里的「内置 MCP 工具」是 builtin.GetAllBuiltinTools()（编译进二进制的 Go 工具）。
// 同名不同义 → 未部署 tools/ 时输出「内置 MCP 工具: 0/0」，与材料的「内置 MCP 工具 52」直接冲突。
// 本测试要求：Go 内置工具数必须来自 GetAllBuiltinTools()，且 YAML 工具数不得再被叫做「内置 MCP 工具」。
func TestCmdDoctor_SeparatesGoBuiltinFromYamlTools(t *testing.T) {
	h := newDoctorTestHandler(nil)
	out := h.cmdDoctor()

	wantBuiltin := len(builtin.GetAllBuiltinTools())
	if wantBuiltin == 0 {
		t.Fatal("GetAllBuiltinTools() 返回空，无法验证口径分层")
	}
	if !strings.Contains(out, fmt.Sprintf("Go 内置 MCP 工具: %d 个", wantBuiltin)) {
		t.Errorf("诊断未按 GetAllBuiltinTools() 报告 Go 内置工具数（期望 %d）:\n%s", wantBuiltin, out)
	}
	// 旧误导措辞必须消失：不得再把 YAML 工具标成「内置 MCP 工具: N/M」。
	if strings.Contains(out, "内置 MCP 工具: ") && !strings.Contains(out, "Go 内置 MCP 工具: ") {
		t.Errorf("诊断仍在用误导措辞「内置 MCP 工具: N/M」:\n%s", out)
	}
	if !strings.Contains(out, "工具 YAML 声明: 0/0 个已启用") {
		t.Errorf("诊断未标注 YAML 工具层的 0/0 及其含义:\n%s", out)
	}
}

// TestCmdDoctor_GoBuiltinCountIndependentOfYamlTools 锁死：Go 内置工具数不随 YAML 工具数量波动。
// 这是本次修正的核心——两个来源必须独立，不能再互相顶替。
func TestCmdDoctor_GoBuiltinCountIndependentOfYamlTools(t *testing.T) {
	wantBuiltin := len(builtin.GetAllBuiltinTools())

	for _, tc := range []struct {
		name  string
		tools []config.ToolConfig
	}{
		{"未部署 tools/（线上真实状态）", nil},
		{"部署 3 个且全启用", []config.ToolConfig{
			{Enabled: true}, {Enabled: true}, {Enabled: true},
		}},
		{"部署 3 个仅 1 个启用", []config.ToolConfig{
			{Enabled: true}, {Enabled: false}, {Enabled: false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := newDoctorTestHandler(tc.tools).cmdDoctor()
			if !strings.Contains(out, fmt.Sprintf("Go 内置 MCP 工具: %d 个", wantBuiltin)) {
				t.Errorf("Go 内置工具数被 YAML 工具数影响（应恒为 %d）:\n%s", wantBuiltin, out)
			}
		})
	}
}

// TestCmdDoctor_YamlEnabledCountIsAccurate 锁死 YAML 层 enabled 计数正确。
func TestCmdDoctor_YamlEnabledCountIsAccurate(t *testing.T) {
	out := newDoctorTestHandler([]config.ToolConfig{
		{Enabled: true}, {Enabled: true}, {Enabled: false},
	}).cmdDoctor()
	if !strings.Contains(out, "工具 YAML 声明: 2/3 个已启用") {
		t.Errorf("YAML 工具启用计数错误（期望 2/3）:\n%s", out)
	}
}

// TestCmdDoctor_ExplainsUndeployedYamlToolsDir 锁死诚实性：0/0 必须自带解释，
// 避免评审只看到「0/0」就判定产品配置损坏或材料夸大。
func TestCmdDoctor_ExplainsUndeployedYamlToolsDir(t *testing.T) {
	out := newDoctorTestHandler(nil).cmdDoctor()
	if !strings.Contains(out, "未部署时为 0/0") {
		t.Errorf("诊断未解释 0/0 的成因，评审无法区分「未部署」与「坏了」:\n%s", out)
	}
}
