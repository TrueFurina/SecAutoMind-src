package handler

import (
	"fmt"
	"strings"
	"testing"

	"secautomind-ai/internal/config"
	"secautomind-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func TestRobotModeSwitch(t *testing.T) {
	h := NewRobotHandler(&config.Config{MultiAgent: config.MultiAgentConfig{Enabled: true}}, nil, nil, zap.NewNop())

	if got := h.cmdSwitchMode("lark", "user-1", "plan-execute"); !strings.Contains(got, "Plan-Execute") {
		t.Fatalf("unexpected switch response: %s", got)
	}
	if got := h.getAgentMode("lark", "user-1"); got != "plan_execute" {
		t.Fatalf("mode = %q, want plan_execute", got)
	}
	if got := h.cmdModes("lark", "user-1"); !strings.Contains(got, "当前模式: Plan-Execute") {
		t.Fatalf("unexpected modes response: %s", got)
	}
}

func TestRobotModeRejectsUnavailableMultiAgent(t *testing.T) {
	h := NewRobotHandler(&config.Config{}, nil, nil, zap.NewNop())

	if got := h.cmdSwitchMode("lark", "user-1", "deep"); !strings.Contains(got, "启用 Eino 多代理") {
		t.Fatalf("unexpected rejection: %s", got)
	}
	if got := h.getAgentMode("lark", "user-1"); got != "eino_single" {
		t.Fatalf("mode changed after rejection: %q", got)
	}
}

func TestParseRobotAgentModeRejectsUnknownMode(t *testing.T) {
	if mode, ok := parseRobotAgentMode("unknown"); ok || mode != "" {
		t.Fatalf("parseRobotAgentMode returned (%q, %v), want empty,false", mode, ok)
	}
}

func TestRobotStatusCommandPermission(t *testing.T) {
	for _, command := range []string{"状态", "status"} {
		permission, recognized := robotCommandPermission(command)
		if !recognized || permission != "chat:read" {
			t.Fatalf("command %q returned permission=%q recognized=%v", command, permission, recognized)
		}
	}
	for _, removed := range []string{"当前", "current"} {
		if _, recognized := robotCommandPermission(removed); recognized {
			t.Fatalf("removed command %q is still recognized", removed)
		}
	}
}

func TestRobotBestPracticeCommandPermissions(t *testing.T) {
	cases := map[string]string{
		"任务":       "chat:read",
		"task":     "chat:read",
		"重命名 新标题":  "chat:write",
		"rename x": "chat:write",
		"诊断":       "config:read",
		"doctor":   "config:read",
	}
	for command, want := range cases {
		permission, recognized := robotCommandPermission(command)
		if !recognized || permission != want {
			t.Fatalf("command %q returned permission=%q recognized=%v, want %q,true", command, permission, recognized, want)
		}
	}
}

func TestRobotConfirmationCanBeCancelled(t *testing.T) {
	h := NewRobotHandler(&config.Config{}, nil, nil, zap.NewNop())
	h.setPendingConfirmation("lark", "user-1", "delete_conversation", "conv-1")
	if got := h.cmdCancelConfirmation("lark", "user-1"); got != "已取消待确认操作。" {
		t.Fatalf("unexpected cancel response: %s", got)
	}
	if got := h.cmdConfirm("lark", "user-1"); !strings.Contains(got, "没有待确认操作") {
		t.Fatalf("confirmation survived cancellation: %s", got)
	}
}

func TestRobotDoctorSeparatesInternalToolsFromHTTPMCP(t *testing.T) {
	h := NewRobotHandler(&config.Config{
		Security: config.SecurityConfig{Tools: []config.ToolConfig{
			{Name: "enabled-tool", Enabled: true},
			{Name: "disabled-tool", Enabled: false},
		}},
		MCP: config.MCPConfig{Enabled: false},
	}, nil, nil, zap.NewNop())

	got := h.cmdDoctor()
	// 2026-10-04 口径修正：本断言原为「内置 MCP 工具: 1/2 个已启用」，而该措辞下的数字其实是
	// tools/ 目录的 YAML 声明数，与材料口径的「内置 MCP 工具」（= GetAllBuiltinTools 的 Go 内置工具）
	// 同名不同义，会让评审把「未部署 tools/」误读成「产品工具全坏/材料夸大」。
	// 本测试的原始意图（YAML 工具层要与 HTTP MCP 层分开陈述）保留，措辞对齐新口径。
	if !strings.Contains(got, "工具 YAML 声明: 1/2 个已启用") {
		t.Fatalf("YAML tool status missing: %s", got)
	}
	// 反向自检：Go 内置工具数不得被 YAML 工具数顶替（未部署 tools/ 时也必须报真值）。
	if !strings.Contains(got, fmt.Sprintf("Go 内置 MCP 工具: %d 个", len(builtin.GetAllBuiltinTools()))) {
		t.Fatalf("Go builtin tool count missing or aliased to YAML count: %s", got)
	}
	if !strings.Contains(got, "HTTP MCP 服务: 已关闭") {
		t.Fatalf("HTTP MCP status missing: %s", got)
	}
}
