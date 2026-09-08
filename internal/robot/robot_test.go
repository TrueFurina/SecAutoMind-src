package robot

import (
	"context"
	"testing"

	"secautomind-ai/internal/config"

	"go.uber.org/zap"
)

// ── 飞书适配器冒烟测试 ──────────────────────────────────

func TestStartLark_DisabledConfig(t *testing.T) {
	// 飞书未启用时 StartLark 应静默返回，不 panic
	cfg := config.RobotsConfig{
		Lark: config.RobotLarkConfig{
			Enabled: false,
		},
	}
	StartLark(context.Background(), cfg, nil, zap.NewNop())
	// 不 panic 即通过
}

func TestStartLark_MissingCredentials(t *testing.T) {
	// 飞书启用但缺凭证时应静默返回，不 panic
	cfg := config.RobotsConfig{
		Lark: config.RobotLarkConfig{
			Enabled: true,
		},
	}
	StartLark(context.Background(), cfg, nil, zap.NewNop())
	// 不 panic 即通过（AppID/AppSecret 为空会直接 return）
}

func TestResolveLarkUserID_NilEvent(t *testing.T) {
	// nil 事件应返回空字符串
	result := resolveLarkUserID(nil, false)
	if result != "" {
		t.Errorf("resolveLarkUserID(nil) = %q, want empty", result)
	}
}

func TestResolveLarkUserID_NilSender(t *testing.T) {
	// nil Sender 应返回空字符串
	// larkim.P2MessageReceiveV1 结构复杂，直接测 nil 输入
	result := resolveLarkUserID(nil, true)
	if result != "" {
		t.Errorf("resolveLarkUserID(nil, allowChatID=true) = %q, want empty", result)
	}
}

// ── 钉钉适配器冒烟测试 ──────────────────────────────────

func TestStartDing_DisabledConfig(t *testing.T) {
	// 钉钉未启用时 StartDing 应静默返回，不 panic
	cfg := config.RobotsConfig{
		Dingtalk: config.RobotDingtalkConfig{
			Enabled: false,
		},
	}
	StartDing(context.Background(), cfg, nil, zap.NewNop())
	// 不 panic 即通过
}

func TestStartDing_MissingCredentials(t *testing.T) {
	// 钉钉启用但缺凭证时应静默返回，不 panic
	cfg := config.RobotsConfig{
		Dingtalk: config.RobotDingtalkConfig{
			Enabled: true,
		},
	}
	StartDing(context.Background(), cfg, nil, zap.NewNop())
	// 不 panic 即通过（ClientID/ClientSecret 为空会直接 return）
}
