package config

import (
	"strings"
	"testing"
)

// ValidateAIGateway 回归（2026-11-09 拍板接线）。
// 判据源在 internal/gatewaycompliance（与 runner L3 闸门同口径），这里锁的是
// server 侧装配语义：默认零影响 / 配置写错 fail-closed / required 两档定级 /
// 回环本地网关豁免。

func chanMap(pairs ...string) map[string]AIChannelConfig {
	m := map[string]AIChannelConfig{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = AIChannelConfig{BaseURL: pairs[i+1]}
	}
	return m
}

func TestAIGatewayDisabledIsNoop(t *testing.T) {
	ai := AIConfig{Channels: chanMap("deep", "https://api.deepseek.com/v1")}
	w, err := ValidateAIGateway(ai)
	if err != nil || w != nil {
		t.Fatalf("未配置网关必须零行为，实际 warns=%v err=%v", w, err)
	}
	ai.Gateway.Enabled = false
	ai.Gateway.BaseURL = "https://gw.example.com/v1"
	if w, err := ValidateAIGateway(ai); err != nil || w != nil {
		t.Fatalf("enabled=false 时必须零行为，实际 warns=%v err=%v", w, err)
	}
}

func TestAIGatewayEnabledBadURLFailClosed(t *testing.T) {
	// 配置写错即 fail-closed（第七条同风格）：不许静默当作没开
	ai := AIConfig{
		Gateway:  AIGatewayConfig{Enabled: true, BaseURL: "gw.example.com/v1"},
		Channels: chanMap("deep", "https://gw.example.com/v1"),
	}
	_, err := ValidateAIGateway(ai)
	if err == nil || !strings.Contains(err.Error(), "拒绝启动") {
		t.Fatalf("enabled=true 但 base_url 无效必须 fatal，实际 err=%v", err)
	}
}

func TestAIGatewayRequiredBlocksDirectChannel(t *testing.T) {
	ai := AIConfig{
		Gateway: AIGatewayConfig{Enabled: true, Required: true, BaseURL: "https://gw.example.com/v1"},
		Channels: chanMap(
			"qwen", "https://gw.example.com/compatible-mode/v1", // 同源放行
			"deep", "https://api.deepseek.com/v1", // 公网直连违规
		),
	}
	_, err := ValidateAIGateway(ai)
	if err == nil {
		t.Fatal("required=true 且有通道直连必须 fatal")
	}
	if !strings.Contains(err.Error(), "deep") || !strings.Contains(err.Error(), "api.deepseek.com") {
		t.Fatalf("fatal 必须点名违规通道可定位，实际 err=%v", err)
	}
	// 反向对照：同源 + 回环全合规 → 放行
	ai2 := AIConfig{
		Gateway: AIGatewayConfig{Enabled: true, Required: true, BaseURL: "https://gw.example.com/v1"},
		Channels: chanMap(
			"qwen", "https://gw.example.com/compatible-mode/v1",
			"ofm", "http://127.0.0.1:18899/v1", // 2026-11-09 拍板：回环本地网关豁免
		),
	}
	if _, err := ValidateAIGateway(ai2); err != nil {
		t.Fatalf("网关同源+回环豁免必须放行，实际 err=%v", err)
	}
}

func TestAIGatewayNotRequiredDowngradesToWarn(t *testing.T) {
	ai := AIConfig{
		Gateway:  AIGatewayConfig{Enabled: true, Required: false, BaseURL: "https://gw.example.com/v1"},
		Channels: chanMap("deep", "https://api.deepseek.com/v1"),
	}
	w, err := ValidateAIGateway(ai)
	if err != nil {
		t.Fatalf("required=false 不得 fatal（文档语义：告警并降级直连），实际 err=%v", err)
	}
	if len(w) != 1 || !strings.Contains(w[0], "deep") {
		t.Fatalf("必须恰有一条点名违规通道的告警，实际 warns=%v", w)
	}
}
