package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestEmbeddedDefaultConfigHitlApproval 锁定内置自举模板的 HITL 口径。
//
// 背景（2026-09-13 深度复检发现）：
//
//	internal/config/default_config.yaml 是 exe 的 go:embed **自举模板** —— 在空目录双击
//	exe 时据此生成 config.yaml。它曾写死 `default_mode: off`，于是"开箱即得"的默认把
//	HITL 关掉，与赛题终审 human-in-the-loop 硬需求相悖，也与另外三份配置
//	（config.example / config / config.share，均为 approval）口径漂移。
//
// 本测试同时锚定四份配置同口径，防止再次漂移。
func TestEmbeddedDefaultConfigHitlApproval(t *testing.T) {
	if len(embeddedDefaultConfig) == 0 {
		t.Fatal("embeddedDefaultConfig 为空：go:embed default_config.yaml 失败")
	}
	assertHitlApproval(t, "internal/config/default_config.yaml（内置自举模板）", embeddedDefaultConfig)

	// 同仓另外两份随包分发的配置必须同口径（本包目录 → 仓库根）
	for _, name := range []string{"config.example.yaml", "config.share.yaml"} {
		p := filepath.Join("..", "..", name)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", p, err)
		}
		assertHitlApproval(t, name, b)
	}
}

func assertHitlApproval(t *testing.T, name string, raw []byte) {
	t.Helper()
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("%s 解析失败: %v", name, err)
	}
	if got := c.Hitl.EffectiveDefaultMode(); got != "approval" {
		t.Fatalf("%s: hitl.default_mode 生效值 = %q，期望 \"approval\"（赛题 human-in-the-loop 硬需求；自举生成的 config.yaml 会沿用此值）",
			name, got)
	}
}
