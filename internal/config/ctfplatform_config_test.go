package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ── CTF 平台抗打击治理配置面（总纲 §2.4）──────────────────────────────
//
// 本文件守三件事：
//   1. **默认开**：段缺失 / 字段缺失都必须解析成「启用」，而非零值 false；
//   2. **可配**：YAML 标签真的接上了（总纲曾判「config.share.yaml 零命中」，
//      即字段存在但没人能通过配置改到 → 必须由 YAML 解析回归证明接上了）；
//   3. **一键回退**：显式 false 与 env 都能关，且 env 优先、非法 env 不误关。

// 清理可能干扰断言的进程环境变量（避免本机 shell 残留导致测试结果随环境漂移）。
func clearAntiBlockEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvAntiBlock, "")
}

func TestCTFPlatformAntiBlockDefaultsOn(t *testing.T) {
	clearAntiBlockEnv(t)

	var zero CTFPlatformConfig
	if !zero.AntiBlockEnabled() {
		t.Error("字段全缺失时必须默认「开」——否则「默认开」是假的")
	}

	// 连整个 Config 都是零值（等价于旧版 config.yaml 完全没有本段）
	var c Config
	if !c.CTFPlatform.AntiBlockEnabled() {
		t.Error("旧配置（无 ctf_platform 段）必须默认「开」，不能因升级静默关掉治理")
	}
}

func TestCTFPlatformAntiBlockYAMLExplicitOff(t *testing.T) {
	clearAntiBlockEnv(t)

	var c Config
	yml := "ctf_platform:\n  enabled: false\n"
	if err := yaml.Unmarshal([]byte(yml), &c); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	if c.CTFPlatform.Enabled == nil {
		t.Fatal("enabled 指针未解析——说明 YAML 标签没接上")
	}
	if c.CTFPlatform.AntiBlockEnabled() {
		t.Error("enabled: false 应解析为回退态")
	}

	// 对照组：显式 true
	var c2 Config
	if err := yaml.Unmarshal([]byte("ctf_platform:\n  enabled: true\n"), &c2); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	if !c2.CTFPlatform.AntiBlockEnabled() {
		t.Error("enabled: true 应为启用态")
	}
}

func TestCTFPlatformAntiBlockEnvOverridesYAML(t *testing.T) {
	// env=0 覆盖 YAML 的 true
	t.Setenv(EnvAntiBlock, "0")
	var c Config
	if err := yaml.Unmarshal([]byte("ctf_platform:\n  enabled: true\n"), &c); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	if c.CTFPlatform.AntiBlockEnabled() {
		t.Error("CTF_AGENT_ANTI_BLOCK=0 应覆盖 YAML enabled: true")
	}

	// env=1 覆盖 YAML 的 false
	t.Setenv(EnvAntiBlock, "1")
	var c2 Config
	if err := yaml.Unmarshal([]byte("ctf_platform:\n  enabled: false\n"), &c2); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	if !c2.CTFPlatform.AntiBlockEnabled() {
		t.Error("CTF_AGENT_ANTI_BLOCK=1 应覆盖 YAML enabled: false")
	}
}

// 非法 env 值不得被当成 false —— 把治理关掉是最坏的一种「容错」。
func TestCTFPlatformAntiBlockInvalidEnvFallsBackToYAML(t *testing.T) {
	t.Setenv(EnvAntiBlock, "yes-please")

	var c Config
	if err := yaml.Unmarshal([]byte("ctf_platform:\n  enabled: false\n"), &c); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	if c.CTFPlatform.AntiBlockEnabled() {
		t.Error("非法 env 应回落 YAML（此处为 false），而不是被当作 true")
	}

	var c2 Config
	if err := yaml.Unmarshal([]byte("ctf_platform:\n  enabled: true\n"), &c2); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	if !c2.CTFPlatform.AntiBlockEnabled() {
		t.Error("非法 env 应回落 YAML（此处为 true），而不是被当作 false 误关治理")
	}
}

func TestCTFPlatformKnobsYAML(t *testing.T) {
	clearAntiBlockEnv(t)

	var c Config
	yml := `ctf_platform:
  enabled: true
  max_retries: 7
  retry_backoff_seconds: 2.5
  waf_timeout_seconds: 45
  list_cache_ttl_seconds: 0
`
	if err := yaml.Unmarshal([]byte(yml), &c); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	cp := c.CTFPlatform

	if got := cp.MaxRetriesEffective(); got != 7 {
		t.Errorf("max_retries 应为 7，实际 %d", got)
	}
	if got := cp.RetryBackoff(); got != 2500*time.Millisecond {
		t.Errorf("retry_backoff_seconds 应为 2.5s，实际 %v", got)
	}
	if got := cp.WAFTimeout(); got != 45*time.Second {
		t.Errorf("waf_timeout_seconds 应为 45s，实际 %v", got)
	}
	ttl := cp.ListCacheTTL()
	if ttl == nil {
		t.Fatal("list_cache_ttl_seconds 显式填 0 时应返回非 nil 指针（= 关闭缓存）")
	}
	if *ttl != 0 {
		t.Errorf("list_cache_ttl_seconds: 0 应表示关闭缓存，实际 %v", *ttl)
	}
}

// 未配置的旋钮必须回落「包内默认」，不能被误解析成 0 / 关闭。
func TestCTFPlatformKnobsUnsetFallBackToPackageDefaults(t *testing.T) {
	clearAntiBlockEnv(t)

	var cp CTFPlatformConfig
	if got := cp.MaxRetriesEffective(); got != 0 {
		t.Errorf("未配置 max_retries 应返回 0（交包内默认 5 兜底），实际 %d", got)
	}
	if got := cp.RetryBackoff(); got != 0 {
		t.Errorf("未配置 retry_backoff 应返回 0（交包内默认 2s 兜底），实际 %v", got)
	}
	if got := cp.WAFTimeout(); got != 0 {
		t.Errorf("未配置 waf_timeout 应返回 0（交包内默认 300s 兜底），实际 %v", got)
	}
	if ttl := cp.ListCacheTTL(); ttl != nil {
		t.Errorf("未配置 list_cache_ttl 应返回 nil（沿用包内默认 10s），实际 %v", *ttl)
	}
}

// 出厂默认配置必须自带本段且为启用态 —— 证明「默认开」是随产物发出去的事实，而非口诀。
func TestEmbeddedDefaultConfigShipsCTFPlatformEnabled(t *testing.T) {
	clearAntiBlockEnv(t)

	var c Config
	if err := yaml.Unmarshal(embeddedDefaultConfig, &c); err != nil {
		t.Fatalf("内置默认配置解析失败: %v", err)
	}
	if c.CTFPlatform.Enabled == nil {
		t.Fatal("内置 default_config.yaml 未包含 ctf_platform.enabled —— 默认开无法落地")
	}
	if !c.CTFPlatform.AntiBlockEnabled() {
		t.Error("内置默认配置的 ctf_platform.enabled 应为 true")
	}
}
