package config

import (
	"os"
	"strings"
	"testing"
)

func TestExpandSecretEnvExpandsEnvVar(t *testing.T) {
	os.Setenv("SECAUTOTEST_KEY", "sk-env-real-key-1234567890")
	defer os.Unsetenv("SECAUTOTEST_KEY")

	cfg := &Config{}
	cfg.OpenAI.APIKey = "${SECAUTOTEST_KEY}"
	cfg.OpenAI.BaseURL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

	ExpandSecretEnv(cfg)

	if cfg.OpenAI.APIKey != "sk-env-real-key-1234567890" {
		t.Fatalf("ExpandSecretEnv 未展开 ${VAR}: got %q", cfg.OpenAI.APIKey)
	}
}

func TestExpandSecretEnvDefaultValue(t *testing.T) {
	os.Unsetenv("SECAUTOTEST_MISSING")

	cfg := &Config{}
	cfg.AI.Channels = map[string]AIChannelConfig{
		"qwen-max": {APIKey: "${SECAUTOTEST_MISSING:-sk-fallback-default-12345}", BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1"},
	}

	ExpandSecretEnv(cfg)

	got := cfg.AI.Channels["qwen-max"].APIKey
	if got != "sk-fallback-default-12345" {
		t.Fatalf("${VAR:-default} 未生效: got %q", got)
	}
}

func TestResolveAPIKeyFromEnvFallsBack(t *testing.T) {
	os.Setenv("DASHSCOPE_API_KEY", "sk-dashscope-real-1234567890")
	defer os.Unsetenv("DASHSCOPE_API_KEY")

	// 占位符 → 应回退到环境变量
	got := ResolveAPIKeyFromEnv("sk-xxxxxxx", "https://dashscope.aliyuncs.com/compatible-mode/v1", "")
	if got != "sk-dashscope-real-1234567890" {
		t.Fatalf("占位符未回退环境变量: got %q", got)
	}

	// 空字符串 → 也应回退
	got2 := ResolveAPIKeyFromEnv("", "https://dashscope.aliyuncs.com/compatible-mode/v1", "")
	if got2 != "sk-dashscope-real-1234567890" {
		t.Fatalf("空 key 未回退环境变量: got %q", got2)
	}

	// 真实 key（非占位）→ 保持原样不覆盖
	got3 := ResolveAPIKeyFromEnv("sk-user-typed-real-key-999", "https://dashscope.aliyuncs.com/compatible-mode/v1", "")
	if got3 != "sk-user-typed-real-key-999" {
		t.Fatalf("真实 key 不应被覆盖: got %q", got3)
	}
}

func TestResolveAllAPIKeysFromEnvChannelsAndKnowledge(t *testing.T) {
	os.Setenv("DASHSCOPE_API_KEY", "sk-dashscope-real-1234567890")
	os.Setenv("DEEPSEEK_API_KEY", "sk-deepseek-real-0987654321")
	defer os.Unsetenv("DASHSCOPE_API_KEY")
	defer os.Unsetenv("DEEPSEEK_API_KEY")

	cfg := &Config{}
	cfg.OpenAI.APIKey = "sk-xxxxxxx"
	cfg.OpenAI.BaseURL = "https://api.deepseek.com/v1"
	cfg.AI.Channels = map[string]AIChannelConfig{
		"qwen-max": {APIKey: "", BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1"},
	}
	cfg.Knowledge.Embedding.APIKey = "sk-xxxxxxx"
	cfg.Knowledge.Embedding.BaseURL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

	ResolveAllAPIKeysFromEnv(cfg)

	if !strings.HasPrefix(cfg.OpenAI.APIKey, "sk-deepseek") {
		t.Fatalf("OpenAI deepseek 回退失败: got %q", cfg.OpenAI.APIKey)
	}
	if !strings.HasPrefix(cfg.AI.Channels["qwen-max"].APIKey, "sk-dashscope") {
		t.Fatalf("qwen-max 通道回退失败: got %q", cfg.AI.Channels["qwen-max"].APIKey)
	}
	if !strings.HasPrefix(cfg.Knowledge.Embedding.APIKey, "sk-dashscope") {
		t.Fatalf("知识库 embedding 回退失败: got %q", cfg.Knowledge.Embedding.APIKey)
	}
}
