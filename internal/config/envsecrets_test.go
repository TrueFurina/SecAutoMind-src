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

func TestResolveRobotSecretsFromEnv(t *testing.T) {
	os.Setenv("FEISHU_APP_ID", "cli_test_app_id_123")
	os.Setenv("FEISHU_APP_SECRET", "feishu-secret-abcdef123456")
	os.Setenv("TELEGRAM_BOT_TOKEN", "123456:ABC-DEF-telegram-token")
	os.Setenv("DINGTALK_APP_KEY", "ding-client-id-xyz")
	os.Setenv("DINGTALK_APP_SECRET", "ding-secret-xyz")
	defer os.Unsetenv("FEISHU_APP_ID")
	defer os.Unsetenv("FEISHU_APP_SECRET")
	defer os.Unsetenv("TELEGRAM_BOT_TOKEN")
	defer os.Unsetenv("DINGTALK_APP_KEY")
	defer os.Unsetenv("DINGTALK_APP_SECRET")

	cfg := &Config{}
	cfg.Robots.Lark.AppID = ""
	cfg.Robots.Lark.AppSecret = "sk-xxxxxxx" // 占位符 → 应回退
	cfg.Robots.Telegram.BotToken = ""
	cfg.Robots.Dingtalk.ClientID = "${DINGTALK_APP_KEY}" // 显式 ${VAR} 展开
	cfg.Robots.Dingtalk.ClientSecret = ""

	ResolveRobotSecretsFromEnv(cfg)

	if cfg.Robots.Lark.AppID != "cli_test_app_id_123" {
		t.Fatalf("Lark.AppID 空值未回退 FEISHU_APP_ID: got %q", cfg.Robots.Lark.AppID)
	}
	if cfg.Robots.Lark.AppSecret != "feishu-secret-abcdef123456" {
		t.Fatalf("Lark.AppSecret 占位符未回退: got %q", cfg.Robots.Lark.AppSecret)
	}
	if cfg.Robots.Telegram.BotToken != "123456:ABC-DEF-telegram-token" {
		t.Fatalf("Telegram.BotToken 未回退: got %q", cfg.Robots.Telegram.BotToken)
	}
	if cfg.Robots.Dingtalk.ClientID != "ding-client-id-xyz" {
		t.Fatalf("Dingtalk.ClientID ${VAR} 展开失败: got %q", cfg.Robots.Dingtalk.ClientID)
	}
	if cfg.Robots.Dingtalk.ClientSecret != "ding-secret-xyz" {
		t.Fatalf("Dingtalk.ClientSecret 未回退: got %q", cfg.Robots.Dingtalk.ClientSecret)
	}
}

func TestDetectAIChannelsFromEnv(t *testing.T) {
	os.Setenv("DEEPSEEK_API_KEY", "sk-deepseek-real-0987654321")
	os.Setenv("OPENAI_API_KEY", "sk-openai-real-1122334455")
	defer os.Unsetenv("DEEPSEEK_API_KEY")
	defer os.Unsetenv("OPENAI_API_KEY")

	cfg := &Config{}
	// 只有 qwen-max（占位符 key），无 deepseek/openai 通道
	cfg.AI.DefaultChannel = "qwen-max"
	cfg.AI.Channels = map[string]AIChannelConfig{
		"qwen-max": {Name: "Qwen Max", APIKey: "sk-xxxxxxx", BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", Model: "qwen3-max"},
	}

	DetectAIChannelsFromEnv(cfg)

	// qwen-max 占位符应被回填（DASHSCOPE 不在 env，但 deepseek/openai 探测命中）
	// 说明：qwen-max 没有 DASHSCOPE_API_KEY 环境变量，这里不要求它被填
	if _, ok := cfg.AI.Channels["deepseek"]; !ok {
		t.Fatalf("未自动补全 deepseek 通道: %+v", cfg.AI.Channels)
	}
	ds := cfg.AI.Channels["deepseek"]
	if ds.APIKey != "sk-deepseek-real-0987654321" || ds.Model != "deepseek-chat" {
		t.Fatalf("deepseek 通道配置错误: %+v", ds)
	}
	if _, ok := cfg.AI.Channels["openai"]; !ok {
		t.Fatalf("未自动补全 openai 通道: %+v", cfg.AI.Channels)
	}
	// 默认通道 qwen-max 无真实 key → 应自动切到第一个命中（deepseek 在预设中位于 openai 之前…实际预设顺序 DASHSCOPE→DEEPSEEK→OPENAI）
	if cfg.AI.DefaultChannel != "deepseek" {
		t.Fatalf("默认通道未自动切换到可用通道: got %q, channels=%+v", cfg.AI.DefaultChannel, cfg.AI.Channels)
	}
}

func TestAutoFailoverChannelIDs(t *testing.T) {
	os.Setenv("DEEPSEEK_API_KEY", "sk-deepseek-real-0987654321")
	os.Setenv("OPENAI_API_KEY", "sk-openai-real-1122334455")
	defer os.Unsetenv("DEEPSEEK_API_KEY")
	defer os.Unsetenv("OPENAI_API_KEY")

	cfg := &Config{}
	cfg.AI.DefaultChannel = "qwen-max"
	cfg.AI.Channels = map[string]AIChannelConfig{
		"qwen-max": {APIKey: "sk-xxxxxxx", BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", Model: "qwen3-max"},
		"deepseek": {APIKey: "", BaseURL: "https://api.deepseek.com/v1", Model: "deepseek-chat"},
		"openai":   {APIKey: "sk-openai-real-1122334455", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini"},
		"dead":     {APIKey: "sk-xxxxxxx", BaseURL: "https://dead.example/v1", Model: "x"},
	}
	ResolveAllAPIKeysFromEnv(cfg)
	DetectAIChannelsFromEnv(cfg)

	ids := cfg.AutoFailoverChannelIDs(cfg.OpenAI)
	// deepseek（env 回退生效）与 openai 应在候选；dead（占位）与 qwen-max（主通道）不在
	joined := strings.Join(ids, ",")
	if !strings.Contains(joined, "deepseek") {
		t.Fatalf("deepseek 未进自动轮询候选: %v", ids)
	}
	if !strings.Contains(joined, "openai") {
		t.Fatalf("openai 未进自动轮询候选: %v", ids)
	}
	if strings.Contains(joined, "dead") {
		t.Fatalf("占位 key 通道不应进候选: %v", ids)
	}
	if strings.Contains(joined, "qwen-max") {
		t.Fatalf("主通道 qwen-max 不应进候选: %v", ids)
	}
}
