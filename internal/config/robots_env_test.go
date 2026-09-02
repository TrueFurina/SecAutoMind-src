package config

import (
	"testing"
)

func TestApplyRobotsEnvOverride_Dingtalk(t *testing.T) {
	t.Setenv("DING_APP_KEY", "ding-test-key")
	t.Setenv("DING_APP_SECRET", "sec-test-secret")
	t.Setenv("DINGTALK_ENABLED", "true")

	cfg := &Config{}
	cfg.Robots.Dingtalk.ClientID = "yaml-key"
	cfg.Robots.Dingtalk.ClientSecret = ""
	cfg.ApplyRobotsEnvOverride()

	if cfg.Robots.Dingtalk.ClientID != "ding-test-key" {
		t.Fatalf("DING_APP_KEY 应覆盖 client_id，got %q", cfg.Robots.Dingtalk.ClientID)
	}
	if cfg.Robots.Dingtalk.ClientSecret != "sec-test-secret" {
		t.Fatalf("DING_APP_SECRET 应覆盖 client_secret，got %q", cfg.Robots.Dingtalk.ClientSecret)
	}
	if !cfg.Robots.Dingtalk.Enabled {
		t.Fatal("DINGTALK_ENABLED=true 应覆盖 enabled")
	}
}

func TestApplyRobotsEnvOverride_EnvAbsentKeepsYaml(t *testing.T) {
	t.Setenv("DING_APP_KEY", "")
	t.Setenv("DING_APP_SECRET", "")

	cfg := &Config{}
	cfg.Robots.Dingtalk.ClientID = "yaml-key"
	cfg.Robots.Dingtalk.ClientSecret = "yaml-secret"
	cfg.ApplyRobotsEnvOverride()

	if cfg.Robots.Dingtalk.ClientID != "yaml-key" || cfg.Robots.Dingtalk.ClientSecret != "yaml-secret" {
		t.Fatalf("环境变量为空时应保留 yaml 原值，got %q/%q", cfg.Robots.Dingtalk.ClientID, cfg.Robots.Dingtalk.ClientSecret)
	}
}

func TestApplyRobotsEnvOverride_InvalidEnabledIgnored(t *testing.T) {
	t.Setenv("DINGTALK_ENABLED", "not-a-bool")

	cfg := &Config{}
	cfg.ApplyRobotsEnvOverride()

	if cfg.Robots.Dingtalk.Enabled {
		t.Fatal("非法布尔值应被忽略，保持 yaml 原值 false")
	}
}

func TestApplyRobotsEnvOverride_AllChannels(t *testing.T) {
	t.Setenv("WECHAT_BOT_TOKEN", "wt")
	t.Setenv("WECOM_CORP_ID", "wc")
	t.Setenv("LARK_APP_ID", "la")
	t.Setenv("TELEGRAM_BOT_TOKEN", "tt")
	t.Setenv("SLACK_BOT_TOKEN", "sb")
	t.Setenv("SLACK_APP_TOKEN", "sa")
	t.Setenv("DISCORD_BOT_TOKEN", "db")
	t.Setenv("QQ_APP_ID", "qa")
	t.Setenv("QQ_CLIENT_SECRET", "qs")

	cfg := &Config{}
	cfg.ApplyRobotsEnvOverride()

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"wechat.bot_token", cfg.Robots.Wechat.BotToken, "wt"},
		{"wecom.corp_id", cfg.Robots.Wecom.CorpID, "wc"},
		{"lark.app_id", cfg.Robots.Lark.AppID, "la"},
		{"telegram.bot_token", cfg.Robots.Telegram.BotToken, "tt"},
		{"slack.bot_token", cfg.Robots.Slack.BotToken, "sb"},
		{"slack.app_token", cfg.Robots.Slack.AppToken, "sa"},
		{"discord.bot_token", cfg.Robots.Discord.BotToken, "db"},
		{"qq.app_id", cfg.Robots.QQ.AppID, "qa"},
		{"qq.client_secret", cfg.Robots.QQ.ClientSecret, "qs"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestEnabledButIncompleteRobots(t *testing.T) {
	cfg := &Config{}
	// 钉钉启用但缺凭证 → 不完整；其余通道未启用 → 完整
	cfg.Robots.Dingtalk.Enabled = true
	cfg.Robots.Dingtalk.ClientID = "k"
	// Telegram 启用且凭证齐全 → 完整
	cfg.Robots.Telegram.Enabled = true
	cfg.Robots.Telegram.BotToken = "tok"

	got := cfg.Robots.EnabledButIncompleteRobots()
	if len(got) != 1 || got[0] != "dingtalk" {
		t.Fatalf("应仅返回 dingtalk，got %v", got)
	}
}
