package config

import (
	"os"
	"strconv"
	"strings"
)

// robotEnvOverride 单个凭证字段的环境变量覆盖规则。
type robotEnvOverride struct {
	envVar string // 环境变量名；按表内顺序取第一个非空值
	set    func(r *RobotsConfig, v string)
}

// robotEnvOverrides 机器人通道凭证的环境变量覆盖表。
// 优先级：系统环境变量 > config.yaml。适配 docker、服务器、答辩现场等
// 不便于编辑配置文件的场景；凭证走环境变量时可保持 config.yaml 留空，
// 避免真实密钥落盘/误提交。
var robotEnvOverrides = map[string][]robotEnvOverride{
	"dingtalk": {
		{"DING_APP_KEY", func(r *RobotsConfig, v string) { r.Dingtalk.ClientID = v }},        // 钉钉 ClientID
		{"DING_APP_SECRET", func(r *RobotsConfig, v string) { r.Dingtalk.ClientSecret = v }}, // 钉钉 ClientSecret
		{"DINGTALK_CLIENT_ID", func(r *RobotsConfig, v string) { r.Dingtalk.ClientID = v }},
		{"DINGTALK_CLIENT_SECRET", func(r *RobotsConfig, v string) { r.Dingtalk.ClientSecret = v }},
	},
	"wechat": {
		{"WECHAT_BOT_TOKEN", func(r *RobotsConfig, v string) { r.Wechat.BotToken = v }},
	},
	"wecom": {
		{"WECOM_CORP_ID", func(r *RobotsConfig, v string) { r.Wecom.CorpID = v }},
		{"WECOM_SECRET", func(r *RobotsConfig, v string) { r.Wecom.Secret = v }},
		{"WECOM_TOKEN", func(r *RobotsConfig, v string) { r.Wecom.Token = v }},
		{"WECOM_ENCODING_AES_KEY", func(r *RobotsConfig, v string) { r.Wecom.EncodingAESKey = v }},
	},
	"lark": {
		{"LARK_APP_ID", func(r *RobotsConfig, v string) { r.Lark.AppID = v }},
		{"LARK_APP_SECRET", func(r *RobotsConfig, v string) { r.Lark.AppSecret = v }},
		{"LARK_VERIFY_TOKEN", func(r *RobotsConfig, v string) { r.Lark.VerifyToken = v }},
	},
	"telegram": {
		{"TELEGRAM_BOT_TOKEN", func(r *RobotsConfig, v string) { r.Telegram.BotToken = v }},
	},
	"slack": {
		{"SLACK_BOT_TOKEN", func(r *RobotsConfig, v string) { r.Slack.BotToken = v }},
		{"SLACK_APP_TOKEN", func(r *RobotsConfig, v string) { r.Slack.AppToken = v }},
	},
	"discord": {
		{"DISCORD_BOT_TOKEN", func(r *RobotsConfig, v string) { r.Discord.BotToken = v }},
	},
	"qq": {
		{"QQ_APP_ID", func(r *RobotsConfig, v string) { r.QQ.AppID = v }},
		{"QQ_CLIENT_SECRET", func(r *RobotsConfig, v string) { r.QQ.ClientSecret = v }},
	},
}

// robotEnabledEnv 通道启用开关的环境变量（值 true/1/yes/on 开启，false/0/no/off 关闭）。
// 用于 docker 等无本地配置文件场景，如：docker run -e DING_APP_KEY=... -e DING_APP_SECRET=... -e DINGTALK_ENABLED=true ...
var robotEnabledEnv = map[string]struct {
	envVar string
	set    func(r *RobotsConfig, enabled bool)
}{
	"dingtalk": {"DINGTALK_ENABLED", func(r *RobotsConfig, b bool) { r.Dingtalk.Enabled = b }},
	"wechat":   {"WECHAT_ENABLED", func(r *RobotsConfig, b bool) { r.Wechat.Enabled = b }},
	"wecom":    {"WECOM_ENABLED", func(r *RobotsConfig, b bool) { r.Wecom.Enabled = b }},
	"lark":     {"LARK_ENABLED", func(r *RobotsConfig, b bool) { r.Lark.Enabled = b }},
	"telegram": {"TELEGRAM_ENABLED", func(r *RobotsConfig, b bool) { r.Telegram.Enabled = b }},
	"slack":    {"SLACK_ENABLED", func(r *RobotsConfig, b bool) { r.Slack.Enabled = b }},
	"discord":  {"DISCORD_ENABLED", func(r *RobotsConfig, b bool) { r.Discord.Enabled = b }},
	"qq":       {"QQ_ENABLED", func(r *RobotsConfig, b bool) { r.QQ.Enabled = b }},
}

// ApplyRobotsEnvOverride 用系统环境变量覆盖 robots 段的启用开关与凭证。
// 环境变量存在且非空时覆盖 yaml 值；环境变量不存在时保持 yaml 原值。
// 钉钉凭证同时支持 DING_APP_KEY/DING_APP_SECRET（钉钉开放平台 ClientID/ClientSecret 的常用别名）
// 与 DINGTALK_CLIENT_ID/DINGTALK_CLIENT_SECRET 两种命名。
// 本方法在 config.Load 中调用，Web 设置保存后重新加载配置时同样生效。
func (c *Config) ApplyRobotsEnvOverride() {
	// 1) 启用开关覆盖（显式解析布尔值，非法值忽略并保持 yaml 原值）
	for _, e := range robotEnabledEnv {
		raw, ok := os.LookupEnv(e.envVar)
		if !ok {
			continue
		}
		if b, err := strconv.ParseBool(strings.TrimSpace(raw)); err == nil {
			e.set(&c.Robots, b)
		}
	}
	// 2) 凭证覆盖：按声明顺序取第一个非空环境变量
	for _, overrides := range robotEnvOverrides {
		for _, o := range overrides {
			if v := strings.TrimSpace(os.Getenv(o.envVar)); v != "" {
				o.set(&c.Robots, v)
			}
		}
	}
}

// EnabledButIncompleteRobots 返回已启用但凭证不完整的机器人通道名列表。
// 机器人均为可选扩展模块：凭证缺失时仅禁用该通道并告警，不影响主系统启动与运行。
func (c RobotsConfig) EnabledButIncompleteRobots() []string {
	var incomplete []string
	add := func(name string, ok bool) {
		if !ok {
			incomplete = append(incomplete, name)
		}
	}
	add("wechat", !c.Wechat.Enabled || strings.TrimSpace(c.Wechat.BotToken) != "")
	add("wecom", !c.Wecom.Enabled || strings.TrimSpace(c.Wecom.Token) != "")
	add("dingtalk", !c.Dingtalk.Enabled || (strings.TrimSpace(c.Dingtalk.ClientID) != "" && strings.TrimSpace(c.Dingtalk.ClientSecret) != ""))
	add("lark", !c.Lark.Enabled || (strings.TrimSpace(c.Lark.AppID) != "" && strings.TrimSpace(c.Lark.AppSecret) != ""))
	add("telegram", !c.Telegram.Enabled || strings.TrimSpace(c.Telegram.BotToken) != "")
	add("slack", !c.Slack.Enabled || (strings.TrimSpace(c.Slack.BotToken) != "" && strings.TrimSpace(c.Slack.AppToken) != ""))
	add("discord", !c.Discord.Enabled || strings.TrimSpace(c.Discord.BotToken) != "")
	add("qq", !c.QQ.Enabled || (strings.TrimSpace(c.QQ.AppID) != "" && strings.TrimSpace(c.QQ.ClientSecret) != ""))
	return incomplete
}
