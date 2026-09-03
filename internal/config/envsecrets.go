package config

import (
	"os"
	"reflect"
	"sort"
	"strings"
)

// sensitiveYAMLTag 判断 yaml tag 是否属于敏感凭据字段（需要环境变量展开/回退）。
func sensitiveYAMLTag(yamlTag string) bool {
	tag := strings.TrimSpace(strings.Split(yamlTag, ",")[0])
	switch tag {
	case "api_key", "token", "secret", "password", "app_secret", "client_secret",
		"bot_token", "verify_token", "auth_header_value", "ilink_bot_id", "ilink_user_id",
		"app_id", "client_id":
		return true
	}
	return false
}

// ExpandSecretEnv 反射遍历 Config，对所有敏感凭据字段做 ${VAR} / ${VAR:-default} 环境变量展开。
// 支持嵌套 struct / map / slice / 指针；非敏感字段保持原样（避免误伤 URL 等含 $ 的普通值）。
func ExpandSecretEnv(cfg *Config) {
	if cfg == nil {
		return
	}
	expandSecretReflect(reflect.ValueOf(cfg).Elem())
}

func expandSecretReflect(v reflect.Value) {
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("yaml")
			fv := v.Field(i)
			if fv.Kind() == reflect.String && sensitiveYAMLTag(tag) && fv.CanSet() {
				fv.SetString(expandEnvVar(fv.String()))
				continue
			}
			expandSecretReflect(fv)
		}
	case reflect.Ptr:
		if !v.IsNil() {
			expandSecretReflect(v.Elem())
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		for _, k := range v.MapKeys() {
			mv := v.MapIndex(k)
			if !mv.IsValid() {
				continue
			}
			switch mv.Kind() {
			case reflect.Ptr:
				if !mv.IsNil() {
					expandSecretReflect(mv.Elem())
				}
			case reflect.Slice, reflect.Map:
				// slice/map 引用类型：底层共享，直接递归即可写入
				expandSecretReflect(mv)
			case reflect.Struct:
				// map 的值类型 struct 不可寻址——复制副本展开后写回 map
				cp := reflect.New(mv.Type()).Elem()
				cp.Set(mv)
				expandSecretReflect(cp)
				v.SetMapIndex(k, cp)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			ev := v.Index(i)
			if ev.Kind() == reflect.Ptr || ev.Kind() == reflect.Struct {
				expandSecretReflect(ev)
			}
		}
	}
}

// isPlaceholderKey 判断是否为占位符/未配置的 API key（避免用占位符发起 401 请求）。
// 仅对空值与明确占位关键词生效；用户填写的短 key（如测试用 qwen-key）不视为占位。
func isPlaceholderKey(key string) bool {
	k := strings.TrimSpace(key)
	if k == "" {
		return true
	}
	low := strings.ToLower(k)
	placeholders := []string{"sk-xxxxxxx", "your-api-key", "your_api_key", "changeme", "replace-me", "<api-key>", "xxx"}
	for _, p := range placeholders {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// envKeyCandidatesForBaseURL 根据 base_url / provider 推断应回退的环境变量名。
// 返回的候选按优先级排序：先特定于 base_url，再通用名。
func envKeyCandidatesForBaseURL(baseURL, provider string) []string {
	var cands []string
	u := strings.ToLower(baseURL)

	add := func(names ...string) {
		for _, n := range names {
			if n != "" && os.Getenv(n) != "" {
				cands = append(cands, n)
			}
		}
	}

	switch {
	case strings.Contains(u, "dashscope"), strings.Contains(u, "aliyun"), provider == "dashscope":
		add("DASHSCOPE_API_KEY", "DASHSCOPE_KEY", "QWEN_API_KEY", "ALIYUN_API_KEY", "BAILIAN_API_KEY")
	case strings.Contains(u, "deepseek"):
		add("DEEPSEEK_API_KEY", "DEEPSEEK_KEY")
	case strings.Contains(u, "anthropic"), strings.Contains(u, "claude"):
		add("ANTHROPIC_API_KEY", "CLAUDE_API_KEY")
	case strings.Contains(u, "siliconflow"):
		add("SILICONFLOW_API_KEY")
	case strings.Contains(u, "openai"), strings.Contains(u, "openrouter"):
		add("OPENAI_API_KEY", "OPENROUTER_API_KEY")
	}
	return cands
}

// ResolveAPIKeyFromEnv 处理单个凭据字段：先展开 ${VAR}；若结果为空或占位符，
// 则按 base_url/provider 从约定环境变量回退真实 key（用户无需在 config 填写）。
func ResolveAPIKeyFromEnv(configured, baseURL, provider string) string {
	key := strings.TrimSpace(expandEnvVar(configured))
	if !isPlaceholderKey(key) {
		return key
	}
	for _, envName := range envKeyCandidatesForBaseURL(baseURL, provider) {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" && !isPlaceholderKey(v) {
			return v
		}
	}
	return key
}

// resolveSecretFromEnv 通用回退：configured 为空/占位符时，按候选环境变量名依次取第一个非空值。
func resolveSecretFromEnv(configured string, envNames ...string) string {
	key := strings.TrimSpace(expandEnvVar(configured))
	if !isPlaceholderKey(key) {
		return key
	}
	for _, n := range envNames {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" && !isPlaceholderKey(v) {
			return v
		}
	}
	return key
}

// ResolveRobotSecretsFromEnv 机器人通道凭据环境变量回退：
// config 中留空/占位的 app_id/app_secret/bot_token 等，按通道约定环境变量自动补齐
// （如 FEISHU_APP_ID / LARK_APP_SECRET / DINGTALK_APP_KEY / TELEGRAM_BOT_TOKEN …）。
func ResolveRobotSecretsFromEnv(cfg *Config) {
	if cfg == nil {
		return
	}
	r := &cfg.Robots
	// 飞书（lark）
	r.Lark.AppID = resolveSecretFromEnv(r.Lark.AppID, "FEISHU_APP_ID", "LARK_APP_ID")
	r.Lark.AppSecret = resolveSecretFromEnv(r.Lark.AppSecret, "FEISHU_APP_SECRET", "LARK_APP_SECRET")
	r.Lark.VerifyToken = resolveSecretFromEnv(r.Lark.VerifyToken, "FEISHU_VERIFY_TOKEN", "LARK_VERIFY_TOKEN")
	// 钉钉
	r.Dingtalk.ClientID = resolveSecretFromEnv(r.Dingtalk.ClientID, "DINGTALK_APP_KEY", "DINGTALK_CLIENT_ID", "DINGDING_APP_KEY")
	r.Dingtalk.ClientSecret = resolveSecretFromEnv(r.Dingtalk.ClientSecret, "DINGTALK_APP_SECRET", "DINGTALK_CLIENT_SECRET")
	// 企业微信
	r.Wecom.CorpID = resolveSecretFromEnv(r.Wecom.CorpID, "WECOM_CORP_ID", "WECHAT_WORK_CORP_ID")
	r.Wecom.Secret = resolveSecretFromEnv(r.Wecom.Secret, "WECOM_SECRET", "WECHAT_WORK_SECRET")
	r.Wecom.Token = resolveSecretFromEnv(r.Wecom.Token, "WECOM_TOKEN")
	r.Wecom.EncodingAESKey = resolveSecretFromEnv(r.Wecom.EncodingAESKey, "WECOM_ENCODING_AES_KEY")
	// Telegram
	r.Telegram.BotToken = resolveSecretFromEnv(r.Telegram.BotToken, "TELEGRAM_BOT_TOKEN")
	// Slack
	r.Slack.BotToken = resolveSecretFromEnv(r.Slack.BotToken, "SLACK_BOT_TOKEN")
	r.Slack.AppToken = resolveSecretFromEnv(r.Slack.AppToken, "SLACK_APP_TOKEN")
	// 微信 iLink
	r.Wechat.BotToken = resolveSecretFromEnv(r.Wechat.BotToken, "WECHAT_ILINK_BOT_TOKEN", "ILINK_BOT_TOKEN")
}

// envChannelPreset 描述一个可由环境变量一键激活的 LLM 通道预设。
type envChannelPreset struct {
	EnvName  string // 探测的环境变量名
	ID       string // 通道 ID（NormalizeAIChannelID 规范化后写入）
	Name     string
	BaseURL  string
	Model    string
	Provider string
}

// envChannelPresets 常见 LLM 提供方预设（按探测顺序，第一个命中成为默认通道候选）。
var envChannelPresets = []envChannelPreset{
	{EnvName: "DASHSCOPE_API_KEY", ID: "qwen-max", Name: "Qwen Max", BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", Model: "qwen3-max", Provider: "openai_compatible"},
	{EnvName: "DEEPSEEK_API_KEY", ID: "deepseek", Name: "DeepSeek", BaseURL: "https://api.deepseek.com/v1", Model: "deepseek-chat", Provider: "openai_compatible"},
	{EnvName: "OPENAI_API_KEY", ID: "openai", Name: "OpenAI", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", Provider: "openai"},
	{EnvName: "SILICONFLOW_API_KEY", ID: "siliconflow", Name: "SiliconFlow", BaseURL: "https://api.siliconflow.cn/v1", Model: "Qwen/Qwen2.5-7B-Instruct", Provider: "openai_compatible"},
	{EnvName: "MOONSHOT_API_KEY", ID: "moonshot", Name: "Moonshot", BaseURL: "https://api.moonshot.cn/v1", Model: "moonshot-v1-8k", Provider: "openai_compatible"},
	{EnvName: "ZHIPU_API_KEY", ID: "zhipu", Name: "智谱 GLM", BaseURL: "https://open.bigmodel.cn/api/paas/v4", Model: "glm-4-flash", Provider: "openai_compatible"},
	{EnvName: "ARK_API_KEY", ID: "ark", Name: "火山方舟", BaseURL: "https://ark.cn-beijing.volces.com/api/v3", Model: "doubao-seed-1-6-250615", Provider: "openai_compatible"},
	{EnvName: "QIANFAN_API_KEY", ID: "qianfan", Name: "百度千帆", BaseURL: "https://qianfan.baidubce.com/v2", Model: "ernie-4.0-turbo-8k", Provider: "openai_compatible"},
	{EnvName: "ANTHROPIC_API_KEY", ID: "claude", Name: "Claude", BaseURL: "https://api.anthropic.com", Model: "claude-sonnet-4-20250514", Provider: "claude"},
}

// DetectAIChannelsFromEnv 探测常见 LLM 环境变量，自动补全 AI 通道：
// - config 未定义的通道 + 环境变量存在真实 key → 按预设写入通道（用户免配置，开箱即用多 provider）
// - 默认通道缺失真实 key 时，自动切到第一个探测命中的通道
func DetectAIChannelsFromEnv(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.AI.Channels == nil {
		cfg.AI.Channels = make(map[string]AIChannelConfig)
	}

	// 1) 补全缺失通道
	for _, p := range envChannelPresets {
		envKey := strings.TrimSpace(os.Getenv(p.EnvName))
		if envKey == "" || isPlaceholderKey(envKey) {
			continue
		}
		id := NormalizeAIChannelID(p.ID)
		if existing, ok := cfg.AI.Channels[id]; ok {
			// 已存在：仅当 key 仍为空/占位时回填 env key（不覆盖用户显式 key）
			if isPlaceholderKey(existing.APIKey) {
				existing.APIKey = envKey
				cfg.AI.Channels[id] = existing
			}
			continue
		}
		cfg.AI.Channels[id] = AIChannelConfig{
			Name:     p.Name,
			Provider: p.Provider,
			APIKey:   envKey,
			BaseURL:  p.BaseURL,
			Model:    p.Model,
		}
	}

	// 2) 默认通道兜底：当前默认通道 key 无效时，切到第一个探测命中的通道
	defID := NormalizeAIChannelID(cfg.AI.DefaultChannel)
	if ch, ok := cfg.AI.Channels[defID]; !ok || isPlaceholderKey(ch.APIKey) {
		for _, p := range envChannelPresets {
			if v := strings.TrimSpace(os.Getenv(p.EnvName)); v != "" && !isPlaceholderKey(v) {
				cfg.AI.DefaultChannel = NormalizeAIChannelID(p.ID)
				break
			}
		}
	}
}

// AutoFailoverChannelIDs 返回"开箱即用的自动轮询候选"通道 ID 列表：
// - 通道存在且 APIKey 有效（非空、非占位符——通常是环境变量自动激活的通道）
// - 排除与 primary 相同端点/模型的通道（避免重复请求同一服务）
// 返回按 ID 排序（确定性，便于测试与日志）。当用户显式配置 model_failover_channels
// 时优先使用显式列表；本方法仅作为显式列表为空时的自动兜底。
func (c *Config) AutoFailoverChannelIDs(primary OpenAIConfig) []string {
	if c == nil || c.AI.Channels == nil {
		return nil
	}
	var out []string
	for id, ch := range c.AI.Channels {
		if isPlaceholderKey(ch.APIKey) {
			continue
		}
		oa := ch.ToOpenAIConfig()
		if sameEndpointKeyModel(primary, oa) {
			continue
		}
		out = append(out, NormalizeAIChannelID(id))
	}
	sort.Strings(out)
	return out
}

// sameEndpointKeyModel 判断两个 OpenAI 配置是否指向同一服务端点 + 同一凭据 + 同一模型。
func sameEndpointKeyModel(a, b OpenAIConfig) bool {
	return strings.EqualFold(strings.TrimSpace(a.Provider), strings.TrimSpace(b.Provider)) &&
		strings.TrimRight(strings.TrimSpace(a.BaseURL), "/") == strings.TrimRight(strings.TrimSpace(b.BaseURL), "/") &&
		strings.TrimSpace(a.APIKey) == strings.TrimSpace(b.APIKey) &&
		strings.TrimSpace(a.Model) == strings.TrimSpace(b.Model)
}

// ResolveAllAPIKeysFromEnv 在 Load 完成后统一处理全部凭据：
// 1) 所有敏感字段的 ${VAR} 已由 ExpandSecretEnv 展开；
// 2) 对 AI 主配置与各通道：空/占位 key 按 base_url 自动回退环境变量；
// 3) 知识库（embedding/rerank）与空间测绘工具（fofa/zoomeye/quake/shodan）同规则回退。
func ResolveAllAPIKeysFromEnv(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.OpenAI.APIKey = ResolveAPIKeyFromEnv(cfg.OpenAI.APIKey, cfg.OpenAI.BaseURL, cfg.OpenAI.Provider)

	if cfg.AI.Channels != nil {
		for id, ch := range cfg.AI.Channels {
			ch.APIKey = ResolveAPIKeyFromEnv(ch.APIKey, ch.BaseURL, ch.Provider)
			cfg.AI.Channels[id] = ch
		}
	}

	// 知识库 embedding / rerank（dashscope/cohere 由 base_url 自动推断 provider）
	cfg.Knowledge.Embedding.APIKey = ResolveAPIKeyFromEnv(cfg.Knowledge.Embedding.APIKey, cfg.Knowledge.Embedding.BaseURL, "")
	cfg.Knowledge.Retrieval.Rerank.APIKey = ResolveAPIKeyFromEnv(cfg.Knowledge.Retrieval.Rerank.APIKey, cfg.Knowledge.Retrieval.Rerank.BaseURL, cfg.Knowledge.Retrieval.Rerank.Provider)

	// 空间测绘工具（默认 dashscope/zoomeye 等由 base_url 判断）
	cfg.FOFA.APIKey = ResolveAPIKeyFromEnv(cfg.FOFA.APIKey, cfg.FOFA.BaseURL, "")
	cfg.ZoomEye.APIKey = ResolveAPIKeyFromEnv(cfg.ZoomEye.APIKey, cfg.ZoomEye.BaseURL, "")
	cfg.Quake.APIKey = ResolveAPIKeyFromEnv(cfg.Quake.APIKey, cfg.Quake.BaseURL, "")
	cfg.Shodan.APIKey = ResolveAPIKeyFromEnv(cfg.Shodan.APIKey, cfg.Shodan.BaseURL, "")
}
