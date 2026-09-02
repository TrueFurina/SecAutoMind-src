package config

import (
	"os"
	"reflect"
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
		add("OPENROUTER_API_KEY")
	}
	// 兜底：常见通用名（不要求环境变量已存在，交给调用方判断空）
	fallback := []string{"OPENAI_API_KEY", "DASHSCOPE_API_KEY", "QWEN_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"}
	for _, n := range fallback {
		if os.Getenv(n) != "" {
			cands = append(cands, n)
		}
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
