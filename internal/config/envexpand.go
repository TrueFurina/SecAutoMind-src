package config

import (
	"os"
	"strings"
)

// expandEnvVar 展开字符串中的 ${VAR} 和 ${VAR:-default} 环境变量引用。
// 与官方 MCP 配置格式一致（Claude Desktop / Cursor / VS Code 均支持此语法）。
func expandEnvVar(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		// 查找 ${
		idx := strings.Index(s[i:], "${")
		if idx < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+idx])
		i += idx + 2 // skip ${

		// 查找对应的 }
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			// 没有 }，原样保留
			b.WriteString("${")
			continue
		}
		expr := s[i : i+end]
		i += end + 1 // skip }

		// 解析 VAR:-default
		varName := expr
		defaultVal := ""
		hasDefault := false
		if colonIdx := strings.Index(expr, ":-"); colonIdx >= 0 {
			varName = expr[:colonIdx]
			defaultVal = expr[colonIdx+2:]
			hasDefault = true
		}

		val := os.Getenv(varName)
		if val == "" && hasDefault {
			val = defaultVal
		}
		b.WriteString(val)
	}
	return b.String()
}

// ExpandConfigEnv 展开 ExternalMCPServerConfig 中所有支持环境变量的字段。
// 展开范围：Command、Args、Env values、URL、Headers values。
//
// 注意：Args/Env/Headers 必须整体替换为新切片/新 map（禁止原地写 cfg.Args[i]）——
// 同一配置对象可能同时被 lazy SDK client 并发读取（createSDKClient→exec.Command 读 Args），
// 原地写共享底层数组会构成数据竞争（09-05 CI -race 实证）。
func ExpandConfigEnv(cfg *ExternalMCPServerConfig) {
	cfg.Command = expandEnvVar(cfg.Command)
	cfg.Args = expandEnvVarSlice(cfg.Args)
	cfg.Env = expandEnvVarMapStr(cfg.Env)
	cfg.URL = expandEnvVar(cfg.URL)
	cfg.Headers = expandEnvVarMapStr(cfg.Headers)
}

// expandEnvVarSlice 返回展开后的新切片，不写传入切片的底层数组。
func expandEnvVarSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = expandEnvVar(s)
	}
	return out
}

// expandEnvVarMapStr 返回展开后的新 map，不写传入 map。
func expandEnvVarMapStr(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = expandEnvVar(v)
	}
	return out
}
