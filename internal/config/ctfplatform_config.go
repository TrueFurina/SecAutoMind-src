package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// CTFPlatformConfig 决赛平台客户端的抗打击治理配置面（总纲 §2.4）。
//
// 约束原文：「全部 config 开关化、默认开、一键回退」。三条里最容易被做假的是
// 「默认开」——为此全部字段用**指针**：必须能区分「未配置」与「显式配成 false / 0」。
// 若用值类型，`enabled: false` 与字段整体缺失会双双落进零值，开关读起来像是
// 接线了、实际上从来没有生效过。
type CTFPlatformConfig struct {
	// Enabled 一键回退总开关。未配置或 true = 7 项抗打击机制全开（默认）；
	// false = 一次性回退为朴素直连。
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// MaxRetries 最大重试次数；>0 生效，留空沿用包内默认（5）。
	MaxRetries *int `yaml:"max_retries,omitempty" json:"max_retries,omitempty"`
	// RetryBackoffSeconds 指数退避基准（秒）；>0 生效，留空沿用包内默认（2）。
	RetryBackoffSeconds *float64 `yaml:"retry_backoff_seconds,omitempty" json:"retry_backoff_seconds,omitempty"`
	// WAFTimeoutSeconds 403 冷却时长（秒）；>0 生效，留空沿用包内默认（300）。
	WAFTimeoutSeconds *float64 `yaml:"waf_timeout_seconds,omitempty" json:"waf_timeout_seconds,omitempty"`
	// ListCacheTTLSeconds 列表缓存 TTL（秒）。留空沿用包内默认（10）；显式 0 = 关闭缓存。
	ListCacheTTLSeconds *float64 `yaml:"list_cache_ttl_seconds,omitempty" json:"list_cache_ttl_seconds,omitempty"`
}

// EnvAntiBlock 是运维侧的一键回退入口（环境变量优先于 YAML）。
//
// 为什么在 YAML 之外再留一个 env：回退是**事故处置动作**——赛时发现抗打击层引入
// 回归时，改 YAML 要走「改文件 → 重启」两步，且回退记录会混进配置变更；env 可以在
// runbook 里一行 export 完成，也能在容器编排里独立于镜像配置注入。
const EnvAntiBlock = "CTF_AGENT_ANTI_BLOCK"

// AntiBlockEnabled 解析抗打击总开关。优先级：环境变量 > YAML > 默认开。
//
// 非法 env 值（如 CTF_AGENT_ANTI_BLOCK=yes-please）**忽略并回落 YAML**，
// 而不是当成 false —— 解析失败时把治理关掉是最坏的一种"容错"。
func (c CTFPlatformConfig) AntiBlockEnabled() bool {
	if v := strings.TrimSpace(os.Getenv(EnvAntiBlock)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	if c.Enabled != nil {
		return *c.Enabled
	}
	return true
}

// MaxRetriesEffective 返回配置的最大重试次数；未配置或非法返回 0（由包内默认兜底）。
func (c CTFPlatformConfig) MaxRetriesEffective() int {
	if c.MaxRetries == nil || *c.MaxRetries <= 0 {
		return 0
	}
	return *c.MaxRetries
}

// RetryBackoff 返回指数退避基准；未配置返回 0（由包内默认兜底）。
func (c CTFPlatformConfig) RetryBackoff() time.Duration {
	return positiveSeconds(c.RetryBackoffSeconds)
}

// WAFTimeout 返回 403 冷却时长；未配置返回 0（由包内默认兜底）。
func (c CTFPlatformConfig) WAFTimeout() time.Duration {
	return positiveSeconds(c.WAFTimeoutSeconds)
}

// ListCacheTTL 返回列表缓存 TTL。
//
// nil = 未配置 → 返回 nil（沿用包内默认 10s）；显式 0 → 返回指向 0 的指针（关闭缓存）。
// 这是本配置面唯一需要三态的字段，故用指针而非「0 即默认」的约定。
func (c CTFPlatformConfig) ListCacheTTL() *time.Duration {
	if c.ListCacheTTLSeconds == nil {
		return nil
	}
	d := time.Duration(*c.ListCacheTTLSeconds * float64(time.Second))
	return &d
}

func positiveSeconds(v *float64) time.Duration {
	if v == nil || *v <= 0 {
		return 0
	}
	return time.Duration(*v * float64(time.Second))
}
