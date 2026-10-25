// Package llmchannel —— 免费 LLM 通道注册表 + 瞬时错误分类（P0-4 通道 failover，2026-10-26）。
//
// 存在理由（2026-10-25 实测事故，非理论推演）：
// 13 题 LLM 评测单通道跑，AMD 通道当晚 429 抖动触发 **37 次重试**，其中
// **3 次重试耗尽直接杀死 2003/2008/2011 三题**（2003 在基线里是可解的）。
// 即：**通道一抖，得分链整条失能** —— 单通道依赖是决赛级 SPOF。
//
// 与既有 failover 的分工（避免重复造轮子）：
//   - `internal/multiagent/eino_model_resilience.go` 已用 eino ADK 原生
//     `adk.ModelFailoverConfig` 服务 **agent 对话路径**（走 config.yaml ai.channels）；
//   - 但 **CTF 解题链两处都没接**：`internal/runnerl3`（生产，env 单通道）与
//     `internal/ctfplatform` 评测 harness（裸 HTTP 单通道 + 4 次重试）。
//     本包正是补这两处，让它们共用同一份「已验证免费通道」清单与错误分类口径。
//
// 通道清单来源：`E:\Program\免费Token总账.md`（2026-10-25 用户确认「目前这些都可以」）。
// 清单一律记 **key 的环境变量名**，绝不记 key 值本身（第六条交付红线）。
package llmchannel

import (
	"context"
	"errors"
	"os"
	"strings"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
)

// BuiltinChannel 内置通道的静态定义（不含 key 值）。
type BuiltinChannel struct {
	ID        string // 通道 ID（用于 RUNNER_LLM_FAILOVER_CHANNELS 指定顺序）
	BaseURL   string
	Model     string
	KeyEnv    string // key 所在环境变量名；匿名通道为空
	Anonymous bool   // 无需 key 的通道（kilo / pollinations）
	Note      string // 免费档限制（仅注释，不参与逻辑）
}

// builtinOrder 按「免费档稳健性 + 质量」排优先级：
// 不限量 → 大额度 → 小额度 → 本地网关 → 匿名兜底。
// 顺序即默认 failover 顺序；改顺序等于改决赛可用性，必须留痕。
var builtinOrder = []BuiltinChannel{
	{ID: "zhipu", BaseURL: "https://open.bigmodel.cn/api/paas/v4", Model: "glm-4-flash", KeyEnv: "ZHIPU_API_KEY", Note: "永久免费不限量"},
	{ID: "modelscope", BaseURL: "https://api-inference.modelscope.cn/v1", Model: "deepseek-ai/DeepSeek-V4-Flash-0731", KeyEnv: "MODELSCOPE_API_KEY", Note: "2000 次/日"},
	{ID: "amd", BaseURL: "https://developer.amd.com.cn/radeon/api/v1", Model: "DeepSeek-V4-Flash", KeyEnv: "AMD_API_KEY", Note: "20rpm/$1 每日 —— 2026-10-25 实测 429 抖动最凶"},
	{ID: "tokenhub", BaseURL: "https://tokenhub.tencentmaas.com/v1", Model: "glm-5.3-flash", KeyEnv: "TOKENHUB_API_KEY", Note: "一次性额度包（非按日刷新）"},
	{ID: "openrouter", BaseURL: "https://openrouter.ai/api/v1", Model: "nvidia/nemotron-3.5-lightning:free", KeyEnv: "OPENROUTER_API_KEY", Note: "50 次/日共享"},
	{ID: "xfyun", BaseURL: "https://spark-api-open.xf-yun.com/v1", Model: "lite", KeyEnv: "XFYUN_API_KEY", Note: "免费档"},
	// 本地网关：只有 opencode serve 在跑时可用，故排在远端通道之后。
	{ID: "ofm", BaseURL: "http://127.0.0.1:18899/v1", Model: "deepseek-v4.1-flash-free", KeyEnv: "OFM_API_KEY", Note: "本地网关（可能未启动）"},
	{ID: "kilo", BaseURL: "https://api.kilo.ai/api/gateway/v1", Model: "cohere/north-mini-code:free", Anonymous: true, Note: "匿名"},
	{ID: "pollinations", BaseURL: "https://text.pollinations.ai/v1", Model: "", Anonymous: true, Note: "匿名兜底，质量差"},
}

// Channel 是解析后的可用通道（含从环境读到的 key）。
type Channel struct {
	ID      string
	BaseURL string
	Model   string
	APIKey  string
}

// BuiltinOrder 返回内置通道的静态定义副本（供测试与文档核对）。
func BuiltinOrder() []BuiltinChannel {
	out := make([]BuiltinChannel, len(builtinOrder))
	copy(out, builtinOrder)
	return out
}

// Options 解析选项。零值 = 全按内置优先级 + 从 os.Getenv 读 key。
type Options struct {
	// Only 显式指定通道 ID 顺序（逗号分隔解析后的结果）；为空则用内置优先级。
	Only []string
	// KeyLookup key 读取函数；nil 时默认 os.Getenv。
	KeyLookup func(string) string
}

// Resolve 产出「主通道 + 备用通道」的有序列表。
//
// 规则（每条都可测）：
//  1. primary 非空且已解析出 key → 排在第一位；
//  2. 内置清单按优先级（或 Only 指定的顺序）依次加入；
//  3. 去重：(BaseURL, Model) 完全相同者只留先出现的（含与主通道重复）；
//  4. 跳过「非匿名且 key 为空」的通道 —— 没 key 的通道加进来只会白烧一次超时；
//  5. 返回值为空是合法的（= 无可用通道），调用方必须按 fail-closed 处理。
func Resolve(primary *Channel, opt Options) []Channel {
	lookup := opt.KeyLookup
	if lookup == nil {
		lookup = os.Getenv
	}

	out := make([]Channel, 0, 8)
	seen := map[string]struct{}{}
	add := func(c Channel) {
		if strings.TrimSpace(c.BaseURL) == "" {
			return
		}
		key := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")) + "|" + strings.TrimSpace(c.Model)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}

	if primary != nil {
		add(*primary)
	}

	ids := builtinOrder
	if len(opt.Only) > 0 {
		// 按 Only 指定的顺序重排内置清单；未识别的 ID 直接忽略（不静默塞进未知通道）。
		ordered := make([]BuiltinChannel, 0, len(opt.Only))
		for _, want := range opt.Only {
			for _, bc := range builtinOrder {
				if strings.EqualFold(strings.TrimSpace(bc.ID), strings.TrimSpace(want)) {
					ordered = append(ordered, bc)
					break
				}
			}
		}
		ids = ordered
	}

	for _, bc := range ids {
		key := ""
		if !bc.Anonymous {
			key = strings.TrimSpace(lookup(bc.KeyEnv))
			if key == "" {
				continue // 规则 4：无 key 不进列表
			}
		}
		add(Channel{ID: bc.ID, BaseURL: bc.BaseURL, Model: bc.Model, APIKey: key})
	}
	return out
}

// ParseChannelIDs 把 "zhipu, amd" / "zhipu\n amd" 形态的文本解析为 ID 列表。
// 空输入返回 nil（= 走内置优先级），不报错。
func ParseChannelIDs(raw string) []string {
	raw = strings.ReplaceAll(raw, "\n", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// IsTransient 判定一次调用失败是否值得切下一个通道。
//
// 判据（fail-closed 取向：不确定就**不切**，避免把其他通道的免费额度烧在一个
// 会全通道复现的 payload bug 上）：
//   - 调用方 ctx 已死（DeadlineExceeded/Canceled）→ 不切：那是我们的预算，不是通道的锅；
//   - HTTP 400 → 不切：payload 错，换通道一样错；
//   - HTTP 401/403（key 无效）/404（该通道没这个模型）/402（额度耗尽）→ 切：通道专属；
//   - HTTP 408/409/425/429/5xx → 切：限流与服务端抖动；
//   - 网络类错误（连接被拒/超时/EOF/TLS/复位）→ 切；
//   - 其余未知错误 → 不切（保守，可留痕排查）。
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}

	var apiErr *einoopenai.APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		return StatusTransient(apiErr.HTTPStatusCode)
	}

	s := strings.ToLower(err.Error())
	for _, frag := range []string{
		"connection refused", "no such host", "i/o timeout", "eof",
		"tls handshake", "connection reset", "connection reset by peer",
		"broken pipe", "network is unreachable", "timeout", "deadline exceeded",
		"429", "rate limit", "too many requests", "502", "503", "504",
		"service unavailable", "bad gateway", "gateway timeout",
	} {
		if strings.Contains(s, frag) {
			return true
		}
	}
	return false
}

// StatusTransient 只按 HTTP 状态码判定是否值得切通道（供裸 HTTP 调用方使用，
// 例如评测 harness —— 它拿不到 eino 的 APIError 类型，只有 "HTTP %d: ..." 文本）。
// 判据与 IsTransient 的状态码分支完全一致，避免两处各写各的漂移。
func StatusTransient(code int) bool {
	switch code {
	case 400:
		return false // payload 错：换通道无用，不烧额度
	case 401, 402, 403, 404:
		return true // key/额度/模型 都是通道专属属性
	case 408, 409, 425, 429:
		return true
	}
	return code >= 500
}
