// llm_fallback —— runner Layer 3: Eino ChatModel 独立调用。
//
// 设计原则：
//   1. 不启动 agent/db/mcp —— 纯 ChatModel.Generate()，零 Web 依赖
//   2. 只做纯文本推理：把题干喂给 LLM，让它输出 flag 候选（纯 flag{...} 格式）
//      - 今天版本没有工具绑定（那是赛后 +3 天的事）
//      - reverse/pwn 需要动态执行二进制 → 留给 Python skill bridge（Layer 2）
//      - crypto/web/misc 需要纯推理 → 这个 Layer 能覆盖
//   3. 依赖门控：RUNNER_LLM_FALLBACK=false 或没有 API key → 自动跳过
//
// Env 变量约定（全部 runner 专属，和 app.go 里的模型配置无关）：
//   RUNNER_LLM_FALLBACK     默认 false，显式 true 才启用
//   RUNNER_LLM_API_KEY      API key（必需，缺则跳过）
//   RUNNER_LLM_BASE_URL     默认 https://api.deepseek.com/v1
//   RUNNER_LLM_MODEL        默认 deepseek-reasoner（推理型模型性价比高）
//   RUNNER_LLM_TIMEOUT_SEC  默认 60 秒
//   RUNNER_LLM_MAX_TOKENS   默认 2048

package main

import (
	"context"
	"os"
	"strings"
	"time"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

type llmFallback struct {
	model   *einoopenai.ChatModel
	logger  *zap.Logger
	enabled bool
}

// newLLMFallback 从 env 变量构造 LLM fallback。缺任何必需项返回 disabled 实例。
// runner 启动时调一次，之后 solver 闭包里读 f.enabled 决定是否调。
func newLLMFallback(ctx context.Context, logger *zap.Logger) *llmFallback {
	if !envBool("RUNNER_LLM_FALLBACK", false) {
		logger.Info("LLM fallback 未启用（RUNNER_LLM_FALLBACK 未设或非 true）")
		return &llmFallback{logger: logger}
	}

	apiKey := strings.TrimSpace(os.Getenv("RUNNER_LLM_API_KEY"))
	if apiKey == "" {
		logger.Warn("LLM fallback 启用但 RUNNER_LLM_API_KEY 未设 → 跳过")
		return &llmFallback{logger: logger}
	}

	baseURL := envOrDefault("RUNNER_LLM_BASE_URL", "https://api.deepseek.com/v1")
	modelName := envOrDefault("RUNNER_LLM_MODEL", "deepseek-reasoner")

	cfg := &einoopenai.ChatModelConfig{
		APIKey:  apiKey,
		BaseURL: baseURL,
		Model:   modelName,
	}

	m, err := einoopenai.NewChatModel(ctx, cfg)
	if err != nil {
		logger.Warn("LLM fallback 初始化失败 → 跳过", zap.Error(err),
			zap.String("base_url", baseURL), zap.String("model", modelName))
		return &llmFallback{logger: logger}
	}

	logger.Info("LLM fallback 就绪",
		zap.String("base_url", baseURL),
		zap.String("model", modelName))

	return &llmFallback{model: m, logger: logger, enabled: true}
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

// solve 把题干喂给 LLM，让它输出 flag 候选列表（flag{...} 格式）。
// 返回 nil, nil 表示要么 disabled、要么 LLM 报错、要么没输出 flag。
// 超时由 ctx 控制（Poller 的 SolveTimeout 已经包了一层）。
func (f *llmFallback) solve(ctx context.Context, title, category, description, attachmentHint string) ([]string, error) {
	if !f.enabled || f.model == nil {
		return nil, nil
	}

	timeout := time.Duration(envInt("RUNNER_LLM_TIMEOUT_SEC", 60)) * time.Second
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	systemPrompt := `你是一个 CTF 解题助手。根据题目描述推理出正确的 flag。

规则：
1. 只输出最终 flag，格式必须是 flag{...}
2. 如果不确定，按"最可能的前 3 个候选"格式输出，每行一个 flag{...}
3. 如果完全无法推理，输出 "NO_SOLUTION"
4. 不要解释推理过程，不要输出代码，只输出 flag`

	userContent := buildLLMPrompt(title, category, description, attachmentHint)

	msgs := []*schema.Message{
		schema.SystemMessage(systemPrompt),
		schema.UserMessage(userContent),
	}

	resp, err := f.model.Generate(callCtx, msgs)
	if err != nil {
		f.logger.Warn("LLM fallback 调用失败",
			zap.String("title", title),
			zap.Error(err))
		return nil, nil
	}

	if resp == nil || len(resp.Content) == 0 {
		return nil, nil
	}

	raw := strings.TrimSpace(resp.Content)
	if strings.Contains(raw, "NO_SOLUTION") {
		return nil, nil
	}

	// 从 LLM 输出里提取所有 flag{...} 候选
	candidates := extractFlagCandidates(raw)
	if len(candidates) == 0 {
		f.logger.Debug("LLM fallback 输出里没找到 flag 格式",
			zap.String("title", title),
			zap.String("raw", truncate(raw, 200)))
		return nil, nil
	}

	f.logger.Info("Layer 3 LLM fallback 命中",
		zap.String("challenge", title),
		zap.String("category", category),
		zap.Strings("candidates", candidates))

	return candidates, nil
}

// buildLLMPrompt 组装 LLM 输入题干。保持简洁——token 是真金白银。
func buildLLMPrompt(title, category, description, attachmentHint string) string {
	var b strings.Builder
	b.WriteString("题目：")
	b.WriteString(title)
	b.WriteString("\n类别：")
	b.WriteString(category)
	if attachmentHint != "" {
		b.WriteString("\n附件信息：")
		b.WriteString(attachmentHint)
	}
	b.WriteString("\n\n题目描述：\n")
	b.WriteString(truncate(description, 8000)) // 限制 token
	return b.String()
}

// extractFlagCandidates 从文本里提取所有 flag{...} 格式的候选。
// 支持常见格式：flag{...} / FLAG{...} / xxxxx{...} 等。
func extractFlagCandidates(text string) []string {
	// 简单正则：找所有 {...} 包围的，前缀通常是 flag 或 FLAG 或 xxxxx
	var flags []string
	seen := make(map[string]bool)

	// 按行分割，每行可能包含一个或多个候选
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		// 找 flag{...} 或 FLAG{...}
		lower := strings.ToLower(line)
		if idx := strings.Index(lower, "flag{"); idx >= 0 {
			end := strings.Index(line[idx:], "}")
			if end > 0 {
				f := strings.TrimSpace(line[idx : idx+end+1])
				f = strings.TrimPrefix(f, "flag: ")
				f = strings.TrimPrefix(f, "FLAG: ")
				if !seen[f] {
					seen[f] = true
					flags = append(flags, f)
				}
			}
		}
	}

	return flags
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(截断)"
}
