package multiagent

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/summarization"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

const (
	toolOutputTruncationMarker = "\n\n...[tool output truncated; full text persisted in reduction cache or summarization transcript]...\n\n"
	aggressiveToolTruncDivisor = 4
	keySnippetMarker           = "\n\n...◆[0-token 正则节选关键行]◆...\n"
)

// keyLinePatterns 0-token 正则节选模式：工具输出被截断前，先按这些模式提取高价值行
// （flag/凭证/URL/报错/开放端口），使关键信息不因截断丢失 —— 对应创新点
// 「节约 token：正则节选实现 0 token 关键信息提取」。
var keyLinePatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"flag", regexp.MustCompile(`(?i)(flag|ctf|key)\s*[=:：]?\s*\{[^}]{4,}\}`)},
	{"url", regexp.MustCompile(`https?://[^\s"'<>]{8,}`)},
	{"cred", regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|credential)\s*[=:：]\s*\S{4,}`)},
	{"err", regexp.MustCompile(`(?i)\b(error|failed|denied|refused|timeout|panic)\b[^\n]{0,70}`)},
	{"port", regexp.MustCompile(`(?i)(?:[0-9]{1,5}/(?:tcp|udp)\s+[a-z0-9/_.:-]{0,24}\s+(?:open|closed|filtered))|(?:\b(?:open|closed|filtered)\b[^\n]{0,24}\b[0-9]{1,5}/(?:tcp|udp))`)},
}

// extractKeySnippets 在截断前对工具输出逐行做正则节选，返回命中的关键行片段。
// 命中数量受预算约束（粗略按字节，避免节选本身超预算）。
func extractKeySnippets(content string, maxBytes int) []string {
	if content == "" || maxBytes <= 0 {
		return nil
	}
	var snippets []string
	seen := make(map[string]bool)
	budget := maxBytes / 3 // 节选预算：最多占截断预算 1/3
	used := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || len(trimmed) > 200 {
			continue
		}
		hit := false
		for _, p := range keyLinePatterns {
			if p.re.MatchString(trimmed) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		// 去重 + 预算控制
		key := strings.ToLower(trimmed)
		if seen[key] {
			continue
		}
		seen[key] = true
		if used+len(trimmed)+2 > budget {
			break
		}
		snippets = append(snippets, trimmed)
		used += len(trimmed) + 2
	}
	return snippets
}

// truncateToolContentWithKeySnippets 组合：优先保留正则节选关键行，再截断其余部分。
// 命中关键行时返回「关键行 + 截断标记」；未命中则退回纯字节截断（0-token 节选不增开销）。
func truncateToolContentWithKeySnippets(content string, maxBytes int, marker string) string {
	if maxBytes <= 0 || len(content) <= maxBytes {
		return content
	}
	if marker == "" {
		marker = toolOutputTruncationMarker
	}
	snippets := extractKeySnippets(content, maxBytes)
	if len(snippets) == 0 {
		return truncateBytesWithMarker(content, maxBytes, marker)
	}
	joined := strings.Join(snippets, "\n")
	head := keySnippetMarker + joined + "\n"
	remain := maxBytes - len(head)
	if remain < 60 {
		// 关键行已占满预算：直接返回关键行（尾部裁剪到预算）
		if len(head) > maxBytes {
			return head[:maxBytes]
		}
		return head
	}
	// 其余正文按剩余预算截断，并标记全文已持久化
	rest := truncateBytesWithMarker(content, remain, marker)
	return head + rest
}

// isEinoContextOverflowError reports API-side context window rejections.
func isEinoContextOverflowError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	markers := []string{
		"context length",
		"context_length",
		"maximum context",
		"max context",
		"context window",
		"context overflow",
		"too many tokens",
		"token limit",
		"tokens exceed",
		"exceeds the context",
		"input is too long",
		"prompt is too long",
		"request too large",
	}
	for _, m := range markers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

func truncateBytesWithMarker(content string, maxBytes int, marker string) string {
	if maxBytes <= 0 || len(content) <= maxBytes {
		return content
	}
	if marker == "" {
		marker = toolOutputTruncationMarker
	}
	budget := maxBytes - len(marker)
	if budget <= 0 {
		if len(marker) > maxBytes {
			return marker[:maxBytes]
		}
		return marker
	}
	head := budget / 2
	tail := budget - head
	for head > 0 && !utf8.RuneStart(content[head]) {
		head--
	}
	tailStart := len(content) - tail
	for tailStart < len(content) && !utf8.RuneStart(content[tailStart]) {
		tailStart++
	}
	return content[:head] + marker + content[tailStart:]
}

func cloneMessage(msg adk.Message) adk.Message {
	if msg == nil {
		return nil
	}
	cloned := *msg
	return &cloned
}

func truncateMessageToolContent(msg adk.Message, maxBytes int, spillRef string) adk.Message {
	if msg == nil || maxBytes <= 0 {
		return msg
	}
	out := cloneMessage(msg)
	marker := toolOutputTruncationMarker
	if spillRef != "" {
		marker = fmt.Sprintf("\n\n...[tool output truncated; retrieve full text via: %s]...\n\n", spillRef)
	}
	switch out.Role {
	case schema.Tool:
		// 0-token 正则节选：工具输出先按关键模式提取（flag/URL/凭证/报错/端口），
		// 再截断其余正文，保证关键信息不因截断丢失（创新点「正则节选 0 token 提效」）。
		out.Content = truncateToolContentWithKeySnippets(out.Content, maxBytes, marker)
	case schema.Assistant:
		if out.ReasoningContent != "" {
			out.ReasoningContent = truncateBytesWithMarker(out.ReasoningContent, maxBytes, marker)
		}
		if out.Content != "" {
			out.Content = truncateBytesWithMarker(out.Content, maxBytes, marker)
		}
	case schema.User:
		if out.Content != "" {
			out.Content = truncateBytesWithMarker(out.Content, maxBytes, marker)
		}
	}
	return out
}

func countMessagesTokens(
	ctx context.Context,
	msgs []adk.Message,
	counter summarization.TokenCounterFunc,
	tools []*schema.ToolInfo,
) (int, error) {
	if counter == nil {
		return 0, nil
	}
	n, err := counter(ctx, &summarization.TokenCounterInput{Messages: msgs, Tools: tools})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func truncateRoundMessagesToTokenBudget(
	ctx context.Context,
	round messageRound,
	tokenBudget int,
	counter summarization.TokenCounterFunc,
	toolMaxBytes int,
	spillRef string,
) ([]adk.Message, error) {
	if tokenBudget <= 0 || len(round.messages) == 0 {
		return nil, nil
	}
	msgs := append([]adk.Message(nil), round.messages...)
	if n, err := countMessagesTokens(ctx, msgs, counter, nil); err != nil {
		return nil, err
	} else if n <= tokenBudget {
		return msgs, nil
	}
	if toolMaxBytes <= 0 {
		toolMaxBytes = 12000
	}
	for pass := 0; pass < 8 && toolMaxBytes >= 32; pass++ {
		out := make([]adk.Message, 0, len(msgs))
		for _, msg := range msgs {
			switch {
			case msg != nil && msg.Role == schema.Tool:
				out = append(out, truncateMessageToolContent(msg, toolMaxBytes, spillRef))
			case msg != nil && msg.Role == schema.Assistant:
				out = append(out, truncateMessageToolContent(msg, toolMaxBytes, spillRef))
			default:
				out = append(out, msg)
			}
		}
		n, err := countMessagesTokens(ctx, out, counter, nil)
		if err != nil {
			return nil, err
		}
		if n <= tokenBudget {
			return out, nil
		}
		msgs = out
		toolMaxBytes /= 2
	}
	return msgs, nil
}

type compactMessagesOpts struct {
	maxTokens    int
	counter      summarization.TokenCounterFunc
	toolMaxBytes int
	spillRef     string
	aggressive   bool
	logger       *zap.Logger
	phase        string
}

func compactMessagesByDroppingRounds(
	ctx context.Context,
	messages []adk.Message,
	opts compactMessagesOpts,
) ([]adk.Message, bool) {
	if opts.maxTokens <= 0 || len(messages) == 0 || opts.counter == nil {
		return messages, false
	}
	before, err := countMessagesTokens(ctx, messages, opts.counter, nil)
	if err != nil || before <= opts.maxTokens {
		return messages, false
	}

	systems := make([]adk.Message, 0, 1)
	contextMsgs := make([]adk.Message, 0, len(messages))
	for _, msg := range messages {
		if msg != nil && msg.Role == schema.System && len(contextMsgs) == 0 {
			systems = append(systems, msg)
			continue
		}
		if msg != nil {
			contextMsgs = append(contextMsgs, msg)
		}
	}
	rounds := splitMessagesIntoRounds(contextMsgs)
	if len(rounds) == 0 {
		return messages, false
	}

	startIdx := 0
	if opts.aggressive {
		startIdx = len(rounds) - 1
		if startIdx < 0 {
			startIdx = 0
		}
	}
	dropped := 0
	for len(rounds) > 1 || (opts.aggressive && len(rounds) == 1) {
		if !opts.aggressive && len(rounds) <= 1 {
			break
		}
		if opts.aggressive && len(rounds) == 1 {
			// Fall through to latest-round truncation below.
			break
		}
		rounds = rounds[1:]
		dropped++
		candidate := append([]adk.Message(nil), systems...)
		for _, round := range rounds {
			candidate = append(candidate, round.messages...)
		}
		after, countErr := countMessagesTokens(ctx, candidate, opts.counter, nil)
		if countErr != nil {
			break
		}
		if after <= opts.maxTokens {
			if opts.logger != nil {
				opts.logger.Warn("eino context compacted by dropping older rounds",
					zap.String("phase", opts.phase),
					zap.Int("tokens_before", before),
					zap.Int("tokens_after", after),
					zap.Int("max_tokens", opts.maxTokens),
					zap.Int("dropped_rounds", dropped),
					zap.Bool("aggressive", opts.aggressive),
				)
			}
			return candidate, true
		}
		if opts.aggressive {
			break
		}
	}

	if len(rounds) == 0 {
		return messages, false
	}
	latest := rounds[len(rounds)-1]
	truncated, truncErr := truncateRoundMessagesToTokenBudget(
		ctx, latest, opts.maxTokens, opts.counter, opts.toolMaxBytes, opts.spillRef,
	)
	if truncErr != nil || len(truncated) == 0 {
		if opts.logger != nil {
			opts.logger.Warn("eino context still above budget after round compaction; passing through without local error",
				zap.String("phase", opts.phase),
				zap.Int("tokens_before", before),
				zap.Int("max_tokens", opts.maxTokens),
				zap.Bool("aggressive", opts.aggressive),
			)
		}
		return messages, false
	}
	candidate := append([]adk.Message(nil), systems...)
	if dropped > 0 || startIdx > 0 {
		for _, round := range rounds[:len(rounds)-1] {
			candidate = append(candidate, round.messages...)
		}
	}
	candidate = append(candidate, truncated...)
	after, countErr := countMessagesTokens(ctx, candidate, opts.counter, nil)
	if countErr != nil {
		return messages, false
	}
	if opts.logger != nil {
		opts.logger.Warn("eino context compacted by truncating latest round tool output",
			zap.String("phase", opts.phase),
			zap.Int("tokens_before", before),
			zap.Int("tokens_after", after),
			zap.Int("max_tokens", opts.maxTokens),
			zap.Int("dropped_rounds", dropped),
			zap.Bool("aggressive", opts.aggressive),
		)
	}
	return candidate, true
}

func aggressiveCompactMessagesForOverflow(
	ctx context.Context,
	messages []adk.Message,
	maxTotalTokens int,
	modelName string,
	toolMaxBytes int,
	phase string,
	logger *zap.Logger,
) []adk.Message {
	if len(messages) == 0 || maxTotalTokens <= 0 {
		return messages
	}
	budget := maxTotalTokens * 70 / 100
	if budget < 4096 {
		budget = 4096
	}
	aggressiveToolMax := toolMaxBytes / aggressiveToolTruncDivisor
	if aggressiveToolMax < 2048 {
		aggressiveToolMax = 2048
	}
	out, _ := compactMessagesByDroppingRounds(ctx, messages, compactMessagesOpts{
		maxTokens:    budget,
		counter:      einoSummarizationTokenCounter(modelName),
		toolMaxBytes: aggressiveToolMax,
		aggressive:   true,
		logger:       logger,
		phase:        phase,
	})
	return out
}
