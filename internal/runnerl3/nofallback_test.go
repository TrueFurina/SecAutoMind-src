package runnerl3

import (
	"context"
	"strings"
	"testing"
	"time"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"secautomind-ai/internal/llmchannel"
)

// 这组测试锁的是 2026-11-01 那批"标称 deepseek-v4-pro、实际由
// cohere/north-mini-code:free 作答"事故的两条对策：
//   1) RUNNER_LLM_NO_FALLBACK=1 时只留主通道（评测要诚实）；
//   2) 任何一次降级都必须在 WARN 里留痕（事后能回答"谁答的题"）。
//
// 反证同样重要：默认必须仍然展开匿名通道——否则赛时通道一抖就整题失能，
// 那是本包存在的原始理由（2026-10-25 单通道 429 杀死 3 题）。

// clearChannelKeys 清空内置通道的 key，让 Resolve 的结果只取决于
// 「匿名通道」与「主通道」两条规则，测试才可复现。
func clearChannelKeys(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"ZHIPU_API_KEY", "MODELSCOPE_API_KEY", "AMD_API_KEY",
		"TOKENHUB_API_KEY", "OPENROUTER_API_KEY", "XFYUN_API_KEY", "OFM_API_KEY",
	} {
		t.Setenv(k, "")
	}
}

func primaryChannel() llmchannel.Channel {
	return llmchannel.Channel{
		BaseURL: "https://primary.invalid/v1",
		Model:   "strong-model",
		APIKey:  "test-key",
	}
}

func TestNoFallbackKeepsOnlyPrimary(t *testing.T) {
	clearChannelKeys(t)
	t.Setenv("RUNNER_LLM_NO_FALLBACK", "1")
	t.Setenv("RUNNER_LLM_FAILOVER_CHANNELS", "")

	_, ids, err := buildFailoverModel(context.Background(), primaryChannel(), nil)
	if err != nil {
		t.Fatalf("NO_FALLBACK=1 时主通道应能构造，实际 err=%v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("NO_FALLBACK=1 应只保留主通道，实际装了 %d 个：%v", len(ids), ids)
	}
}

func TestDefaultStillExpandsAnonymousChannels(t *testing.T) {
	clearChannelKeys(t)
	t.Setenv("RUNNER_LLM_NO_FALLBACK", "")
	t.Setenv("RUNNER_LLM_FAILOVER_CHANNELS", "")

	_, ids, err := buildFailoverModel(context.Background(), primaryChannel(), nil)
	if err != nil {
		t.Fatalf("默认配置应能构造，实际 err=%v", err)
	}
	// 反证：默认必须展开，否则赛时不具备容错能力（回到单通道 SPOF）。
	if len(ids) < 2 {
		t.Fatalf("默认应展开备用通道，实际只有 %v", ids)
	}
	hasAnonymous := false
	for _, id := range ids {
		if id == "kilo" || id == "pollinations" {
			hasAnonymous = true
		}
	}
	if !hasAnonymous {
		t.Fatalf("匿名通道（kilo/pollinations）应无条件进链——这正是要防的污染源，实际 %v", ids)
	}
}

func TestDowngradeToBackupIsLogged(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ch1 := &scriptedModel{id: "primary", respond: func(int) (*schema.Message, error) {
		return nil, &einoopenai.APIError{HTTPStatusCode: 403, Message: "free quota exhausted"}
	}}
	ch2 := &scriptedModel{id: "kilo", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}

	core, logs := observer.New(zapcore.WarnLevel)
	f := &failoverChatModel{
		entries:  []*failoverEntry{{id: ch1.id, mdl: ch1}, {id: ch2.id, mdl: ch2}},
		cooldown: 300 * time.Second,
		logger:   zap.New(core),
		now:      func() time.Time { return now },
	}

	if _, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("期望降级到备用通道后成功，实际 err=%v", err)
	}

	var found bool
	for _, e := range logs.All() {
		if !strings.Contains(e.Message, "降级到备用通道") {
			continue
		}
		found = true
		if got := e.ContextMap()["used"]; got != "kilo" {
			t.Fatalf("留痕里的 used 应为 kilo（真正作答的通道），实际 %v", got)
		}
	}
	if !found {
		t.Fatalf("降级必须留痕，实际日志条目：%+v", logs.All())
	}
}

func TestNoDowngradeNoWarnOnPrimarySuccess(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ch1 := &scriptedModel{id: "primary", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}

	core, logs := observer.New(zapcore.WarnLevel)
	f := &failoverChatModel{
		entries: []*failoverEntry{{id: ch1.id, mdl: ch1}},
		logger:  zap.New(core),
		now:     func() time.Time { return now },
	}

	if _, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("主通道成功不应报错，实际 err=%v", err)
	}
	// 反证：主通道正常时不许刷"降级"WARN，否则日志被噪声淹没，真降级反而看不见。
	for _, e := range logs.All() {
		if strings.Contains(e.Message, "降级") {
			t.Fatalf("主通道成功时不应出现降级告警，实际：%s", e.Message)
		}
	}
}
