package runnerl3

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"

	"secautomind-ai/internal/llmchannel"
)

// 通道 failover（P0-4，2026-10-26）。
//
// 事故起点：2026-10-25 全量 13 题评测，单通道 AMD 当晚 429 抖动 → 37 次重试、
// 3 次重试耗尽直接杀掉 2003/2008/2011（2003 基线可解）。单通道 = 决赛级 SPOF。
//
// 形态：实现 eino `model.BaseChatModel`（= BaseModel[*schema.Message]），
// 对 `LLMFallback.model` 是 drop-in 替换 —— Solve 逐轮 `Generate` 的调用点一行不改。
// eino ChatModel 无状态（消息历史由调用方持有），故「换通道重发同一份 msgs」语义干净。
//
// Env（全部沿用 RUNNER_LLM_* 前缀口径）：
//   RUNNER_LLM_FAILOVER             默认 true；false = 退回旧的单通道路径
//   RUNNER_LLM_FAILOVER_CHANNELS    逗号/换行分隔的通道 ID 顺序；空 = 内置优先级
//   RUNNER_LLM_FAILOVER_COOLDOWN_SEC 单通道失败后冷却秒数；默认 300；0 = 不冷却
//
// 向后兼容：只有主通道时，entries 长度为 1 —— 成功即返回、失败即报错，
// 与改造前行为在 Solve 层完全一致（Solve 对任何 err 都是 warn + nil,nil）。
type failoverChatModel struct {
	entries  []*failoverEntry
	cooldown time.Duration
	logger   *zap.Logger
	now      func() time.Time // 测试注入（冷却窗口必须可脚本化，否则测不了）
}

type failoverEntry struct {
	id  string
	mdl model.BaseChatModel

	mu          sync.Mutex
	cooledUntil time.Time
}

func (e *failoverEntry) ready(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return now.After(e.cooledUntil) || now.Equal(e.cooledUntil)
}

func (e *failoverEntry) cool(until time.Time) {
	e.mu.Lock()
	e.cooledUntil = until
	e.mu.Unlock()
}

func (e *failoverEntry) clearCool() {
	e.mu.Lock()
	e.cooledUntil = time.Time{}
	e.mu.Unlock()
}

// Generate 按优先级尝试各通道：
//   - 成功 → 清掉该通道冷却并返回；
//   - 瞬时错误（429/402/403/404/408/409/425/5xx/网络） → 冷却该通道，切下一个；
//   - 永久错误（400 payload 错 / 调用方 ctx 已死） → 立即返回，不烧其他通道额度；
//   - 全部不可用 → fail-closed 报错（列出试过的通道），绝不返回 nil,nil 假装成功。
func (f *failoverChatModel) Generate(ctx context.Context, in []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	now := f.now()
	tried := make([]string, 0, len(f.entries))
	var lastErr error

	for _, e := range f.entries {
		if ctx.Err() != nil {
			// 调用方预算耗尽：不是通道的锅，不切
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		}
		if !e.ready(now) {
			continue
		}
		tried = append(tried, e.id)
		msg, err := e.mdl.Generate(ctx, in, opts...)
		if err == nil {
			e.clearCool()
			return msg, nil
		}
		lastErr = err
		if !llmchannel.IsTransient(err) {
			return nil, err
		}
		if f.cooldown > 0 {
			e.cool(now.Add(f.cooldown))
		}
		if f.logger != nil {
			f.logger.Warn("LLM 通道瞬时失败 → 冷却并切换下一通道",
				zap.String("channel", e.id),
				zap.Duration("cooldown", f.cooldown),
				zap.Error(err))
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("LLM 全部通道失败（已试 %d 个：%s）：%w",
			len(tried), strings.Join(tried, "→"), lastErr)
	}
	return nil, fmt.Errorf("LLM 无可用通道（%d 个全部冷却中）", len(f.entries))
}

// Stream 与 Generate 同口径切通道，但有 Stream 的硬限制：
// **reader 返回后才发生的错误无法切换**（调用方已持有 reader）。
// 本包 Solve 走 Generate，不受该限制影响；此处只保证「建流失败」可切换。
func (f *failoverChatModel) Stream(ctx context.Context, in []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	now := f.now()
	tried := make([]string, 0, len(f.entries))
	var lastErr error

	for _, e := range f.entries {
		if ctx.Err() != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		}
		if !e.ready(now) {
			continue
		}
		tried = append(tried, e.id)
		sr, err := e.mdl.Stream(ctx, in, opts...)
		if err == nil {
			e.clearCool()
			return sr, nil
		}
		lastErr = err
		if !llmchannel.IsTransient(err) {
			return nil, err
		}
		if f.cooldown > 0 {
			e.cool(now.Add(f.cooldown))
		}
		if f.logger != nil {
			f.logger.Warn("LLM 通道建流失败 → 冷却并切换下一通道",
				zap.String("channel", e.id), zap.Error(err))
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("LLM 全部通道建流失败（已试 %d 个：%s）：%w",
			len(tried), strings.Join(tried, "→"), lastErr)
	}
	return nil, fmt.Errorf("LLM 无可用通道（%d 个全部冷却中）", len(f.entries))
}

// buildFailoverModel 按 env 构造 failover 模型。主通道在前，备用按优先级排后。
// 返回 (模型, 已装填通道 ID 列表, 错误)。
func buildFailoverModel(ctx context.Context, primary llmchannel.Channel, logger *zap.Logger) (model.BaseChatModel, []string, error) {
	cooldown := time.Duration(envInt("RUNNER_LLM_FAILOVER_COOLDOWN_SEC", 300)) * time.Second
	if cooldown < 0 {
		cooldown = 0
	}

	channels := llmchannel.Resolve(&primary, llmchannel.Options{
		Only: llmchannel.ParseChannelIDs(os.Getenv("RUNNER_LLM_FAILOVER_CHANNELS")),
	})

	entries := make([]*failoverEntry, 0, len(channels))
	ids := make([]string, 0, len(channels))
	for _, c := range channels {
		id := c.ID
		if strings.TrimSpace(id) == "" {
			id = "primary"
		}
		m, err := einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
			APIKey:  c.APIKey,
			BaseURL: strings.TrimSuffix(c.BaseURL, "/"),
			Model:   c.Model,
		})
		if err != nil {
			// 建链 fail-soft：单个通道构造坏掉不该让整条 L3 失能；但调用必须 fail-closed。
			if logger != nil {
				logger.Warn("LLM failover 通道构造失败 → 跳过该通道",
					zap.String("channel", id), zap.Error(err))
			}
			continue
		}
		entries = append(entries, &failoverEntry{id: id, mdl: m})
		ids = append(ids, id)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("无可用 LLM 通道（主通道构造亦失败）")
	}
	return &failoverChatModel{
		entries:  entries,
		cooldown: cooldown,
		logger:   logger,
		now:      time.Now,
	}, ids, nil
}
