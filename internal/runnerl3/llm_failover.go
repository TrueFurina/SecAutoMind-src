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
//
//	RUNNER_LLM_FAILOVER             默认 true；false = 退回旧的单通道路径
//	RUNNER_LLM_FAILOVER_CHANNELS    逗号/换行分隔的通道 ID 顺序；空 = 内置优先级
//	RUNNER_LLM_FAILOVER_COOLDOWN_SEC 单通道失败后冷却秒数；默认 300；0 = 不冷却
//	RUNNER_LLM_NO_FALLBACK          默认 false；true = **只用主通道，禁止降级到备用/匿名通道**
//	RUNNER_LLM_RATELIMIT_RETRY      默认 false；true = 402/429 先在同一通道退避重试（见 retryRateLimit）
//	RUNNER_LLM_RATELIMIT_MAX_RETRIES 重试上限，默认 6（0 = 不重试，退回旧切通道语义）
//	RUNNER_LLM_RATELIMIT_BACKOFF_SEC 首次退避秒数，默认 2，指数增长到 60s 封顶
//
// 为什么需要 NO_FALLBACK（2026-11-01 实证，非理论）：
// 内置清单里 `kilo`/`pollinations` 是**匿名通道**（不需要 key），
// 所以 Resolve 无论配了什么都会把它们塞进链尾。真实后果是主通道 403 之后
// 请求落到 `cohere/north-mini-code:free`，而跑批报告仍按 env 写
// `model=deepseek-v4-pro-0813` —— 于是**弱模型的成绩被记在强模型名下**。
// 这不是"分母污染"（那种已由 ErrLLMUnavailable 处理），而是**归属伪造**，
// 且失败与成功时都无声。赛时要的是"不许死"，评测要的是"不许冒充"，故做成开关：
// 赛时默认（false）保留 failover，评测跑必须显式 export RUNNER_LLM_NO_FALLBACK=1。
//
// 向后兼容：只有主通道时，entries 长度为 1 —— 成功即返回、失败即报错，
// 与改造前行为在 Solve 层完全一致（Solve 对任何 err 都是 warn + nil,nil）。
type failoverChatModel struct {
	entries  []*failoverEntry
	cooldown time.Duration
	logger   *zap.Logger
	now      func() time.Time // 测试注入（冷却窗口必须可脚本化，否则测不了）

	// 402/429 同通道退避重试（opt-in，默认关）。
	// 开启后，瞬时在途/限流错不再立即切通道，而是在**同一通道**上退避重试，
	// 耗尽重试上限才退回既有 failover（冷却+切下一通道）。
	// 这是 OpenRouter「按在途请求计额度」场景下根治 batch1 式「23 题在途打穿额度→级联 SKIP」的关键；
	// 默认关闭以保留「瞬时错即切通道」的旧语义，不破坏既有 failover 设计与测试。
	rlRetry      bool
	rlMaxRetries int
	rlBackoff    time.Duration
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
		var msg *schema.Message
		var err error
		if f.rlRetry {
			// 402/429 同通道退避重试：先等瞬时在途/限流落定，避免立即切通道把整轮打崩。
			msg, err = f.retryRateLimitMsg(ctx, e, func() (*schema.Message, error) {
				return e.mdl.Generate(ctx, in, opts...)
			})
		} else {
			msg, err = e.mdl.Generate(ctx, in, opts...)
		}
		if err == nil {
			e.clearCool()
			// 降级留痕：一旦不是主通道完成的生成，必须显式记录。
			// 否则结果会被当成主通道（通常是 env 里那个强模型）的成绩 ——
			// 2026-11-01 那批"报告写 deepseek-v4-pro、实际由 cohere/north-mini-code 作答"
			// 就是这样无声发生的。日志是唯一能事后区分"谁答的"的证据。
			if len(tried) > 1 && f.logger != nil {
				f.logger.Warn("LLM 已降级到备用通道完成本轮生成（成绩归属 ≠ 主通道）",
					zap.String("used", e.id),
					zap.Int("failed_before", len(tried)-1),
					zap.Strings("tried_order", tried))
			}
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
		var sr *schema.StreamReader[*schema.Message]
		var err error
		if f.rlRetry {
			sr, err = f.retryRateLimitStream(ctx, e, func() (*schema.StreamReader[*schema.Message], error) {
				return e.mdl.Stream(ctx, in, opts...)
			})
		} else {
			sr, err = e.mdl.Stream(ctx, in, opts...)
		}
		if err == nil {
			e.clearCool()
			// 与 Generate 同口径留痕（见该处注释）。
			if len(tried) > 1 && f.logger != nil {
				f.logger.Warn("LLM 已降级到备用通道建流（成绩归属 ≠ 主通道）",
					zap.String("used", e.id),
					zap.Int("failed_before", len(tried)-1),
					zap.Strings("tried_order", tried))
			}
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

// retryRateLimit 对 402/429 在**同一通道**上做有界退避重试（不切通道、不冷却）。
// fn 是一次通道调用；返回 (结果, err)。
//   - 成功 → 立即返回；
//   - 非 402/429 错误 → 立即透传，交给外层 failover（冷却 / 切下一通道 / fail-closed）；
//   - 402/429 → 退避后重试同一通道，直到成功、ctx 死亡、或达到 rlMaxRetries 上限。
//
// 为什么这能根治 batch1 式崩法：OpenRouter 按「在途请求」计额度，23 题并发会瞬时
// 撞 402（"Retry after in-flight requests settle"）。旧逻辑把 402 当切通道信号 →
// 单通道下无处可切 → 整轮级联 SKIPPED。本方法让同一通道在 402 时退避等请求落定，
// 额度释放后即可续跑，且带指数退避（封顶 60s）+ ctx 感知，绝不死循环烧额度。
func (f *failoverChatModel) retryRateLimitMsg(ctx context.Context, e *failoverEntry, fn func() (*schema.Message, error)) (*schema.Message, error) {
	var zero *schema.Message
	var err error
	backoff := f.rlBackoff
	for attempt := 0; ; attempt++ {
		res, callErr := fn()
		if callErr == nil {
			return res, nil
		}
		err = callErr
		if attempt >= f.rlMaxRetries {
			return zero, err
		}
		code := llmchannel.APIStatusCode(err)
		if !llmchannel.StatusRetryableRateLimit(code) {
			return zero, err
		}
		if f.logger != nil {
			f.logger.Warn("LLM 通道 402/429 → 退避后重试同一通道（不切通道）",
				zap.String("channel", e.id),
				zap.Int("attempt", attempt+1),
				zap.Int("code", code),
				zap.Duration("backoff", backoff))
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

func (f *failoverChatModel) retryRateLimitStream(ctx context.Context, e *failoverEntry, fn func() (*schema.StreamReader[*schema.Message], error)) (*schema.StreamReader[*schema.Message], error) {
	var zero *schema.StreamReader[*schema.Message]
	var err error
	backoff := f.rlBackoff
	for attempt := 0; ; attempt++ {
		res, callErr := fn()
		if callErr == nil {
			return res, nil
		}
		err = callErr
		if attempt >= f.rlMaxRetries {
			return zero, err
		}
		code := llmchannel.APIStatusCode(err)
		if !llmchannel.StatusRetryableRateLimit(code) {
			return zero, err
		}
		if f.logger != nil {
			f.logger.Warn("LLM 通道 402/429 → 退避后重试同一通道（不切通道）",
				zap.String("channel", e.id),
				zap.Int("attempt", attempt+1),
				zap.Int("code", code),
				zap.Duration("backoff", backoff))
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

// channelLabel 给出通道的「ID/模型」可读标签，用于回答"这一轮到底谁答的题"。
// 主通道可能没设 ID（env 直连形态），此时统一显示 primary，与 entries 的兜底一致。
func channelLabel(c llmchannel.Channel) string {
	id := strings.TrimSpace(c.ID)
	if id == "" {
		id = "primary"
	}
	return id + "/" + c.Model
}

// buildFailoverModel 按 env 构造 failover 模型。主通道在前，备用按优先级排后。
// 返回 (模型, 已装填通道 ID 列表, 错误)。
func buildFailoverModel(ctx context.Context, primary llmchannel.Channel, logger *zap.Logger) (model.BaseChatModel, []string, error) {
	cooldown := time.Duration(envInt("RUNNER_LLM_FAILOVER_COOLDOWN_SEC", 300)) * time.Second
	if cooldown < 0 {
		cooldown = 0
	}

	// 402/429 同通道退避重试（默认关；跑批受瞬时在途/限流困扰时由 batch 脚本开启）。
	rlRetry := envBool("RUNNER_LLM_RATELIMIT_RETRY", false)
	rlMaxRetries := envInt("RUNNER_LLM_RATELIMIT_MAX_RETRIES", 6)
	if rlMaxRetries < 0 {
		rlMaxRetries = 0
	}
	rlBackoff := time.Duration(envInt("RUNNER_LLM_RATELIMIT_BACKOFF_SEC", 2)) * time.Second
	if rlBackoff < 0 {
		rlBackoff = 0
	}

	channels := llmchannel.Resolve(&primary, llmchannel.Options{
		Only: llmchannel.ParseChannelIDs(os.Getenv("RUNNER_LLM_FAILOVER_CHANNELS")),
	})

	// 评测模式：只留主通道（见文件头 NO_FALLBACK 说明）。
	// 截断而非"不 Resolve"：Resolve 保证主通道排第一（规则 1），
	// 直接切 [:1] 就不会有"主通道被内置清单顶掉"的可能。
	if envBool("RUNNER_LLM_NO_FALLBACK", false) && len(channels) > 1 {
		if logger != nil {
			dropped := make([]string, 0, len(channels)-1)
			for _, c := range channels[1:] {
				dropped = append(dropped, channelLabel(c))
			}
			logger.Info("RUNNER_LLM_NO_FALLBACK=1 → 只使用主通道，已丢弃备用/匿名通道",
				zap.String("keep", channelLabel(channels[0])),
				zap.Int("dropped", len(dropped)),
				zap.Strings("dropped_channels", dropped))
		}
		channels = channels[:1]
	}

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
		entries:      entries,
		cooldown:     cooldown,
		logger:       logger,
		now:          time.Now,
		rlRetry:      rlRetry,
		rlMaxRetries: rlMaxRetries,
		rlBackoff:    rlBackoff,
	}, ids, nil
}
