package robot

import (
	"context"
	"strings"
	"sync"
	"time"

	"secautomind-ai/internal/config"

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"
	"go.uber.org/zap"
)

// dingDedupeTTL 去重窗口。钉钉 ack 超时重投的间隔实测约 60s，10 分钟窗口足够覆盖
// 「处理中 + 处理完成后的迟到重投」两种场景，且不会误伤用户 10 分钟后的新消息
//（钉钉 msgId 全局唯一，同 msgId 重现只可能是重投）。
const dingDedupeTTL = 10 * time.Minute

// dingDedupe 按 msgId 做 TTL 去重：mark 返回 true 表示该 msgId 在窗口内已出现过（重投帧）。
type dingDedupe struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
}

func newDingDedupe(ttl time.Duration) *dingDedupe {
	return &dingDedupe{ttl: ttl, seen: make(map[string]time.Time)}
}

func (d *dingDedupe) mark(id string) bool {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, ts := range d.seen {
		if now.Sub(ts) > d.ttl {
			delete(d.seen, k)
		}
	}
	if _, ok := d.seen[id]; ok {
		return true
	}
	d.seen[id] = now
	return false
}

// dingFrameDispatcher 钉钉消息分发器：立即 ack + 异步处理 + webhook 异步回复。
//
// 🔴 根治的问题：handler 同步阻塞到 Agent 任务跑完（可达数分钟），SDK 要等 handler
// 返回才发 ack → 钉钉判定 ack 超时，把同一条消息原样重投（实测 60s 一次）→
// 重投帧撞上会话任务锁，给用户回「当前会话已有任务正在执行中」的假错误。
// 用户只发过一条消息，重投是钉钉机制，错在我们 ack 太慢。
//
// 方案（依赖一个实测事实：Stream 机器人帧中 SessionWebhook **有值**——线上所有 ack
// data 恒为空串但用户能收到回复，证明回复一直走的是 webhook POST 路径）：
//   - 有 webhook：msgId 去重后转 goroutine 异步处理，本调用立即返回空 → SDK 马上
//     ack 200 → 钉钉不再重投；处理完成后经 SessionWebhook POST 回复（webhook 本身
//     带 sessionWebhookExpiredTime 有效期，长任务后仍可 POST）。
//   - webhook 为空 / 无 msgId（异常形态）：保留同步旧路径，经 Stream 返回值回复，
//     保证任何形态下消息都不丢。
type dingFrameDispatcher struct {
	cfg                config.RobotDingtalkConfig
	strictUserIdentity bool
	h                  MessageHandler
	logger             *zap.Logger
	dedupe             *dingDedupe
}

func newDingFrameDispatcher(cfg config.RobotDingtalkConfig, strictUserIdentity bool, h MessageHandler, logger *zap.Logger) *dingFrameDispatcher {
	return &dingFrameDispatcher{
		cfg:                cfg,
		strictUserIdentity: strictUserIdentity,
		h:                  h,
		logger:             logger,
		dedupe:             newDingDedupe(dingDedupeTTL),
	}
}

// dispatch 处理一帧回调，返回值仅用于同步路径（经 Stream ack data 回复）；
// 异步路径恒返回空串（回复由 webhook POST 完成）。
func (d *dingFrameDispatcher) dispatch(ctx context.Context, msg *chatbot.BotCallbackDataModel) string {
	if msg == nil {
		return ""
	}
	if strings.TrimSpace(msg.SessionWebhook) == "" || strings.TrimSpace(msg.MsgId) == "" {
		// 异常形态兜底：同步处理并经 Stream 返回值回复。
		return processDingMessage(ctx, msg, d.cfg, d.strictUserIdentity, d.h, d.logger)
	}
	if d.dedupe.mark(strings.TrimSpace(msg.MsgId)) {
		d.logger.Info("钉钉重复帧已吞并（同一 msgId 已在处理/已处理，立即 ack 防重投风暴）",
			zap.String("msg_id", msg.MsgId))
		return ""
	}
	d.logger.Info("钉钉消息转异步处理（立即 ack，防超时重投）", zap.String("msg_id", msg.MsgId))
	go func() {
		// 独立 context：不依赖回调 ctx（SDK 用 Background 调 handler，但显式自管更稳）。
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		_ = processDingMessage(bgCtx, msg, d.cfg, d.strictUserIdentity, d.h, d.logger)
	}()
	return ""
}
