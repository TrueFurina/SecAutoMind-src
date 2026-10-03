package robot

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"secautomind-ai/internal/config"

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/client"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/payload"
	dingutils "github.com/open-dingtalk/dingtalk-stream-sdk-go/utils"
	"go.uber.org/zap"
)

const (
	dingReconnectInitial = 5 * time.Second  // 首次重连间隔
	dingReconnectMax     = 60 * time.Second // 最大重连间隔
)

// StartDing 启动钉钉 Stream 长连接（无需公网），收到消息后调用 handler 处理并回复。
// 断线（如笔记本睡眠、网络中断）后会自动重连；ctx 被取消时退出，便于配置变更时重启。
func StartDing(ctx context.Context, robotsCfg config.RobotsConfig, h MessageHandler, logger *zap.Logger) {
	cfg := robotsCfg.Dingtalk
	if !cfg.Enabled || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return
	}
	go runDingLoop(ctx, cfg, robotsCfg.Session.StrictUserIdentityEnabled(), h, logger)
}

// runDingLoop 维持钉钉长连接。
//
// 关键：SDK 的 StreamClient.Start() 是**同步且会自行守护**的——
//   - 它在 client.go 内部完成 网关取票 → WebSocket 拨号 → 成功后启动 processLoop goroutine → 返回 nil；
//   - SDK 默认开启 WithAutoReconnect(true)，断线时由 processLoop 自行重连（client.go:135）。
//
// 因此外层**不能**在 Start() 成功返回后继续循环重建 client：
// 那会在连接健康时不断丢弃旧连接、新建 client，导致日志刷"正在连接"、
// 僵尸连接累积，且消息路由在多个连接间抖动。
// 正确语义：Start() 失败才按退避重建；成功则阻塞到 ctx 取消，把重连交给 SDK。
//
// 回复机制（🔴 实测修正：钉钉 Stream 机器人帧中 SessionWebhook **有值**——线上所有
// ack data 恒为空串但用户能收到回复，证明回复一直走 webhook POST；下方旧注释
// "Stream 模式下通常为空"是错误推断，曾据此写出让全部消息被静默丢弃的 bug）：
//   - 主路径（dingFrameDispatcher）：立即 ack + 异步处理 + SessionWebhook POST 回复，
//     根治「handler 阻塞数分钟 → 钉钉 ack 超时重投 → 重投帧撞会话锁报假错误」；
//   - 兜底：webhook 或 msgId 缺失的异常形态，保持同步处理并 return []byte(reply)
//     由框架经 Stream ack 回复。
func runDingLoop(ctx context.Context, cfg config.RobotDingtalkConfig, strictUserIdentity bool, h MessageHandler, logger *zap.Logger) {
	// 必须先桥接 SDK 日志：SDK 默认 logger 是空实现，不桥接则读帧错误、
	// topic 未注册、收帧内容全部静默丢弃，消息不进时无从排查。
	installDingSDKLogger(logger)
	dispatcher := newDingFrameDispatcher(cfg, strictUserIdentity, h, logger)
	backoff := dingReconnectInitial
	for {
		streamClient := client.NewStreamClient(
			client.WithAppCredential(client.NewAppCredentialConfig(cfg.ClientID, cfg.ClientSecret)),
			client.WithSubscription(dingutils.SubscriptionTypeKCallback, payload.BotMessageCallbackTopic,
				chatbot.NewDefaultChatBotFrameHandler(func(ctx context.Context, msg *chatbot.BotCallbackDataModel) ([]byte, error) {
					if msg == nil {
						return nil, nil
					}
					// 回调入口埋点：只要走到这里就说明钉钉确实推了消息过来。
					// 有了这一行就能区分「消息没到」与「到了但被下游丢弃」。
					logger.Info("钉钉收到 Stream 回调帧",
						zap.String("msgtype", msg.Msgtype),
						zap.String("conversation_id", msg.ConversationId),
						zap.String("sender_id", msg.SenderId))
					reply := dispatcher.dispatch(ctx, msg)
					if reply == "" {
						return nil, nil
					}
					return []byte(reply), nil
				}).OnEventReceived),
		)
		logger.Info("钉钉 Stream 正在连接…", zap.String("client_id", cfg.ClientID))
		err := streamClient.Start(ctx)
		if ctx.Err() != nil {
			logger.Info("钉钉 Stream 已按配置重启关闭")
			return
		}
		if err != nil {
			// 只有真正失败才重建连接，退避后重试
			logger.Warn("钉钉 Stream 长连接断开（如睡眠/断网），将自动重连", zap.Error(err), zap.Duration("retry_after", backoff))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < dingReconnectMax {
				backoff *= 2
				if backoff > dingReconnectMax {
					backoff = dingReconnectMax
				}
			}
			continue
		}
		// 连接已建立：SDK 内部的 processLoop 持续收帧，断线时 AutoReconnect 会调
		// reconnect() 每 3 秒重试直到成功（client.go:311）。连接状态字段是私有的、
		// 无对外查询接口，因此外层只能也只应阻塞到 ctx 取消（配置变更/进程退出）。
		logger.Info("钉钉 Stream 连接成功，已进入长连接守护（断线由 SDK 自动重连）")
		backoff = dingReconnectInitial
		<-ctx.Done()
		logger.Info("钉钉 Stream 已退出")
		return
	}
}

// processDingMessage 处理一条钉钉消息并返回回复文本（不为空时由调用方经 Stream 框架回复）。
// 仅当 msg.SessionWebhook 非空（兼容旧 HTTP 回调场景）时，才改用 webhook POST 回复。
func processDingMessage(ctx context.Context, msg *chatbot.BotCallbackDataModel, cfg config.RobotDingtalkConfig, strictUserIdentity bool, h MessageHandler, logger *zap.Logger) string {
	if msg == nil {
		return ""
	}
	content := extractDingContent(msg)
	if content == "" {
		logger.Debug("钉钉消息内容为空，已忽略", zap.String("msgtype", msg.Msgtype))
		return ""
	}
	logger.Info("钉钉收到消息", zap.String("sender", msg.SenderId), zap.String("content", content))
	tenantKey := strings.TrimSpace(cfg.ClientID)
	if tenantKey == "" {
		tenantKey = "default"
	}
	userID := strings.TrimSpace(msg.SenderId)
	if userID != "" {
		userID = "t:" + tenantKey + "|u:" + userID
	} else if cfg.AllowConversationIDFallback && !strictUserIdentity {
		conversationID := strings.TrimSpace(msg.ConversationId)
		if conversationID != "" {
			userID = "t:" + tenantKey + "|c:" + conversationID
		}
	}
	if userID == "" {
		logger.Warn("钉钉消息缺少可用用户标识，已忽略")
		return ""
	}
	reply := h.HandleMessage("dingtalk", userID, content)
	// 兼容旧 HTTP 回调模式：若 SessionWebhook 有值，改走 webhook POST（此时本函数返回空，
	// 避免与 Stream 返回值回复重复发送）。
	if msg.SessionWebhook != "" {
		postDingReplyViaWebhook(ctx, msg.SessionWebhook, reply, logger)
		return ""
	}
	return reply
}

// extractDingContent 从回调消息中提取纯文本正文，兼容 text 与 richText。
func extractDingContent(msg *chatbot.BotCallbackDataModel) string {
	content := ""
	if msg.Text.Content != "" {
		content = strings.TrimSpace(msg.Text.Content)
	}
	if content == "" && msg.Msgtype == "richText" {
		if cMap, ok := msg.Content.(map[string]interface{}); ok {
			if rich, ok := cMap["richText"].([]interface{}); ok {
				for _, c := range rich {
					if m, ok := c.(map[string]interface{}); ok {
						if txt, ok := m["text"].(string); ok {
							content = strings.TrimSpace(txt)
							break
						}
					}
				}
			}
		}
	}
	return content
}

// postDingReplyViaWebhook 经 SessionWebhook 主动 POST 回复（兼容旧 HTTP 回调模式）。
func postDingReplyViaWebhook(ctx context.Context, webhook, reply string, logger *zap.Logger) {
	title := reply
	if idx := strings.IndexAny(reply, "\n"); idx > 0 {
		title = strings.TrimSpace(reply[:idx])
	}
	if len(title) > 50 {
		title = title[:50] + "…"
	}
	if title == "" {
		title = "回复"
	}
	body := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": title,
			// 🔴 钉钉 markdown 不认单个 \n（会折叠成空格），必须 \n\n 才换行。
			// 不展开则帮助文本/AI 报告在钉钉里是没有任何换行的一坨。
			"text": expandLineBreaksForMarkdown(reply),
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		logger.Warn("钉钉构造回复请求失败", zap.Error(err))
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(bodyBytes))
	if err != nil {
		logger.Warn("钉钉构造回复请求失败", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Warn("钉钉回复请求失败", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Warn("钉钉回复非 200", zap.Int("status", resp.StatusCode))
		return
	}
	// 🔴 Info 级（原为 Debug，生产日志级别下不可见）：回复是否真的发出去、发了多长，
	// 是排查「用户说没收到回复」时唯一能自证的一环——只记失败日志会让人误判为已送达。
	logger.Info("钉钉回复成功",
		zap.Int("reply_runes", len([]rune(reply))),
		zap.String("content_preview", truncateForLog(reply, 80)))
}
