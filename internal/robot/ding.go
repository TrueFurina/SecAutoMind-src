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
	dingutils "github.com/open-dingtalk/dingtalk-stream-sdk-go/utils"
	"go.uber.org/zap"
)

const (
	dingReconnectInitial = 5 * time.Second  // 首次重连间隔
	dingReconnectMax     = 60 * time.Second // 最大重连间隔
)

// StartDing 启动钉钉 Stream 长连接（无需公网），收到消息后调用 handler 并通过 SessionWebhook 回复。
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
func runDingLoop(ctx context.Context, cfg config.RobotDingtalkConfig, strictUserIdentity bool, h MessageHandler, logger *zap.Logger) {
	backoff := dingReconnectInitial
	for {
		streamClient := client.NewStreamClient(
			client.WithAppCredential(client.NewAppCredentialConfig(cfg.ClientID, cfg.ClientSecret)),
			client.WithSubscription(dingutils.SubscriptionTypeKCallback, "/v1.0/im/bot/messages/get",
				chatbot.NewDefaultChatBotFrameHandler(func(ctx context.Context, msg *chatbot.BotCallbackDataModel) ([]byte, error) {
					go handleDingMessage(ctx, msg, cfg, strictUserIdentity, h, logger)
					return nil, nil
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

func handleDingMessage(ctx context.Context, msg *chatbot.BotCallbackDataModel, cfg config.RobotDingtalkConfig, strictUserIdentity bool, h MessageHandler, logger *zap.Logger) {
	if msg == nil || msg.SessionWebhook == "" {
		return
	}
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
	if content == "" {
		logger.Debug("钉钉消息内容为空，已忽略", zap.String("msgtype", msg.Msgtype))
		return
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
		return
	}
	reply := h.HandleMessage("dingtalk", userID, content)
	// 使用 markdown 类型以便正确展示标题、列表、代码块等格式
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
			"text":  reply,
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, msg.SessionWebhook, bytes.NewReader(bodyBytes))
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
	logger.Debug("钉钉回复成功", zap.String("content_preview", reply))
}
