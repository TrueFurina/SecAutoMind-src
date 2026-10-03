package robot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secautomind-ai/internal/config"

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"
	"go.uber.org/zap"
)

// ── 钉钉接消息路径冒烟测试（收消息 → 解析 → 调 handler → 回复 webhook）──────────

// fakeHandler 记录 HandleMessage 调用并返回固定回复，模拟上层会话处理。
type fakeHandler struct {
	calls []dingCall
	reply string
}

type dingCall struct{ platform, userID, text string }

func (f *fakeHandler) HandleMessage(platform, userID, text string) string {
	f.calls = append(f.calls, dingCall{platform: platform, userID: userID, text: text})
	return f.reply
}

func TestHandleDingMessage_NilMsg(t *testing.T) {
	h := &fakeHandler{reply: "回复"}
	processDingMessage(context.Background(), nil, config.RobotDingtalkConfig{}, false, h, zap.NewNop())
	if len(h.calls) != 0 {
		t.Errorf("nil 消息不应触达 handler，实际 %d 次", len(h.calls))
	}
}

// TestHandleDingMessage_EmptyWebhook 锁定 Stream 模式语义（历史 bug 的回归防线）。
//
// 旧实现以 `if msg.SessionWebhook == "" { return }` 作为丢弃消息的条件，
// 而 SessionWebhook 是**钉钉 HTTP 回调模式**的字段；Stream 长连接模式下它为空，
// 于是该行把**每一条 Stream 消息都静默丢弃**——表现就是「建链成功但群里毫无反应」。
//
// 因此正确行为是：SessionWebhook 为空（Stream 模式）时，**必须照常处理并返回回复**，
// 由 SDK 经 Stream 连接发回钉钉。
func TestHandleDingMessage_EmptyWebhook(t *testing.T) {
	h := &fakeHandler{reply: "Stream 模式回复"}
	msg := &chatbot.BotCallbackDataModel{SenderId: "sender-stream"}
	msg.Text.Content = "你好"

	reply := processDingMessage(context.Background(), msg, config.RobotDingtalkConfig{}, false, h, zap.NewNop())

	if len(h.calls) != 1 {
		t.Fatalf("Stream 模式（SessionWebhook 为空）必须照常处理消息，实际 handler 调用 %d 次", len(h.calls))
	}
	if reply != "Stream 模式回复" {
		t.Errorf("reply = %q, want %q（应返回给 SDK 经 Stream 回复）", reply, "Stream 模式回复")
	}
}

// TestProcessDingMessage_StreamModeSkipsWebhook 确认 Stream 模式下不会误走 webhook 分支。
func TestProcessDingMessage_StreamModeSkipsWebhook(t *testing.T) {
	h := &fakeHandler{reply: "走 Stream"}
	msg := &chatbot.BotCallbackDataModel{SenderId: "sender-x"}
	msg.Text.Content = "hi"

	reply := processDingMessage(context.Background(), msg, config.RobotDingtalkConfig{}, false, h, zap.NewNop())
	if reply == "" {
		t.Error("Stream 模式应返回回复文本供 SDK 经连接发回")
	}
}

func TestHandleDingMessage_EmptyContent_Ignored(t *testing.T) {
	h := &fakeHandler{reply: "回复"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	msg := &chatbot.BotCallbackDataModel{SessionWebhook: srv.URL}
	msg.Text.Content = "   " // 仅空白
	processDingMessage(context.Background(), msg, config.RobotDingtalkConfig{}, false, h, zap.NewNop())
	if len(h.calls) != 0 {
		t.Errorf("空白内容不应触达 handler，实际 %d 次", len(h.calls))
	}
}

// TestHandleDingMessage_TextFullPath 核心链路：文本消息 → handler → webhook 收到 markdown 回复。
func TestHandleDingMessage_TextFullPath(t *testing.T) {
	var gotPayload map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := &fakeHandler{reply: "查询结果\n第二行内容"}
	cfg := config.RobotDingtalkConfig{ClientID: "ding-app-key"}
	msg := &chatbot.BotCallbackDataModel{
		SessionWebhook: srv.URL,
		ConversationId: "cid123",
		SenderId:       "sender-100",
	}
	msg.Text.Content = "  帮我查一下漏洞  "

	processDingMessage(context.Background(), msg, cfg, false, h, zap.NewNop())

	// 1) handler 被正确调用：platform / userID（含租户与用户前缀）/ 清洗后的文本
	if len(h.calls) != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d 次", len(h.calls))
	}
	call := h.calls[0]
	if call.platform != "dingtalk" {
		t.Errorf("platform = %q, want dingtalk", call.platform)
	}
	if want := "t:ding-app-key|u:sender-100"; call.userID != want {
		t.Errorf("userID = %q, want %q", call.userID, want)
	}
	if call.text != "帮我查一下漏洞" {
		t.Errorf("text = %q, want 清洗后的文本", call.text)
	}

	// 2) webhook 收到 markdown 回复
	if gotPayload == nil {
		t.Fatal("webhook 未收到回复")
	}
	if gotPayload["msgtype"] != "markdown" {
		t.Errorf("msgtype = %v, want markdown", gotPayload["msgtype"])
	}
	md, _ := gotPayload["markdown"].(map[string]interface{})
	if md == nil {
		t.Fatal("payload 缺少 markdown 字段")
	}
	if text, _ := md["text"].(string); !strings.Contains(text, "查询结果") {
		t.Errorf("回复文本未包含 handler 返回内容，got %q", text)
	}
	if title, _ := md["title"].(string); title != "查询结果" {
		t.Errorf("title = %q, want 首行截断 %q", title, "查询结果")
	}
}

// TestHandleDingMessage_UserIDFormat 验证完整用户标识格式（租户隔离 + 用户前缀）。
func TestHandleDingMessage_UserIDFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	h := &fakeHandler{reply: "ok"}
	cfg := config.RobotDingtalkConfig{ClientID: "app-key"}
	msg := &chatbot.BotCallbackDataModel{SessionWebhook: srv.URL}
	msg.Text.Content = "hi"
	msg.SenderId = "sender-001"

	processDingMessage(context.Background(), msg, cfg, false, h, zap.NewNop())

	if len(h.calls) != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d 次", len(h.calls))
	}
	want := "t:app-key|u:sender-001"
	if h.calls[0].userID != want {
		t.Errorf("userID = %q, want %q（租户隔离格式）", h.calls[0].userID, want)
	}
}

// TestHandleDingMessage_ConversationFallback 无 SenderID 时按配置回退到会话 ID。
func TestHandleDingMessage_ConversationFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	h := &fakeHandler{reply: "ok"}
	cfg := config.RobotDingtalkConfig{ClientID: "app-key", AllowConversationIDFallback: true}
	msg := &chatbot.BotCallbackDataModel{SessionWebhook: srv.URL, ConversationId: "conv-42"}
	msg.Text.Content = "hi"

	processDingMessage(context.Background(), msg, cfg, false, h, zap.NewNop())

	if len(h.calls) != 1 {
		t.Fatalf("允许回退时 handler 应被调用 1 次，实际 %d 次", len(h.calls))
	}
	if want := "t:app-key|c:conv-42"; h.calls[0].userID != want {
		t.Errorf("userID = %q, want %q", h.calls[0].userID, want)
	}
}

// TestHandleDingMessage_NoUserID_Ignored 无 SenderID 且未开启回退 → 拒登不建会话。
func TestHandleDingMessage_NoUserID_Ignored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	h := &fakeHandler{reply: "ok"}
	msg := &chatbot.BotCallbackDataModel{SessionWebhook: srv.URL, ConversationId: "conv-42"}
	msg.Text.Content = "hi"

	processDingMessage(context.Background(), msg, config.RobotDingtalkConfig{}, false, h, zap.NewNop())

	if len(h.calls) != 0 {
		t.Errorf("无用户标识不应触达 handler（拒登语义），实际 %d 次", len(h.calls))
	}
}

// TestHandleDingMessage_RichText 验证富文本消息的首段文本提取。
func TestHandleDingMessage_RichText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	h := &fakeHandler{reply: "ok"}
	msg := &chatbot.BotCallbackDataModel{SessionWebhook: srv.URL, Msgtype: "richText", SenderId: "sender-200"}
	msg.Content = map[string]interface{}{
		"richText": []interface{}{
			map[string]interface{}{"type": "picture", "downloadCode": "x"},
			map[string]interface{}{"type": "text", "text": "富文本里的提问"},
		},
	}

	processDingMessage(context.Background(), msg, config.RobotDingtalkConfig{}, false, h, zap.NewNop())

	if len(h.calls) != 1 {
		t.Fatalf("richText 应提取出文本并触达 handler，实际 %d 次", len(h.calls))
	}
	if h.calls[0].text != "富文本里的提问" {
		t.Errorf("text = %q, want %q", h.calls[0].text, "富文本里的提问")
	}
}

// ── 通用辅助器 ─────────────────────────────────────────

func TestSplitTextChunks(t *testing.T) {
	if got := splitTextChunks("", 10); got != nil {
		t.Errorf("空文本应返回 nil，got %v", got)
	}
	if got := splitTextChunks("abc", 0); got != nil {
		t.Errorf("maxRunes<=0 应返回 nil，got %v", got)
	}
	if got := splitTextChunks("  abc  ", 10); len(got) != 1 || got[0] != "abc" {
		t.Errorf("短文本应 TrimSpace 后单块返回，got %v", got)
	}
	// 中文按 rune 切，不出现乱码
	long := strings.Repeat("漏", 7)
	got := splitTextChunks(long, 3)
	if len(got) != 3 || got[0] != "漏漏漏" || got[2] != "漏" {
		t.Errorf("中文分块错误，got %v", got)
	}
	joined := strings.Join(got, "")
	if joined != long {
		t.Errorf("分块拼接后应还原原文，got %q", joined)
	}
}
