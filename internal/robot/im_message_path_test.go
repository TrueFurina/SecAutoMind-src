package robot

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	lark "github.com/larksuite/oapi-sdk-go/v3"
	larkcore "github.com/larksuite/oapi-sdk-go/v3/core"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/tencent-connect/botgo/dto"
	"github.com/tencent-connect/botgo/openapi"
	"github.com/tencent-connect/botgo/openapi/options"
	"go.uber.org/zap"

	"secautomind-ai/internal/config"
)

func config0Lark() config.RobotLarkConfig { return config.RobotLarkConfig{} }

// larkTestClient 离线构造真实 client（不拨号）；回复时网络失败仅记 warn，非致命。
func larkTestClient() *lark.Client { return lark.NewClient("test-app-id", "test-app-secret") }

// countingHandler 线程安全的 MessageHandler 计数桩。
type countingHandler struct {
	mu    sync.Mutex
	calls []dingCall
	reply string
}

func (f *countingHandler) HandleMessage(platform, userID, text string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, dingCall{platform: platform, userID: userID, text: text})
	return f.reply
}

func (f *countingHandler) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *countingHandler) last() dingCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// ── 飞书接消息路径 ─────────────────────────────────────

func larkTextEvent(msgType, content, openID, tenantKey string) *larkim.P2MessageReceiveV1 {
	return &larkim.P2MessageReceiveV1{
		Event: &larkim.P2MessageReceiveV1Data{
			Message: larkim.NewEventMessageBuilder().
				MessageType(msgType).
				Content(content).
				MessageId("om-test-1").
				Build(),
			Sender: &larkim.EventSender{
				SenderId:  &larkim.UserId{OpenId: larkcore.StringPtr(openID)},
				TenantKey: larkcore.StringPtr(tenantKey),
			},
		},
	}
}

func TestHandleLarkMessage_NilEvent(t *testing.T) {
	h := &countingHandler{reply: "ok"}
	client := larkTestClient()
	handleLarkMessage(context.Background(), nil, config0Lark(), false, h, client, zap.NewNop())
	if h.count() != 0 {
		t.Errorf("nil 事件不应触达 handler，实际 %d 次", h.count())
	}
}

func TestHandleLarkMessage_NonTextRejected(t *testing.T) {
	h := &countingHandler{reply: "ok"}
	ev := larkTextEvent("image", `{"image_key":"img_x"}`, "ou-1", "tk")
	handleLarkMessage(context.Background(), ev, config0Lark(), false, h, larkTestClient(), zap.NewNop())
	if h.count() != 0 {
		t.Errorf("非文本消息不应触达 handler，实际 %d 次", h.count())
	}
}

func TestHandleLarkMessage_BadContentRejected(t *testing.T) {
	h := &countingHandler{reply: "ok"}
	ev := larkTextEvent(larkim.MsgTypeText, "not-json{{", "ou-1", "tk")
	handleLarkMessage(context.Background(), ev, config0Lark(), false, h, larkTestClient(), zap.NewNop())
	if h.count() != 0 {
		t.Errorf("Content 解析失败不应触达 handler，实际 %d 次", h.count())
	}
}

// TestHandleLarkMessage_TextFullPath 全链路：文本→handler；回复经离线 client 走网络失败但非致命。
func TestHandleLarkMessage_TextFullPath(t *testing.T) {
	h := &countingHandler{reply: "飞书回复"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ev := larkTextEvent(larkim.MsgTypeText, `{"text":"  检查一下资产  "}`, "ou-abc", "tenant-1")
	handleLarkMessage(ctx, ev, config0Lark(), false, h, larkTestClient(), zap.NewNop())
	if h.count() != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d 次", h.count())
	}
	call := h.last()
	if call.platform != "lark" {
		t.Errorf("platform = %q, want lark", call.platform)
	}
	if want := "t:tenant-1|o:ou-abc"; call.userID != want {
		t.Errorf("userID = %q, want %q（租户+openId 隔离）", call.userID, want)
	}
	if call.text != "检查一下资产" {
		t.Errorf("text = %q, want 清洗后的文本", call.text)
	}
}

// ── QQ 接消息路径 ─────────────────────────────────────

// fakeQQAPI 嵌入接口仅覆写消息发送，其余方法不触达。
type fakeQQAPI struct {
	openapi.OpenAPI
	mu       sync.Mutex
	c2cSent  []string
	groupSent []string
}

func (f *fakeQQAPI) PostC2CMessage(ctx context.Context, userID string, msg dto.APIMessage, opt ...options.Option) (*dto.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.c2cSent = append(f.c2cSent, userID+"|"+msgContent(msg))
	return &dto.Message{}, nil
}

func (f *fakeQQAPI) PostGroupMessage(ctx context.Context, groupID string, msg dto.APIMessage, opt ...options.Option) (*dto.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groupSent = append(f.groupSent, groupID+"|"+msgContent(msg))
	return &dto.Message{}, nil
}

func msgContent(msg dto.APIMessage) string {
	if m, ok := msg.(*dto.MessageToCreate); ok {
		return m.Content
	}
	return ""
}

// setQQState 注入包级状态并返回恢复函数。
func setQQState(h MessageHandler, api openapi.OpenAPI) func() {
	qqHandlerMu.Lock()
	defer qqHandlerMu.Unlock()
	origH, origAPI, origLogger := qqHandler, qqAPI, qqLogger
	qqHandler, qqAPI, qqLogger = h, api, zap.NewNop()
	return func() {
		qqHandlerMu.Lock()
		defer qqHandlerMu.Unlock()
		qqHandler, qqAPI, qqLogger = origH, origAPI, origLogger
	}
}

func TestHandleQQC2CMessage_Guards(t *testing.T) {
	h := &countingHandler{reply: "ok"}
	restore := setQQState(h, &fakeQQAPI{})
	defer restore()

	if err := handleQQC2CMessage(&dto.WSPayload{}, nil); err != nil {
		t.Errorf("nil data 应返回 nil，got %v", err)
	}
	if err := handleQQC2CMessage(&dto.WSPayload{}, &dto.WSC2CMessageData{}); err != nil {
		t.Errorf("nil author 应返回 nil，got %v", err)
	}
	if err := handleQQC2CMessage(&dto.WSPayload{}, &dto.WSC2CMessageData{Content: "   ", Author: &dto.User{ID: "ou-1"}}); err != nil {
		t.Errorf("空白内容应返回 nil，got %v", err)
	}
	if err := handleQQC2CMessage(&dto.WSPayload{}, &dto.WSC2CMessageData{Content: "hi", Author: &dto.User{ID: "  "}}); err != nil {
		t.Errorf("空 openid 应返回 nil，got %v", err)
	}
	if h.count() != 0 {
		t.Errorf("守卫路径均不应触达 handler，实际 %d 次", h.count())
	}
}

func TestHandleQQC2CMessage_FullPath(t *testing.T) {
	h := &countingHandler{reply: "QQ回复内容"}
	api := &fakeQQAPI{}
	restore := setQQState(h, api)
	defer restore()

	data := &dto.WSC2CMessageData{Content: "  帮我扫一下  ", ID: "msgid-1", Author: &dto.User{ID: "ou-user-9"}}
	if err := handleQQC2CMessage(&dto.WSPayload{WSPayloadBase: dto.WSPayloadBase{EventID: "evt-1"}}, data); err != nil {
		t.Fatalf("全链路应成功，got %v", err)
	}
	if h.count() != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d 次", h.count())
	}
	call := h.last()
	if call.platform != "qq" || call.userID != "u:ou-user-9" || call.text != "帮我扫一下" {
		t.Errorf("handler 参数错误: %+v", call)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.c2cSent) != 1 || !strings.Contains(api.c2cSent[0], "ou-user-9|QQ回复内容") {
		t.Errorf("C2C 回复未正确发出: %v", api.c2cSent)
	}
}

func TestHandleQQGroupATMessage_FullPath(t *testing.T) {
	h := &countingHandler{reply: "群回复"}
	api := &fakeQQAPI{}
	restore := setQQState(h, api)
	defer restore()

	data := &dto.WSGroupATMessageData{Content: "群里问一下", ID: "msgid-2", GroupID: "group-77", Author: &dto.User{ID: "ou-user-8"}}
	if err := handleQQGroupATMessage(&dto.WSPayload{}, data); err != nil {
		t.Fatalf("群@全链路应成功，got %v", err)
	}
	if h.count() != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d 次", h.count())
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.groupSent) != 1 || !strings.Contains(api.groupSent[0], "group-77|群回复") {
		t.Errorf("群回复未正确发出: %v", api.groupSent)
	}
}

// ── Slack 接消息路径 ──────────────────────────────────

func TestHandleSlackMessage_Guards(t *testing.T) {
	h := &countingHandler{reply: "ok"}
	api := slack.New("xoxb-fake-token")

	handleSlackMessage(context.Background(), api, "tm", nil, h, zap.NewNop())
	botEv := &slackevents.MessageEvent{BotID: "B1", ChannelType: "im", Text: "hi", User: "U1"}
	handleSlackMessage(context.Background(), api, "tm", botEv, h, zap.NewNop())
	subEv := &slackevents.MessageEvent{SubType: "message_changed", ChannelType: "im", Text: "hi", User: "U1"}
	handleSlackMessage(context.Background(), api, "tm", subEv, h, zap.NewNop())
	chanEv := &slackevents.MessageEvent{ChannelType: "channel", Text: "hi", User: "U1"}
	handleSlackMessage(context.Background(), api, "tm", chanEv, h, zap.NewNop())
	emptyEv := &slackevents.MessageEvent{ChannelType: "im", Text: "  ", User: "U1"}
	handleSlackMessage(context.Background(), api, "tm", emptyEv, h, zap.NewNop())

	if h.count() != 0 {
		t.Errorf("守卫路径均不应触达 handler，实际 %d 次", h.count())
	}
}

// TestHandleSlackMessage_FullPath 全链路：IM 文本→handler；PostMessage 离线失败非致命。
func TestHandleSlackMessage_FullPath(t *testing.T) {
	h := &countingHandler{reply: "slack 回复"}
	api := slack.New("xoxb-fake-token")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ev := &slackevents.MessageEvent{ChannelType: "im", Text: "  盘点一下  ", User: "USLACK", Channel: "DCHAN"}
	handleSlackMessage(ctx, api, "team-1", ev, h, zap.NewNop())

	if h.count() != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d 次", h.count())
	}
	call := h.last()
	if call.platform != "slack" {
		t.Errorf("platform = %q, want slack", call.platform)
	}
	if want := "t:team-1|u:USLACK"; call.userID != want {
		t.Errorf("userID = %q, want %q", call.userID, want)
	}
	if call.text != "盘点一下" {
		t.Errorf("text = %q, want 清洗后的文本", call.text)
	}
}

func TestSlackSessionKey(t *testing.T) {
	if got := slackSessionKey("tm", "U1"); got != "t:tm|u:U1" {
		t.Errorf("slackSessionKey = %q", got)
	}
	if got := slackSessionKey("", "U1"); got != "t:default|u:U1" {
		t.Errorf("空 team 应回退 default，got %q", got)
	}
}

// ── Discord @机器人判定 ───────────────────────────────

func TestDiscordMentionsBot(t *testing.T) {
	if discordMentionsBot(nil, "bot1") {
		t.Error("nil 消息应返回 false")
	}
	m := &discordgo.MessageCreate{Message: &discordgo.Message{
		Mentions: []*discordgo.User{{ID: "bot1"}},
		Content:  "不带内联标记",
	}}
	if !discordMentionsBot(m, "bot1") {
		t.Error("Mentions 列表命中应返回 true")
	}
	m2 := &discordgo.MessageCreate{Message: &discordgo.Message{Content: "<@bot2> 在吗"}}
	if !discordMentionsBot(m2, "bot2") {
		t.Error("<@bot2> 内联标记应返回 true")
	}
	m3 := &discordgo.MessageCreate{Message: &discordgo.Message{Content: "<@!bot3> 在吗"}}
	if !discordMentionsBot(m3, "bot3") {
		t.Error("<@!bot3> 昵称标记应返回 true")
	}
	m4 := &discordgo.MessageCreate{Message: &discordgo.Message{Content: "普通消息", Mentions: []*discordgo.User{{ID: "other"}}}}
	if discordMentionsBot(m4, "bot4") {
		t.Error("无关消息应返回 false")
	}
}
