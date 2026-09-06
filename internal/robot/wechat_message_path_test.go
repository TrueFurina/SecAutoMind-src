package robot

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"secautomind-ai/internal/config"
	"secautomind-ai/internal/robot/ilink"

	"go.uber.org/zap"
)

// cancelAfterReply handler 返回回复后取消 ctx，驱动 runWechatPoll 退出。
type cancelAfterReply struct {
	inner  *countingHandler
	cancel context.CancelFunc
}

func (c *cancelAfterReply) HandleMessage(platform, userID, text string) string {
	reply := c.inner.HandleMessage(platform, userID, text)
	c.cancel()
	return reply
}

// TestRunWechatPoll_FullPath 全链路：长轮询收到文本 → handler → sendmessage 回复。
func TestRunWechatPoll_FullPath(t *testing.T) {
	var mu sync.Mutex
	var sentBody string
	var gotMsgCount int

	mux := http.NewServeMux()
	mux.HandleFunc("/ilink/bot/getupdates", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMsgCount++
		n := gotMsgCount
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write([]byte(`{"ret":0,"errcode":0,"msgs":[{"from_user_id":"wx-user-1","message_type":1,"context_token":"ctx-1","item_list":[{"type":1,"text_item":{"text":"  微信提问  "}}]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"ret":0,"errcode":0,"msgs":[]}`))
	})
	mux.HandleFunc("/ilink/bot/sendmessage", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		sentBody = string(body)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ret":0}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &countingHandler{reply: "微信回复"}
	cfg := config.RobotWechatConfig{BaseURL: srv.URL, BotToken: "tok", ILinkBotID: "bot-1"}

	done := make(chan struct{})
	go func() {
		_ = runWechatPoll(ctx, cfg, h, "1.0.0", zap.NewNop())
		close(done)
	}()

	waitFor(t, 3*time.Second, func() bool { return h.count() > 0 })
	waitFor(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return sentBody != ""
	})
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runWechatPoll 未在取消后退出")
	}

	if h.count() != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d 次", h.count())
	}
	call := h.last()
	if call.platform != "wechat" {
		t.Errorf("platform = %q, want wechat", call.platform)
	}
	if call.userID != "wx-user-1" {
		t.Errorf("userID = %q, want wx-user-1", call.userID)
	}
	if call.text != "微信提问" {
		t.Errorf("text = %q, want 清洗后的文本", call.text)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(sentBody, "微信回复") || !strings.Contains(sentBody, "wx-user-1") {
		t.Errorf("sendmessage payload 不含回复与收件人: %s", sentBody)
	}
}

// TestRunWechatPoll_SkipNonText 非文本/空文本/空 userID 消息应被跳过。
func TestRunWechatPoll_SkipNonText(t *testing.T) {
	var mu sync.Mutex
	batch := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/ilink/bot/getupdates", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		batch++
		n := batch
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			// 四条消息：非文本 / 空 text_item / 空 userID / 合法——仅最后一条触达 handler
			_, _ = w.Write([]byte(`{"ret":0,"errcode":0,"msgs":[
				{"from_user_id":"wx-a","message_type":2,"item_list":[{"type":1,"text_item":{"text":"图片消息"}}]},
				{"from_user_id":"wx-b","message_type":1},
				{"from_user_id":"","message_type":1,"item_list":[{"type":1,"text_item":{"text":"无主消息"}}]},
				{"from_user_id":"wx-user-1","message_type":1,"context_token":"ctx-1","item_list":[{"type":1,"text_item":{"text":"合法提问"}}]}
			]}`))
			return
		}
		_, _ = w.Write([]byte(`{"ret":0,"errcode":0,"msgs":[]}`))
	})
	mux.HandleFunc("/ilink/bot/sendmessage", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":0}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inner := &countingHandler{reply: "回复"}
	h := &cancelAfterReply{inner: inner, cancel: cancel}
	cfg := config.RobotWechatConfig{BaseURL: srv.URL, BotToken: "tok", ILinkBotID: "bot-1"}

	done := make(chan struct{})
	go func() {
		_ = runWechatPoll(ctx, cfg, h, "1.0.0", zap.NewNop())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("runWechatPoll 未退出")
	}
	if inner.count() != 1 {
		t.Errorf("仅 1 条合法消息应触达 handler，实际 %d 次", inner.count())
	}
	if inner.last().text != "合法提问" {
		t.Errorf("text = %q, want 合法提问", inner.last().text)
	}
}

func TestStartWechat_DisabledConfig(t *testing.T) {
	StartWechat(context.Background(), config.RobotsConfig{Wechat: config.RobotWechatConfig{Enabled: false}}, nil, "1.0.0", zap.NewNop())
	StartWechat(context.Background(), config.RobotsConfig{Wechat: config.RobotWechatConfig{Enabled: true}}, nil, "1.0.0", zap.NewNop())
	// 不 panic 即通过（缺 BotToken 直接 return）
}

// TestExtractText 纯函数：首条文本提取。
func TestExtractText(t *testing.T) {
	if got := ilink.ExtractText(ilink.WeixinMessage{}); got != "" {
		t.Errorf("空消息应返回空，got %q", got)
	}
	msg := ilink.WeixinMessage{ItemList: []ilink.MessageItem{
		{Type: 2},
		{Type: 1, TextItem: &struct {
			Text string `json:"text"`
		}{Text: "  带空白的文本  "}},
	}}
	if got := ilink.ExtractText(msg); got != "带空白的文本" {
		t.Errorf("ExtractText = %q", got)
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待条件超时 %v", d)
}
