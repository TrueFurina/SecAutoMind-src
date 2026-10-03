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

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"
	"go.uber.org/zap"
)

// fakeSlowHandler 模拟 Agent 长任务：可注入延迟。
type fakeSlowHandler struct {
	mu    sync.Mutex
	calls int
	delay time.Duration
	reply string
}

func (f *fakeSlowHandler) HandleMessage(platform, userID, text string) string {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.reply
}

func (f *fakeSlowHandler) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// recordingWebhook 模拟钉钉 SessionWebhook 端点，记录收到的 POST。
type recordingWebhook struct {
	mu     sync.Mutex
	bodies []string
	srv    *httptest.Server
}

func newRecordingWebhook(t *testing.T) *recordingWebhook {
	w := &recordingWebhook{}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.bodies = append(w.bodies, string(b))
		w.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *recordingWebhook) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.bodies)
}

func (w *recordingWebhook) waitFor(t *testing.T, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if w.count() >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("webhook 在 %v 内未收到 %d 条回复（实际 %d 条）", timeout, n, w.count())
}

func dingMsg(msgID, webhook, text string) *chatbot.BotCallbackDataModel {
	return &chatbot.BotCallbackDataModel{
		MsgId:          msgID,
		Msgtype:        "text",
		Text:           chatbot.BotCallbackDataTextModel{Content: text},
		SessionWebhook: webhook,
		SenderId:       "sender-x",
		ConversationId: "cid-x",
	}
}

// 核心断言：有 webhook 时 dispatch 必须**立即返回**（不等 handler 跑完），
// 回复经 webhook 异步送达。这是「钉钉 ack 超时重投」的根治点。
func TestDingFrameDispatcher_AsyncImmediateAckAndWebhookReply(t *testing.T) {
	webhook := newRecordingWebhook(t)
	h := &fakeSlowHandler{delay: 500 * time.Millisecond, reply: "任务完成"}
	d := newDingFrameDispatcher(config.RobotDingtalkConfig{ClientID: "ding-test"}, false, h, zap.NewNop())

	start := time.Now()
	got := d.dispatch(context.Background(), dingMsg("m-1", webhook.srv.URL, "渗透测试"))
	elapsed := time.Since(start)

	if got != "" {
		t.Fatalf("异步路径应立即返回空串，实际返回 %q", got)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("dispatch 阻塞了 %v（handler 要 500ms），说明没有异步化，ack 必超时", elapsed)
	}
	webhook.waitFor(t, 1, 3*time.Second)
	if h.callCount() != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d", h.callCount())
	}
	if !strings.Contains(webhook.bodies[0], "任务完成") {
		t.Fatalf("webhook 收到的回复应含最终回复文本，实际: %s", webhook.bodies[0])
	}
}

// 核心断言：同一 msgId 的重投帧必须被吞并——handler 不再被调用、不再发第二条回复，
// 并立即返回空（快速 ack），钉钉收到 ack 后停止重投。
func TestDingFrameDispatcher_DuplicateFrameSuppressed(t *testing.T) {
	webhook := newRecordingWebhook(t)
	h := &fakeSlowHandler{delay: 100 * time.Millisecond, reply: "回复A"}
	d := newDingFrameDispatcher(config.RobotDingtalkConfig{ClientID: "ding-test"}, false, h, zap.NewNop())

	if got := d.dispatch(context.Background(), dingMsg("m-dup", webhook.srv.URL, "你好")); got != "" {
		t.Fatalf("首帧应走异步路径返回空，实际 %q", got)
	}
	// 首帧还在处理中（100ms 延迟）时，钉钉重投同 msgId。
	if got := d.dispatch(context.Background(), dingMsg("m-dup", webhook.srv.URL, "你好")); got != "" {
		t.Fatalf("重投帧应被吞并返回空，实际 %q", got)
	}
	webhook.waitFor(t, 1, 3*time.Second)
	time.Sleep(200 * time.Millisecond) // 给可能存在的错误二次处理留时间暴露
	if h.callCount() != 1 {
		t.Fatalf("重投帧不应再次调用 handler，实际调用了 %d 次", h.callCount())
	}
	if webhook.count() != 1 {
		t.Fatalf("重投帧不应产生第二条回复，实际 webhook 收到 %d 条", webhook.count())
	}
}

// 兜底路径：webhook 为空的异常形态必须保持同步处理并经返回值回复（锁死历史行为）。
func TestDingFrameDispatcher_EmptyWebhookSyncReply(t *testing.T) {
	h := &fakeSlowHandler{reply: "同步回复"}
	d := newDingFrameDispatcher(config.RobotDingtalkConfig{ClientID: "ding-test"}, false, h, zap.NewNop())

	got := d.dispatch(context.Background(), dingMsg("m-sync", "", "你好"))
	if got != "同步回复" {
		t.Fatalf("无 webhook 时应同步返回回复文本，实际 %q", got)
	}
	if h.callCount() != 1 {
		t.Fatalf("handler 应被调用 1 次，实际 %d", h.callCount())
	}
}

// 去重器 TTL 过期：窗口内重复判定为真，过期后视为新消息。
func TestDingDedupe_MarkAndExpire(t *testing.T) {
	d := newDingDedupe(30 * time.Millisecond)
	if d.mark("x") {
		t.Fatal("首次 mark 不应判定为重复")
	}
	if !d.mark("x") {
		t.Fatal("TTL 窗口内的第二次 mark 应判定为重复")
	}
	time.Sleep(60 * time.Millisecond)
	if d.mark("x") {
		t.Fatal("TTL 过期后应视为新消息")
	}
}

// 变异自检：若把去重逻辑去掉（重投帧不吞并），上面的 DuplicateFrameSuppressed
// 会因 handler 被调用 2 次而 FAIL——本测试以反向形态锁死去重器本身有效。
func TestDingDedupe_DistinctIDsNotConfused(t *testing.T) {
	d := newDingDedupe(time.Minute)
	if d.mark("a") || d.mark("b") || d.mark("c") {
		t.Fatal("不同 msgId 不应互相误判为重复")
	}
	if !d.mark("a") || !d.mark("b") {
		t.Fatal("第二次出现相同 msgId 应判定为重复")
	}
}
