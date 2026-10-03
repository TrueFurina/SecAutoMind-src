package robot

import (
	"strings"
	"testing"

	dinglogger "github.com/open-dingtalk/dingtalk-stream-sdk-go/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// ── 钉钉 SDK 日志桥接测试 ─────────────────────────────────
//
// 背景：SDK 默认 logger 是 doNothingLogger（空实现），不桥接则所有 SDK 内部
// 日志（读帧错误/topic 未注册/**收帧 ack**/心跳超时/断连）全部丢失，
// 消息不进时完全无法定位。
//
// 🔴 本文件最重要的用例是 TestDingSDKLogBridge_NeverDropsEvidence：
// 它锁定「只截断不丢弃」原则，防止有人再次把关键证据当噪音过滤掉
// （2026-10-03 曾因此得出"连接 62 分钟零帧"的错误结论）。

func newObservedLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	return zap.New(core), logs
}

func TestDingSDKLogBridge_ForwardsToZap(t *testing.T) {
	lg, logs := newObservedLogger()
	b := &dingSDKLogBridge{logger: lg}

	b.Errorf("connection process read message error: %s", "boom")

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("Errorf 应被桥接进 zap，实际 %d 条", len(entries))
	}
	if !strings.Contains(entries[0].Message, "read message error") {
		t.Errorf("消息内容未保留，got %q", entries[0].Message)
	}
	if entries[0].ContextMap()["sdk"] != "dingtalk" {
		t.Errorf("缺少 sdk=dingtalk 标记，fields=%v", entries[0].ContextMap())
	}
	if entries[0].ContextMap()["lvl"] != "error" {
		t.Errorf("lvl = %v, want error", entries[0].ContextMap()["lvl"])
	}
}

// TestDingSDKLogBridge_NeverDropsEvidence 防止「过滤噪音」再次吃掉关键证据。
//
// SDK 收帧路径（client.go:178 ReadMessage）本身不打日志；每收到一个数据帧，
// processDataFrame 必发 ack 并打 "[wire] [websocket] local => remote"（client.go:285）。
// 这条 ack 是判断「钉钉到底有没有推帧」的唯一证据，ack 的 code 还能区分
// 200(已处理) / 404(topic 未注册) / 500(处理报错)。
//
// 同理「ping time out」「processLoop received close signal」是连接生死证据。
// 这三类任何一条被丢弃，都会让排查结论不可信 —— 曾经就发生过。
func TestDingSDKLogBridge_NeverDropsEvidence(t *testing.T) {
	lg, logs := newObservedLogger()
	b := &dingSDKLogBridge{logger: lg}

	// 这些曾经被误当作"噪音"过滤，导致证据全丢。
	mustKeep := []string{
		`[wire] [websocket] local => remote:{"headers":{"messageId":"abc"},"code":200}`,
		`[wire] [websocket] local => remote:{"headers":{"messageId":"xyz"},"code":404}`,
		"ping time out, connection is closing",
		"connection processLoop received close signal, shutting down.",
		"connection process read message error: error=[unexpected EOF]",
		"HandlerNotRegistedForTypeTopic_CALLBACK_/v1.0/im/bot/messages/get",
		"connection process decode data frame error: length=[0]",
		"connect success, sessionId=[abc-123]",
		"StreamClient reconnect error. error=[EOF]",
		"[wire] [http] remote => localhost:HTTP/2.0 200 OK",
	}
	for _, msg := range mustKeep {
		b.Infof("%s", msg)
	}
	if got := logs.Len(); got != len(mustKeep) {
		t.Errorf("关键证据日志不得被过滤丢弃：期望 %d 条，实际 %d 条", len(mustKeep), got)
	}
}

// TestDingSDKLogBridge_TruncatesInsteadOfDropping 验证超长日志是「截断」而非「丢弃」。
func TestDingSDKLogBridge_TruncatesInsteadOfDropping(t *testing.T) {
	lg, logs := newObservedLogger()
	b := &dingSDKLogBridge{logger: lg}

	huge := strings.Repeat("A", maxSDKLogRunes*3)
	b.Infof("%s", huge)

	if logs.Len() != 1 {
		t.Fatalf("超长日志应被截断保留（1 条），实际 %d 条（0 说明被丢弃了）", logs.Len())
	}
	got := logs.All()[0].Message
	if !strings.Contains(got, "已截断") {
		t.Error("超长日志应带截断标记")
	}
	if len([]rune(got)) > maxSDKLogRunes+len("…(已截断)") {
		t.Errorf("截断后长度仍超限：%d", len([]rune(got)))
	}
}

// TestDingSDKLogBridge_TruncationKeepsMultibyteIntact 确保按 rune 截断不产生乱码。
func TestDingSDKLogBridge_TruncationKeepsMultibyteIntact(t *testing.T) {
	lg, logs := newObservedLogger()
	b := &dingSDKLogBridge{logger: lg}

	cn := strings.Repeat("钉", maxSDKLogRunes+500)
	b.Infof("%s", cn)

	got := logs.All()[0].Message
	if strings.Contains(got, "�") {
		t.Error("按字节截断导致多字节字符被切坏（出现替换字符）")
	}
	if !strings.Contains(got, "钉钉") {
		t.Error("截断后应保留完整的中文字符")
	}
}

func TestDingSDKLogBridge_NilSafe(t *testing.T) {
	// 桥接器在 logger 为 nil 时不能 panic（SDK 可能在日志初始化前就打日志）
	var b *dingSDKLogBridge
	b.Errorf("boom %d", 1)
	empty := &dingSDKLogBridge{}
	empty.Infof("boom")
}

// TestInstallDingSDKLogger 确认安装后 SDK 走的是我们的 logger（而非空实现）。
func TestInstallDingSDKLogger(t *testing.T) {
	lg, logs := newObservedLogger()
	installDingSDKLogger(lg)
	t.Cleanup(func() { installDingSDKLogger(nil) })

	dinglogger.GetLogger().Errorf("bridge-installed-check %s", "ok")

	found := false
	for _, e := range logs.All() {
		if strings.Contains(e.Message, "bridge-installed-check") {
			found = true
			break
		}
	}
	if !found {
		t.Error("SetLogger 后 SDK 日志未进入 zap，桥接未生效")
	}
}
