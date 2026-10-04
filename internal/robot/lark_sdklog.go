package robot

import (
	"context"
	"fmt"
	"strings"

	larkcore "github.com/larksuite/oapi-sdk-go/v3/core"
	"go.uber.org/zap"
)

// larkSDKLogBridge 把飞书（Lark）SDK 的内部日志桥接到项目 zap 日志。
//
// 为什么必须做（与 dingSDKLogBridge 同源的历史教训）：
// lark SDK 的 ws.Client 在未注入自定义 Logger 时，默认 logger 写到 os.Stdout
// （core/logger.go 的 NewDefaultLogger），而本服务的结构化日志写的是自己的 zap 文件
// （logs/secautomind.log）。于是飞书长连接的全部诊断——「connected to <url>」、
// 「connect failed, err: ...」、「trying to reconnect: N」——全进了 journald/stdout，
// 项目日志里一条都看不到。
//
// 表现（2026-10-04 实测）：runLarkLoop 只打了一次「飞书长连接正在连接…」就再无下文——
// 既看不到连接成功，也看不到任何失败原因，完全无法判断飞书到底连没连上、为何连不上。
// 这会让演示时「飞书通道静默失效」而无从排查。
//
// 修复：注入本桥接器后，SDK 的建链/失败/重连日志都会落到 zap 文件，grep 即可见真实原因。
//
// 原则同 DingTalk：诊断优先，只截断不丢弃。
type larkSDKLogBridge struct {
	logger *zap.Logger
}

var _ larkcore.Logger = (*larkSDKLogBridge)(nil)

// installLarkSDKLogger 构造飞书 SDK 日志桥。在建立长连接前传入 WithLogger 即可。
func installLarkSDKLogger(logger *zap.Logger) *larkSDKLogBridge {
	return &larkSDKLogBridge{logger: logger}
}

// emit 把 SDK 的 (msg, kv...) 参数拼成一个字符串后落到 zap，sdk 标注 feishu。
// SDK 调用形如 c.logger.Info(ctx, c.fmtLog("connected to %s", u)...)，
// fmtLog 返回 []interface{}{"<msg>", "[conn_id=xxx]"}，故 args[0] 为消息本体。
func (b *larkSDKLogBridge) emit(lvl string, args ...interface{}) {
	if b == nil || b.logger == nil || len(args) == 0 {
		return
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = fmt.Sprint(a)
	}
	msg := strings.Join(parts, " ")
	// 截断而非丢弃：仅控制单条长度，不删除任何类别的日志。
	if r := []rune(msg); len(r) > maxSDKLogRunes {
		msg = string(r[:maxSDKLogRunes]) + "…(已截断)"
	}
	b.logger.Info(msg, zap.String("sdk", "feishu"), zap.String("lvl", lvl))
}

func (b *larkSDKLogBridge) Debug(ctx context.Context, args ...interface{}) {
	b.emit("debug", args...)
}

func (b *larkSDKLogBridge) Info(ctx context.Context, args ...interface{}) {
	b.emit("info", args...)
}

func (b *larkSDKLogBridge) Warn(ctx context.Context, args ...interface{}) {
	b.emit("warn", args...)
}

func (b *larkSDKLogBridge) Error(ctx context.Context, args ...interface{}) {
	b.emit("error", args...)
}
