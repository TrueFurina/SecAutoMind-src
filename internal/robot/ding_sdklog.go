package robot

import (
	"fmt"

	dinglogger "github.com/open-dingtalk/dingtalk-stream-sdk-go/logger"
	"go.uber.org/zap"
)

// dingSDKLogBridge 把钉钉 Stream SDK 的内部日志桥接到项目 zap 日志。
//
// 为什么必须做（历史教训）：
// SDK 的 logger 默认是 `doNothingLogger`（SDK logger/logger.go:30），
// **所有** Debugf/Infof/Warningf/Errorf 都是空实现。于是：
//   - 读帧错误、topic 未注册（HandlerNotRegistedForTypeTopic）、心跳超时、
//     断连信号 —— 全部被静默丢弃。
// 表现为「日志只有「连接成功」却零消息，且完全查不出原因」。
//
// 🔴 血泪教训（2026-10-03）：第一版桥接器把
//
//	"[wire] [websocket] local => remote"（SDK 处理每个收帧后发回的 ack）
//	"ping time out"（心跳超时 = 连接已死）
//	"processLoop received close signal"（断连信号）
//
// 当作"高频噪音"过滤掉了 —— 结果**把唯一的收帧证据全删了**，
// 导致"连接 62 分钟零帧"这种结论完全不可信（既可能真没消息，也可能是证据被吞）。
//
// 事实（读 SDK client.go 逐行核实）：
//   - 收帧路径 client.go:178 ReadMessage() **不打任何日志**，只有读错误才打（:181）。
//   - 每收到一个数据帧，processDataFrame 必发 ack 并打
//     "[wire] [websocket] local => remote"（client.go:285）——
//     **这是判断"钉钉到底有没有推帧过来"的唯一证据**，ack 里的 code
//     还能区分 200(已处理) / 404(topic 没注册) / 500(处理报错)。
//   - keepAliveIdle 默认 120s，且 ping 成功时**不打日志**（client.go:212 仅错误时打）。
//
// 因此本实现原则：**诊断优先，只截断不丢弃**。
// 仅对超长内容做长度截断（避免单条日志撑爆日志文件），其余一律保留。
// 宁可日志略长，也绝不能丢关键证据——「查不到」比「日志多」危险得多。
type dingSDKLogBridge struct {
	logger *zap.Logger
}

var _ dinglogger.ILogger = (*dingSDKLogBridge)(nil)

// installDingSDKLogger 将 SDK 日志接到 zap。必须在建立 Stream 连接前调用。
func installDingSDKLogger(logger *zap.Logger) {
	dinglogger.SetLogger(&dingSDKLogBridge{logger: logger})
}

// maxSDKLogRunes 单条 SDK 日志最大保留长度（按 rune 计数，避免截断多字节字符）。
const maxSDKLogRunes = 1500

func (b *dingSDKLogBridge) emit(lvl, format string, args ...interface{}) {
	if b == nil || b.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	// 截断而非丢弃：仅控制单条长度，不删除任何类别的日志。
	if r := []rune(msg); len(r) > maxSDKLogRunes {
		msg = string(r[:maxSDKLogRunes]) + "…(已截断)"
	}
	b.logger.Info(msg, zap.String("sdk", "dingtalk"), zap.String("lvl", lvl))
}

func (b *dingSDKLogBridge) Debugf(format string, args ...interface{}) {
	b.emit("debug", format, args...)
}

func (b *dingSDKLogBridge) Infof(format string, args ...interface{}) {
	b.emit("info", format, args...)
}

func (b *dingSDKLogBridge) Warningf(format string, args ...interface{}) {
	b.emit("warn", format, args...)
}

func (b *dingSDKLogBridge) Errorf(format string, args ...interface{}) {
	b.emit("error", format, args...)
}

func (b *dingSDKLogBridge) Fatalf(format string, args ...interface{}) {
	b.emit("fatal", format, args...)
}
