package app

import (
	"log"

	"secautomind-ai/internal/mcp"

	"go.uber.org/zap"
)

// toolInternalError —— 工具**内部错误**的对外收敛口（REA #10 / #176）。
//
// 为什么必须收敛：MCP 工具把失败写进「结果文本」，模型看到的是一段话而不是
// 状态码。`textResult("错误: "+err.Error(), true)` 会把驱动层的
// `database is locked`、表名、绝对路径、SQL 片段原样喂给模型；模型分不清
// 「内部细节」与「事实」，会拿它继续推理，甚至写进报告，而用户看到的是一段
// 谁也看不懂的驱动噪音。对外只需要「发生了什么 + 下一步能做什么」，原文留给日志。
//
// 什么**不该**走这里：入参校验错误。`assetFromCreateArgs`、
// `project.ParseFactLinkInputs`、`assetFilterFromToolArgs` 这类本项目校验函数
// 产生的 err **本来就是写给调用方看的**（"至少提供 host、ip、domain 之一"、
// "summary 过长（最多 N 字）"），它就是可行动文案——收敛掉反而让模型失去了
// 自我纠正的依据。判据一句话：**err 来自本项目校验 → 直出；err 来自
// 数据库/驱动/序列化/作用域解析 → 走本函数。**
//
// `scene` 的写法要求：可行动、不含内部细节、不暴露表名与路径。统一带
// 「（已记日志）」后缀，告诉模型详情在服务端日志里，它不是它该追问的东西。
func toolInternalError(logger *zap.Logger, scene string, err error) *mcp.ToolResult {
	if logger != nil {
		logger.Error("工具内部错误："+scene, zap.Error(err))
	} else {
		// logger 为 nil 时同样必须留痕：静默丢弃 err 等于销毁证据，
		// 事后只剩一句"失败了"无从排查。
		log.Printf("工具内部错误：%s: %v", scene, err)
	}
	return textResult("错误: "+scene, true)
}
