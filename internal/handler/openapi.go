package handler

import (
	"net/http"

	"secautomind-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// OpenAPIHandler OpenAPI处理器
type OpenAPIHandler struct {
	db               *database.DB
	logger           *zap.Logger
	conversationHdlr *ConversationHandler
	agentHdlr        *AgentHandler
}

// NewOpenAPIHandler 创建新的OpenAPI处理器
func NewOpenAPIHandler(db *database.DB, logger *zap.Logger, conversationHdlr *ConversationHandler, agentHdlr *AgentHandler) *OpenAPIHandler {
	return &OpenAPIHandler{
		db:               db,
		logger:           logger,
		conversationHdlr: conversationHdlr,
		agentHdlr:        agentHdlr,
	}
}

// GetOpenAPISpec 获取OpenAPI规范
func (h *OpenAPIHandler) GetOpenAPISpec(c *gin.Context) {
	host := c.Request.Host
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}

	finalizationRequestSchema := map[string]interface{}{
		"type":        "object",
		"description": "最终回复交付策略。后端不会从自然语言内容推断执行意图；执行入口应显式声明是否要求 completed 工具证据。",
		"properties": map[string]interface{}{
			"requireExecutionEvidence": map[string]interface{}{
				"type":        "boolean",
				"description": "为 true 时，缺少 completed 工具执行记录会触发无注入续跑或最终阻断；普通聊天可省略或设为 false。",
			},
		},
	}

	spec := map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":       "SecAutoMind API",
			"description": "AI驱动的自动化安全测试平台API文档",
			"version":     "1.0.0",
			"contact": map[string]interface{}{
				"name": "SecAutoMind",
			},
		},
		"servers": []map[string]interface{}{
			{
				"url":         scheme + "://" + host,
				"description": "当前服务器",
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
					"description":  "使用Bearer Token进行认证。Token通过 /api/auth/login 接口获取。",
				},
			},
			"schemas": buildOpenAPISchemas(),
		},
		"security": []map[string]interface{}{
			{
				"bearerAuth": []string{},
			},
		},
		"paths": buildOpenAPIPaths(finalizationRequestSchema),
	}

	enrichSpecWithI18nKeys(spec)
	c.JSON(http.StatusOK, spec)
}

// GetConversationResults 获取对话结果（OpenAPI端点）
// 注意：创建对话和获取对话详情直接使用标准的 /api/conversations 端点
// 这个端点只是为了提供结果聚合功能
func (h *OpenAPIHandler) GetConversationResults(c *gin.Context) {
	conversationID := c.Param("id")

	// 验证对话是否存在
	conv, err := h.db.GetConversation(conversationID)
	if err != nil {
		h.logger.Error("获取对话失败", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}

	// 获取消息列表
	messages, err := h.db.GetMessages(conversationID)
	if err != nil {
		h.logger.Error("获取消息失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 获取漏洞列表
	vulnList, err := h.db.ListVulnerabilities(1000, 0, database.VulnerabilityListFilter{ConversationID: conversationID})
	if err != nil {
		h.logger.Warn("获取漏洞列表失败", zap.Error(err))
		vulnList = []*database.Vulnerability{}
	}
	vulnerabilities := make([]database.Vulnerability, len(vulnList))
	for i, v := range vulnList {
		vulnerabilities[i] = *v
	}

	// 获取执行结果（历史大结果由 Eino reduction 落盘，此处不再聚合文件存储）
	executionResults := []map[string]interface{}{}

	response := map[string]interface{}{
		"conversationId":   conv.ID,
		"messages":         messages,
		"vulnerabilities":  vulnerabilities,
		"executionResults": executionResults,
	}

	c.JSON(http.StatusOK, response)
}
