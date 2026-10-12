package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"secautomind-ai/internal/config"
	"secautomind-ai/internal/llm"
	"secautomind-ai/internal/openai"

	"github.com/cloudwego/eino/schema"
	"github.com/gin-gonic/gin"
)

// TestOpenAIRequest 测试OpenAI连接请求
type TestOpenAIRequest struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
	Model    string `json:"model"`
}

// TestOpenAI 测试OpenAI API连接是否可用

// TestOpenAI 测试OpenAI API连接是否可用
func (h *ConfigHandler) TestOpenAI(c *gin.Context) {
	var req TestOpenAIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}

	if strings.TrimSpace(req.APIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key 不能为空"})
		return
	}
	if strings.TrimSpace(req.Model) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "模型不能为空"})
		return
	}

	baseURL := strings.TrimSuffix(strings.TrimSpace(req.BaseURL), "/")
	if baseURL == "" {
		if strings.EqualFold(strings.TrimSpace(req.Provider), "claude") {
			baseURL = "https://api.anthropic.com"
		} else {
			baseURL = "https://api.openai.com/v1"
		}
	}

	// 构造一个最小的 chat completion 请求
	payload := map[string]interface{}{
		"model": req.Model,
		"messages": []map[string]string{
			{"role": "user", "content": "Hi"},
		},
		"max_completion_tokens": 5,
	}

	// OpenAI-compatible 通道使用内部客户端；Claude 通道在下方直接使用 Eino agenticclaude。
	tmpCfg := &config.OpenAIConfig{
		Provider: req.Provider,
		BaseURL:  baseURL,
		APIKey:   strings.TrimSpace(req.APIKey),
		Model:    req.Model,
	}
	client := openai.NewClient(tmpCfg, nil, h.logger)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	start := time.Now()
	if llm.IsClaudeProvider(req.Provider) {
		nativeModel, err := llm.NewClaudeAgenticModel(ctx, *tmpCfg, nil, 5, nil)
		if err == nil {
			_, err = nativeModel.Generate(ctx, []*schema.AgenticMessage{
				schema.UserAgenticMessage("Hi"),
			})
		}
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"error":   "连接失败: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"model":      tmpCfg.Model,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		return
	}

	var chatResp struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	err := client.ChatCompletion(ctx, payload, &chatResp)
	latency := time.Since(start)

	if err != nil {
		if apiErr, ok := err.(*openai.APIError); ok {
			c.JSON(http.StatusOK, gin.H{
				"success":     false,
				"error":       fmt.Sprintf("API 返回错误 (HTTP %d): %s", apiErr.StatusCode, apiErr.Body),
				"status_code": apiErr.StatusCode,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "连接失败: " + err.Error(),
		})
		return
	}

	// 严格校验：必须包含 choices 且有 assistant 回复
	if len(chatResp.Choices) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "API 响应缺少 choices 字段，请检查 Base URL 路径是否正确",
		})
		return
	}
	if chatResp.ID == "" && chatResp.Model == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "API 响应格式不符合预期，请检查 Base URL 是否正确",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"model":      chatResp.Model,
		"latency_ms": latency.Milliseconds(),
	})
}

// ListModelsRequest 获取模型列表请求（OpenAI 兼容 GET /models）。

// ListModelsRequest 获取模型列表请求（OpenAI 兼容 GET /models）。
type ListModelsRequest struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
}

// ListModels 代理调用上游 GET /models，返回可用模型 id 列表。

// ListModels 代理调用上游 GET /models，返回可用模型 id 列表。
func (h *ConfigHandler) ListModels(c *gin.Context) {
	var req ListModelsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}

	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		provider = "openai"
	}
	if strings.EqualFold(provider, "claude") {
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": false,
			"error":     "Claude (Anthropic Messages API) 不支持自动获取模型列表，请手动填写",
		})
		return
	}

	if strings.TrimSpace(req.APIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key 不能为空"})
		return
	}

	baseURL := strings.TrimSuffix(strings.TrimSpace(req.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	tmpCfg := &config.OpenAIConfig{
		Provider: provider,
		BaseURL:  baseURL,
		APIKey:   strings.TrimSpace(req.APIKey),
	}
	client := openai.NewClient(tmpCfg, nil, h.logger)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	models, err := client.ListModels(ctx)
	if err != nil {
		if apiErr, ok := err.(*openai.APIError); ok {
			c.JSON(http.StatusOK, gin.H{
				"success":   false,
				"supported": true,
				"error":     fmt.Sprintf("API 返回错误 (HTTP %d): %s", apiErr.StatusCode, apiErr.Body),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": true,
			"error":     err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"supported": true,
		"models":    models,
		"count":     len(models),
	})
}

// TestVisionRequest 测试 Vision 模型连接；vision.api_key/base_url 留空时可传 openai 段作回退。

// TestVisionRequest 测试 Vision 模型连接；vision.api_key/base_url 留空时可传 openai 段作回退。
type TestVisionRequest struct {
	Vision config.VisionConfig `json:"vision"`
	OpenAI config.OpenAIConfig `json:"openai,omitempty"`
}

// TestVision 测试视觉模型 API 连接（最小 chat completion）。

// TestVision 测试视觉模型 API 连接（最小 chat completion）。
func (h *ConfigHandler) TestVision(c *gin.Context) {
	var req TestVisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}
	oa := req.Vision.OpenAICfgEffective(req.OpenAI)
	if strings.TrimSpace(oa.APIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key 不能为空（可填写 vision.api_key 或 openai.api_key）"})
		return
	}
	if strings.TrimSpace(oa.Model) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "视觉模型不能为空"})
		return
	}

	baseURL := strings.TrimSuffix(strings.TrimSpace(oa.BaseURL), "/")
	if baseURL == "" {
		if strings.EqualFold(strings.TrimSpace(oa.Provider), "claude") {
			baseURL = "https://api.anthropic.com"
		} else {
			baseURL = "https://api.openai.com/v1"
		}
	}

	payload := map[string]interface{}{
		"model": oa.Model,
		"messages": []map[string]string{
			{"role": "user", "content": "Hi"},
		},
		"max_completion_tokens": 5,
	}

	tmpCfg := &config.OpenAIConfig{
		Provider: oa.Provider,
		BaseURL:  baseURL,
		APIKey:   strings.TrimSpace(oa.APIKey),
		Model:    oa.Model,
	}
	client := openai.NewClient(tmpCfg, nil, h.logger)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	start := time.Now()
	var chatResp struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	err := client.ChatCompletion(ctx, payload, &chatResp)
	latency := time.Since(start)

	if err != nil {
		if apiErr, ok := err.(*openai.APIError); ok {
			c.JSON(http.StatusOK, gin.H{
				"success":     false,
				"error":       fmt.Sprintf("API 返回错误 (HTTP %d): %s", apiErr.StatusCode, apiErr.Body),
				"status_code": apiErr.StatusCode,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "连接失败: " + err.Error(),
		})
		return
	}
	if len(chatResp.Choices) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "API 响应缺少 choices 字段，请检查 Base URL 与视觉模型名称",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"model":      chatResp.Model,
		"latency_ms": latency.Milliseconds(),
	})
}

// ApplyConfig 应用配置（重新加载并重启相关服务）
