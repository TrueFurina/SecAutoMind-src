package handler

import (
	"net/http"
	"strings"
	"time"

	"secautomind-ai/internal/audit"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/knowledge"
	"secautomind-ai/internal/mcp"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// UpdateConfigRequest 更新配置请求
type UpdateConfigRequest struct {
	AI         *config.AIConfig            `json:"ai,omitempty"`
	OpenAI     *config.OpenAIConfig        `json:"openai,omitempty"`
	Vision     *config.VisionConfig        `json:"vision,omitempty"`
	FOFA       *config.FofaConfig          `json:"fofa,omitempty"`
	ZoomEye    *config.SpaceSearchConfig   `json:"zoomeye,omitempty"`
	Quake      *config.SpaceSearchConfig   `json:"quake,omitempty"`
	Shodan     *config.SpaceSearchConfig   `json:"shodan,omitempty"`
	MCP        *config.MCPConfig           `json:"mcp,omitempty"`
	Tools      []ToolEnableStatus          `json:"tools,omitempty"`
	Agent      *AgentConfigUpdate          `json:"agent,omitempty"`
	Hitl       *config.HitlConfig          `json:"hitl,omitempty"`
	Knowledge  *config.KnowledgeConfig     `json:"knowledge,omitempty"`
	Robots     *config.RobotsConfig        `json:"robots,omitempty"`
	MultiAgent *config.MultiAgentAPIUpdate `json:"multi_agent,omitempty"`
	C2         *config.C2APIUpdate         `json:"c2,omitempty"`
}

// AgentConfigUpdate 用于 PATCH /api/config 的 agent 段：仅 JSON 中出现的字段（指针非 nil）覆盖内存配置。
// 避免旧版「整包替换 *AgentConfig」时，未传的整型字段被反序列化为 0 误覆盖（例如 tool_timeout_minutes 变成 0）。

// AgentConfigUpdate 用于 PATCH /api/config 的 agent 段：仅 JSON 中出现的字段（指针非 nil）覆盖内存配置。
// 避免旧版「整包替换 *AgentConfig」时，未传的整型字段被反序列化为 0 误覆盖（例如 tool_timeout_minutes 变成 0）。
type AgentConfigUpdate struct {
	MaxIterations                      *int    `json:"max_iterations,omitempty"`
	ToolTimeoutMinutes                 *int    `json:"tool_timeout_minutes,omitempty"`
	ToolWaitTimeoutSeconds             *int    `json:"tool_wait_timeout_seconds,omitempty"`
	ExternalMCPMaxConcurrentPerServer  *int    `json:"external_mcp_max_concurrent_per_server,omitempty"`
	ExternalMCPMaxConcurrentTotal      *int    `json:"external_mcp_max_concurrent_total,omitempty"`
	ExternalMCPCircuitFailureThreshold *int    `json:"external_mcp_circuit_failure_threshold,omitempty"`
	ExternalMCPCircuitCooldownSeconds  *int    `json:"external_mcp_circuit_cooldown_seconds,omitempty"`
	SystemPromptPath                   *string `json:"system_prompt_path,omitempty"`
}

func applyAgentConfigUpdate(dst *config.AgentConfig, src *AgentConfigUpdate) {
	if dst == nil || src == nil {
		return
	}
	if src.MaxIterations != nil {
		dst.MaxIterations = *src.MaxIterations
	}
	if src.ToolTimeoutMinutes != nil {
		dst.ToolTimeoutMinutes = *src.ToolTimeoutMinutes
	}
	if src.ToolWaitTimeoutSeconds != nil {
		dst.ToolWaitTimeoutSeconds = *src.ToolWaitTimeoutSeconds
	}
	if src.ExternalMCPMaxConcurrentPerServer != nil {
		dst.ExternalMCPMaxConcurrentPerServer = *src.ExternalMCPMaxConcurrentPerServer
	}
	if src.ExternalMCPMaxConcurrentTotal != nil {
		dst.ExternalMCPMaxConcurrentTotal = *src.ExternalMCPMaxConcurrentTotal
	}
	if src.ExternalMCPCircuitFailureThreshold != nil {
		dst.ExternalMCPCircuitFailureThreshold = *src.ExternalMCPCircuitFailureThreshold
	}
	if src.ExternalMCPCircuitCooldownSeconds != nil {
		dst.ExternalMCPCircuitCooldownSeconds = *src.ExternalMCPCircuitCooldownSeconds
	}
	if src.SystemPromptPath != nil {
		dst.SystemPromptPath = *src.SystemPromptPath
	}
}

// ToolEnableStatus 工具启用状态

// UpdateConfig 更新配置
func (h *ConfigHandler) UpdateConfig(c *gin.Context) {
	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// 更新OpenAI配置
	if req.AI != nil {
		h.config.AI = *req.AI
		h.config.ApplyDefaultAIChannel()
		h.logger.Info("更新 AI 通道配置",
			zap.String("default_channel", h.config.AI.DefaultChannel),
			zap.Int("channels", len(h.config.AI.Channels)),
		)
	}
	if req.OpenAI != nil {
		h.config.OpenAI = *req.OpenAI
		h.config.AI.EnsureDefaultFromOpenAI(h.config.OpenAI)
		if def := config.NormalizeAIChannelID(h.config.AI.DefaultChannel); def != "" {
			h.config.AI.Channels[def] = config.AIChannelFromOpenAI(def, "Default", h.config.OpenAI)
		}
		h.logger.Info("更新OpenAI配置",
			zap.String("base_url", h.config.OpenAI.BaseURL),
			zap.String("model", h.config.OpenAI.Model),
		)
	}

	if req.Vision != nil {
		h.config.Vision = *req.Vision
		h.logger.Info("更新 Vision 配置",
			zap.Bool("enabled", h.config.Vision.Enabled),
			zap.String("model", h.config.Vision.Model),
		)
	}

	// 更新FOFA配置
	if req.FOFA != nil {
		h.config.FOFA = *req.FOFA
		h.logger.Info("更新FOFA配置", zap.String("base_url", h.config.FOFA.BaseURL))
	}
	if req.ZoomEye != nil {
		h.config.ZoomEye = *req.ZoomEye
		h.logger.Info("更新ZoomEye配置", zap.String("base_url", h.config.ZoomEye.BaseURL))
	}
	if req.Quake != nil {
		h.config.Quake = *req.Quake
		h.logger.Info("更新Quake配置", zap.String("base_url", h.config.Quake.BaseURL))
	}
	if req.Shodan != nil {
		h.config.Shodan = *req.Shodan
		h.logger.Info("更新Shodan配置", zap.String("base_url", h.config.Shodan.BaseURL))
	}

	// 更新MCP配置
	if req.MCP != nil {
		h.config.MCP = *req.MCP
		h.logger.Info("更新MCP配置",
			zap.Bool("enabled", h.config.MCP.Enabled),
			zap.String("host", h.config.MCP.Host),
			zap.Int("port", h.config.MCP.Port),
		)
	}

	// 更新Agent配置（按字段合并，避免部分 JSON 把未出现的字段写成 0）
	if req.Agent != nil {
		applyAgentConfigUpdate(&h.config.Agent, req.Agent)
		h.logger.Info("更新Agent配置",
			zap.Int("max_iterations", h.config.Agent.MaxIterations),
			zap.Int("tool_timeout_minutes", h.config.Agent.ToolTimeoutMinutes),
			zap.Int("tool_wait_timeout_seconds", h.config.Agent.ToolWaitTimeoutSeconds),
			zap.Int("external_mcp_max_concurrent_per_server", h.config.Agent.ExternalMCPMaxConcurrentPerServer),
			zap.Int("external_mcp_max_concurrent_total", h.config.Agent.ExternalMCPMaxConcurrentTotal),
			zap.Int("external_mcp_circuit_failure_threshold", h.config.Agent.ExternalMCPCircuitFailureThreshold),
			zap.Int("external_mcp_circuit_cooldown_seconds", h.config.Agent.ExternalMCPCircuitCooldownSeconds),
		)
		if h.agent != nil && req.Agent.MaxIterations != nil {
			h.agent.UpdateMaxIterations(h.config.Agent.MaxIterations)
		}
		if h.executor != nil {
			h.executor.SetToolOutputMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
			h.executor.SetToolOutputSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
		}
		if h.mcpServer != nil {
			h.mcpServer.ConfigureHTTPToolCallTimeoutFromAgentMinutes(h.config.Agent.ToolTimeoutMinutes)
			h.mcpServer.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
			h.mcpServer.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
			h.mcpServer.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
		}
		if h.externalMCPMgr != nil {
			h.externalMCPMgr.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
			h.externalMCPMgr.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
			h.externalMCPMgr.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
			h.externalMCPMgr.ConfigureResilience(mcp.ExternalMCPResilienceConfig{
				MaxConcurrentPerServer:  h.config.Agent.ExternalMCPMaxConcurrentPerServer,
				MaxConcurrentTotal:      h.config.Agent.ExternalMCPMaxConcurrentTotal,
				CircuitFailureThreshold: h.config.Agent.ExternalMCPCircuitFailureThreshold,
				CircuitCooldown:         time.Duration(h.config.Agent.ExternalMCPCircuitCooldownSeconds) * time.Second,
			})
		}
	}

	if req.Hitl != nil {
		h.config.Hitl.AuditModel = req.Hitl.AuditModel
		h.config.Hitl.ToolWhitelist = mergeHitlToolWhitelistSlice(nil, req.Hitl.ToolWhitelist)
		if strings.TrimSpace(req.Hitl.DefaultMode) != "" {
			h.config.Hitl.DefaultMode = req.Hitl.EffectiveDefaultMode()
		}
		h.config.Hitl.DefaultReviewer = req.Hitl.EffectiveDefaultReviewer()
		if req.Hitl.DefaultTimeoutSeconds != nil {
			v := req.Hitl.EffectiveDefaultTimeoutSeconds()
			h.config.Hitl.DefaultTimeoutSeconds = &v
		}
		h.config.Hitl.AuditAgentPrompt = strings.TrimSpace(req.Hitl.AuditAgentPrompt)
		h.config.Hitl.AuditAgentPromptReviewEdit = strings.TrimSpace(req.Hitl.AuditAgentPromptReviewEdit)
		if req.Hitl.RetentionDays != nil {
			v := *req.Hitl.RetentionDays
			if v < 0 {
				v = 0
			}
			h.config.Hitl.RetentionDays = &v
		}
		h.logger.Info("更新HITL配置",
			zap.String("default_reviewer", h.config.Hitl.DefaultReviewer),
			zap.Int("tool_whitelist", len(h.config.Hitl.ToolWhitelist)),
		)
	}

	// 更新Knowledge配置
	if req.Knowledge != nil {
		// 保存旧的嵌入模型配置（用于检测变更）
		if h.config.Knowledge.Enabled {
			h.lastEmbeddingConfig = &config.EmbeddingConfig{
				Provider: h.config.Knowledge.Embedding.Provider,
				Model:    h.config.Knowledge.Embedding.Model,
				BaseURL:  h.config.Knowledge.Embedding.BaseURL,
				APIKey:   h.config.Knowledge.Embedding.APIKey,
			}
		}
		h.config.Knowledge = *req.Knowledge
		h.logger.Info("更新Knowledge配置",
			zap.Bool("enabled", h.config.Knowledge.Enabled),
			zap.String("base_path", h.config.Knowledge.BasePath),
			zap.String("embedding_model", h.config.Knowledge.Embedding.Model),
			zap.Int("retrieval_top_k", h.config.Knowledge.Retrieval.TopK),
			zap.Float64("similarity_threshold", h.config.Knowledge.Retrieval.SimilarityThreshold),
		)
	}

	// 更新机器人配置
	if req.Robots != nil {
		if err := config.ValidateWecomConfig(req.Robots.Wecom); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := config.ValidateRobotsAuthorization(*req.Robots); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := h.validateRobotServiceAccounts(*req.Robots); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		h.config.Robots = *req.Robots
		h.logger.Info("更新机器人配置",
			zap.Bool("wechat_enabled", h.config.Robots.Wechat.Enabled),
			zap.Bool("wecom_enabled", h.config.Robots.Wecom.Enabled),
			zap.Bool("dingtalk_enabled", h.config.Robots.Dingtalk.Enabled),
			zap.Bool("lark_enabled", h.config.Robots.Lark.Enabled),
			zap.Bool("telegram_enabled", h.config.Robots.Telegram.Enabled),
			zap.Bool("slack_enabled", h.config.Robots.Slack.Enabled),
			zap.Bool("discord_enabled", h.config.Robots.Discord.Enabled),
			zap.Bool("qq_enabled", h.config.Robots.QQ.Enabled),
		)
	}

	if req.C2 != nil {
		v := req.C2.Enabled
		h.config.C2.Enabled = &v
		h.logger.Info("更新C2配置", zap.Bool("enabled", v))
	}

	// 多代理标量（sub_agents 等仍由 config.yaml 维护）
	if req.MultiAgent != nil {
		h.config.MultiAgent.Enabled = req.MultiAgent.Enabled
		h.config.MultiAgent.BatchUseMultiAgent = req.MultiAgent.BatchUseMultiAgent
		if mode := strings.TrimSpace(req.MultiAgent.RobotDefaultAgentMode); mode != "" {
			h.config.MultiAgent.RobotDefaultAgentMode = mode
		} else {
			h.config.MultiAgent.RobotDefaultAgentMode = "eino_single"
		}
		if req.MultiAgent.PlanExecuteLoopMaxIterations != nil {
			h.config.MultiAgent.PlanExecuteLoopMaxIterations = *req.MultiAgent.PlanExecuteLoopMaxIterations
		}
		if req.MultiAgent.SummarizationUserIntentLedgerMaxRunes != nil {
			v := *req.MultiAgent.SummarizationUserIntentLedgerMaxRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerMaxRunes = v
		}
		if req.MultiAgent.SummarizationUserIntentLedgerEntryMaxRunes != nil {
			v := *req.MultiAgent.SummarizationUserIntentLedgerEntryMaxRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunes = v
		}
		if req.MultiAgent.LatestUserMessageMaxRunes != nil {
			v := *req.MultiAgent.LatestUserMessageMaxRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.LatestUserMessageMaxRunes = v
		}
		if req.MultiAgent.LatestUserMessageHeadRunes != nil {
			v := *req.MultiAgent.LatestUserMessageHeadRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.LatestUserMessageHeadRunes = v
		}
		if req.MultiAgent.LatestUserMessageTailRunes != nil {
			v := *req.MultiAgent.LatestUserMessageTailRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.LatestUserMessageTailRunes = v
		}
		if req.MultiAgent.ModelRetryMaxRetries != nil {
			v := *req.MultiAgent.ModelRetryMaxRetries
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.ModelRetryMaxRetries = v
		}
		if req.MultiAgent.ModelRetryMaxBackoffSec != nil {
			v := *req.MultiAgent.ModelRetryMaxBackoffSec
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.ModelRetryMaxBackoffSec = v
		}
		if req.MultiAgent.ModelFailoverChannels != nil {
			h.config.MultiAgent.EinoMiddleware.ModelFailoverChannels = dedupeTrimmedStringList(*req.MultiAgent.ModelFailoverChannels)
		}
		if req.MultiAgent.ModelFailoverMaxRetries != nil {
			v := *req.MultiAgent.ModelFailoverMaxRetries
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.ModelFailoverMaxRetries = v
		}
		if req.MultiAgent.ToolSearchAlwaysVisibleTools != nil {
			h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools = dedupeToolNameList(*req.MultiAgent.ToolSearchAlwaysVisibleTools)
		}
		h.logger.Info("更新多代理配置",
			zap.Bool("enabled", h.config.MultiAgent.Enabled),
			zap.String("robot_default_agent_mode", config.NormalizeRobotAgentMode(h.config.MultiAgent)),
			zap.Bool("batch_use_multi_agent", h.config.MultiAgent.BatchUseMultiAgent),
			zap.Int("plan_execute_loop_max_iterations", h.config.MultiAgent.PlanExecuteLoopMaxIterations),
			zap.Int("summarization_user_intent_ledger_max_runes", h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerMaxRunesEffective()),
			zap.Int("summarization_user_intent_ledger_entry_max_runes", h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunesEffective()),
			zap.Int("latest_user_message_max_runes", h.config.MultiAgent.EinoMiddleware.LatestUserMessageMaxRunesEffective()),
			zap.Int("latest_user_message_head_runes", h.config.MultiAgent.EinoMiddleware.LatestUserMessageHeadRunesEffective()),
			zap.Int("latest_user_message_tail_runes", h.config.MultiAgent.EinoMiddleware.LatestUserMessageTailRunesEffective()),
			zap.Int("model_retry_max_retries", h.config.MultiAgent.EinoMiddleware.ModelRetryMaxRetries),
			zap.Int("model_retry_max_backoff_sec", h.config.MultiAgent.EinoMiddleware.ModelRetryMaxBackoffSec),
			zap.Int("model_failover_channels", len(h.config.MultiAgent.EinoMiddleware.ModelFailoverChannels)),
			zap.Int("model_failover_max_retries", h.config.MultiAgent.EinoMiddleware.ModelFailoverMaxRetries),
			zap.Int("tool_search_always_visible_tools", len(h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools)),
		)
	}

	// 更新工具启用状态
	if req.Tools != nil {
		// 分离内部工具和外部工具
		internalToolMap := make(map[string]bool)
		// 外部工具状态：MCP名称 -> 工具名称 -> 启用状态
		externalMCPToolMap := make(map[string]map[string]bool)

		for _, toolStatus := range req.Tools {
			if toolStatus.IsExternal && toolStatus.ExternalMCP != "" {
				// 外部工具：保存每个工具的独立状态
				mcpName := toolStatus.ExternalMCP
				if externalMCPToolMap[mcpName] == nil {
					externalMCPToolMap[mcpName] = make(map[string]bool)
				}
				externalMCPToolMap[mcpName][toolStatus.Name] = toolStatus.Enabled
			} else {
				// 内部工具
				internalToolMap[toolStatus.Name] = toolStatus.Enabled
			}
		}

		// 更新内部工具状态
		for i := range h.config.Security.Tools {
			if enabled, ok := internalToolMap[h.config.Security.Tools[i].Name]; ok {
				h.config.Security.Tools[i].Enabled = enabled
				h.logger.Info("更新工具启用状态",
					zap.String("tool", h.config.Security.Tools[i].Name),
					zap.Bool("enabled", enabled),
				)
			}
		}

		// 更新外部MCP工具状态
		if h.externalMCPMgr != nil {
			for mcpName, toolStates := range externalMCPToolMap {
				// 更新配置中的工具启用状态
				if h.config.ExternalMCP.Servers == nil {
					h.config.ExternalMCP.Servers = make(map[string]config.ExternalMCPServerConfig)
				}
				cfg, exists := h.config.ExternalMCP.Servers[mcpName]
				if !exists {
					h.logger.Warn("外部MCP配置不存在", zap.String("mcp", mcpName))
					continue
				}

				// 初始化ToolEnabled map
				if cfg.ToolEnabled == nil {
					cfg.ToolEnabled = make(map[string]bool)
				}

				// 更新每个工具的启用状态
				for toolName, enabled := range toolStates {
					cfg.ToolEnabled[toolName] = enabled
					h.logger.Info("更新外部工具启用状态",
						zap.String("mcp", mcpName),
						zap.String("tool", toolName),
						zap.Bool("enabled", enabled),
					)
				}

				// 检查是否有任何工具启用，如果有则启用MCP
				hasEnabledTool := false
				for _, enabled := range cfg.ToolEnabled {
					if enabled {
						hasEnabledTool = true
						break
					}
				}

				// 如果MCP之前未启用，但现在有工具启用，则启用MCP
				// 如果MCP之前已启用，保持启用状态（允许部分工具禁用）
				if !cfg.ExternalMCPEnable && hasEnabledTool {
					cfg.ExternalMCPEnable = true
					h.logger.Info("自动启用外部MCP（因为有工具启用）", zap.String("mcp", mcpName))
				}

				h.config.ExternalMCP.Servers[mcpName] = cfg
			}

			// 同步更新 externalMCPMgr 中的配置，确保 GetConfigs() 返回最新配置
			// 在循环外部统一更新，避免重复调用
			h.externalMCPMgr.LoadConfigs(&h.config.ExternalMCP)

			// 处理MCP连接状态（异步启动，避免阻塞）
			for mcpName := range externalMCPToolMap {
				cfg := h.config.ExternalMCP.Servers[mcpName]
				// 如果MCP需要启用，确保客户端已启动
				if cfg.ExternalMCPEnable {
					// 启动外部MCP（如果未启动）- 异步执行，避免阻塞
					client, exists := h.externalMCPMgr.GetClient(mcpName)
					if !exists || !client.IsConnected() {
						go func(name string) {
							if err := h.externalMCPMgr.StartClient(name); err != nil {
								h.logger.Warn("启动外部MCP失败",
									zap.String("mcp", name),
									zap.Error(err),
								)
							} else {
								h.logger.Info("启动外部MCP",
									zap.String("mcp", name),
								)
							}
						}(mcpName)
					}
				}
			}
		}
	}

	h.config.NormalizeAIProviderProfiles()

	// 保存配置到文件
	if err := h.saveConfig(); err != nil {
		h.logger.Error("保存配置失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置失败: " + err.Error()})
		return
	}

	if h.audit != nil {
		h.audit.RecordOK(c, "config", "update", "更新内存配置", "config", "", nil)
	}
	c.JSON(http.StatusOK, gin.H{"message": "配置已更新"})
}

// TestOpenAIRequest 测试OpenAI连接请求

// ApplyConfig 应用配置（重新加载并重启相关服务）
func (h *ConfigHandler) ApplyConfig(c *gin.Context) {
	// 先检查是否需要动态初始化知识库（在锁外执行，避免阻塞其他请求）
	var needInitKnowledge bool
	var knowledgeInitializer KnowledgeInitializer

	h.mu.RLock()
	needInitKnowledge = h.config.Knowledge.Enabled && h.knowledgeToolRegistrar == nil && h.knowledgeInitializer != nil
	if needInitKnowledge {
		knowledgeInitializer = h.knowledgeInitializer
	}
	h.mu.RUnlock()

	// 如果需要动态初始化知识库，在锁外执行（这是耗时操作）
	if needInitKnowledge {
		h.logger.Info("检测到知识库从禁用变为启用，开始动态初始化知识库组件")
		if _, err := knowledgeInitializer(); err != nil {
			h.logger.Error("动态初始化知识库失败", zap.Error(err))
			if h.audit != nil {
				h.audit.RecordFail(c, "config", "apply", "应用配置失败：初始化知识库", map[string]interface{}{"error": err.Error()})
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "初始化知识库失败: " + err.Error()})
			return
		}
		h.logger.Debug("知识库动态初始化完成，工具已注册")
	}

	// 检查嵌入模型配置是否变更（需要在锁外执行，避免阻塞）
	var needReinitKnowledge bool
	var reinitKnowledgeInitializer KnowledgeInitializer
	h.mu.RLock()
	if h.config.Knowledge.Enabled && h.knowledgeInitializer != nil && h.lastEmbeddingConfig != nil {
		// 检查嵌入模型配置是否变更
		currentEmbedding := h.config.Knowledge.Embedding
		if currentEmbedding.Provider != h.lastEmbeddingConfig.Provider ||
			currentEmbedding.Model != h.lastEmbeddingConfig.Model ||
			currentEmbedding.BaseURL != h.lastEmbeddingConfig.BaseURL ||
			currentEmbedding.APIKey != h.lastEmbeddingConfig.APIKey {
			needReinitKnowledge = true
			reinitKnowledgeInitializer = h.knowledgeInitializer
			h.logger.Info("检测到嵌入模型配置变更，需要重新初始化知识库组件",
				zap.String("old_model", h.lastEmbeddingConfig.Model),
				zap.String("new_model", currentEmbedding.Model),
				zap.String("old_base_url", h.lastEmbeddingConfig.BaseURL),
				zap.String("new_base_url", currentEmbedding.BaseURL),
			)
		}
	}
	h.mu.RUnlock()

	// 如果需要重新初始化知识库（嵌入模型配置变更），在锁外执行
	if needReinitKnowledge {
		h.logger.Info("开始重新初始化知识库组件（嵌入模型配置已变更）")
		if _, err := reinitKnowledgeInitializer(); err != nil {
			h.logger.Error("重新初始化知识库失败", zap.Error(err))
			if h.audit != nil {
				h.audit.RecordFail(c, "config", "apply", "应用配置失败：重新初始化知识库", map[string]interface{}{"error": err.Error()})
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "重新初始化知识库失败: " + err.Error()})
			return
		}
		h.logger.Info("知识库组件重新初始化完成")
	}

	// C2：在 ClearTools 之前按配置启停（随后由 c2ToolRegistrar 注册 MCP 工具）
	h.mu.RLock()
	c2Rt := h.c2Runtime
	h.mu.RUnlock()
	if c2Rt != nil {
		if err := c2Rt.ReconcileC2AfterConfigApply(); err != nil {
			h.logger.Error("C2 配置应用失败", zap.Error(err))
			if h.audit != nil {
				h.audit.RecordFail(c, "config", "apply", "应用配置失败：C2", map[string]interface{}{"error": err.Error()})
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "C2 启动失败: " + err.Error()})
			return
		}
	}

	// 现在获取写锁，执行快速的操作
	h.mu.Lock()
	defer h.mu.Unlock()

	// 如果重新初始化了知识库，更新嵌入模型配置记录
	if needReinitKnowledge && h.config.Knowledge.Enabled {
		h.lastEmbeddingConfig = &config.EmbeddingConfig{
			Provider: h.config.Knowledge.Embedding.Provider,
			Model:    h.config.Knowledge.Embedding.Model,
			BaseURL:  h.config.Knowledge.Embedding.BaseURL,
			APIKey:   h.config.Knowledge.Embedding.APIKey,
		}
		h.logger.Info("已更新嵌入模型配置记录")
	}

	// 从 tools 目录重新加载工具配置（新增/修改/删除 yaml 后无需重启）
	if err := config.ReloadSecurityToolsFromDir(h.config, h.configPath); err != nil {
		h.logger.Error("重新加载工具配置失败", zap.Error(err))
		if h.audit != nil {
			h.audit.RecordFail(c, "config", "apply", "应用配置失败：重新加载工具", map[string]interface{}{"error": err.Error()})
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重新加载工具配置失败: " + err.Error()})
		return
	}
	h.logger.Debug("已从 tools 目录重新加载工具配置", zap.Int("tools_count", len(h.config.Security.Tools)))

	// 重新注册工具（根据新的启用状态）
	h.logger.Debug("重新注册工具")

	// 清空MCP服务器中的工具
	h.mcpServer.ClearTools()

	// 重新注册安全工具
	h.executor.SetToolOutputMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
	h.executor.SetToolOutputSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
	h.executor.RegisterTools(h.mcpServer)
	mcp.RegisterExecutionControlTools(h.mcpServer, h.externalMCPMgr)

	// 重新注册漏洞记录工具（内置工具，必须注册）
	if h.vulnerabilityToolRegistrar != nil {
		h.logger.Info("重新注册漏洞记录工具")
		if err := h.vulnerabilityToolRegistrar(); err != nil {
			h.logger.Error("重新注册漏洞记录工具失败", zap.Error(err))
		} else {
			h.logger.Info("漏洞记录工具已重新注册")
		}
	}

	// 重新注册 WebShell 工具（内置工具，必须注册）
	if h.webshellToolRegistrar != nil {
		h.logger.Info("重新注册 WebShell 工具")
		if err := h.webshellToolRegistrar(); err != nil {
			h.logger.Error("重新注册 WebShell 工具失败", zap.Error(err))
		} else {
			h.logger.Info("WebShell 工具已重新注册")
		}
	}

	// 重新注册Skills工具（内置工具，必须注册）
	if h.skillsToolRegistrar != nil {
		h.logger.Info("重新注册Skills工具")
		if err := h.skillsToolRegistrar(); err != nil {
			h.logger.Error("重新注册Skills工具失败", zap.Error(err))
		} else {
			h.logger.Info("Skills工具已重新注册")
		}
	}

	// 重新注册批量任务 MCP 工具
	if h.batchTaskToolRegistrar != nil {
		h.logger.Info("重新注册批量任务 MCP 工具")
		if err := h.batchTaskToolRegistrar(); err != nil {
			h.logger.Error("重新注册批量任务 MCP 工具失败", zap.Error(err))
		} else {
			h.logger.Info("批量任务 MCP 工具已重新注册")
		}
	}

	// 重新注册 C2 MCP 工具（仅当 C2 已启动）
	if h.c2ToolRegistrar != nil {
		h.logger.Info("重新注册 C2 MCP 工具")
		if err := h.c2ToolRegistrar(); err != nil {
			h.logger.Error("重新注册 C2 MCP 工具失败", zap.Error(err))
		} else {
			h.logger.Info("C2 MCP 工具已处理")
		}
	}

	// 如果知识库启用，重新注册知识库工具
	if h.config.Knowledge.Enabled && h.knowledgeToolRegistrar != nil {
		h.logger.Info("重新注册知识库工具")
		if err := h.knowledgeToolRegistrar(); err != nil {
			h.logger.Error("重新注册知识库工具失败", zap.Error(err))
		} else {
			h.logger.Info("知识库工具已重新注册")
		}
	}

	// 更新Agent的OpenAI配置
	if h.agent != nil {
		h.agent.UpdateConfig(&h.config.OpenAI)
		h.agent.UpdateMaxIterations(h.config.Agent.MaxIterations)
		h.agent.UpdateToolDescriptionMode(h.config.Security.ToolDescriptionMode)
		h.logger.Info("Agent配置已更新")
	}
	if h.mcpServer != nil {
		h.mcpServer.ConfigureHTTPToolCallTimeoutFromAgentMinutes(h.config.Agent.ToolTimeoutMinutes)
		h.mcpServer.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
		h.mcpServer.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
		h.mcpServer.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
	}
	if h.executor != nil {
		h.executor.SetToolOutputMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
		h.executor.SetToolOutputSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
	}
	if h.externalMCPMgr != nil {
		h.externalMCPMgr.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
		h.externalMCPMgr.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
		h.externalMCPMgr.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
		h.externalMCPMgr.ConfigureResilience(mcp.ExternalMCPResilienceConfig{
			MaxConcurrentPerServer:  h.config.Agent.ExternalMCPMaxConcurrentPerServer,
			MaxConcurrentTotal:      h.config.Agent.ExternalMCPMaxConcurrentTotal,
			CircuitFailureThreshold: h.config.Agent.ExternalMCPCircuitFailureThreshold,
			CircuitCooldown:         time.Duration(h.config.Agent.ExternalMCPCircuitCooldownSeconds) * time.Second,
		})
	}

	// 更新AttackChainHandler的OpenAI配置
	if h.attackChainHandler != nil {
		h.attackChainHandler.UpdateConfig(&h.config.OpenAI)
		h.logger.Info("AttackChainHandler配置已更新")
	}

	// 更新检索器配置（如果知识库启用）
	if h.config.Knowledge.Enabled && h.retrieverUpdater != nil {
		retrievalConfig := knowledge.RetrievalConfigFromYAML(h.config.Knowledge.Retrieval)
		h.retrieverUpdater.UpdateConfig(retrievalConfig)
		h.logger.Info("检索器配置已更新",
			zap.Int("top_k", retrievalConfig.TopK),
			zap.Float64("similarity_threshold", retrievalConfig.SimilarityThreshold),
		)
	}

	// 更新嵌入模型配置记录（如果知识库启用）
	if h.config.Knowledge.Enabled {
		h.lastEmbeddingConfig = &config.EmbeddingConfig{
			Provider: h.config.Knowledge.Embedding.Provider,
			Model:    h.config.Knowledge.Embedding.Model,
			BaseURL:  h.config.Knowledge.Embedding.BaseURL,
			APIKey:   h.config.Knowledge.Embedding.APIKey,
		}
	}

	// 重启钉钉/飞书长连接，使前端修改的机器人配置立即生效（无需重启服务）
	if h.robotRestarter != nil {
		h.robotRestarter.RestartRobotConnections()
		h.logger.Info("已触发机器人连接重启（钉钉/飞书）")
	}

	h.logger.Info("配置已应用",
		zap.Int("tools_count", len(h.config.Security.Tools)),
	)

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "config",
			Action:   "apply",
			Result:   "success",
			Message:  "配置已应用",
			Detail: map[string]interface{}{
				"tools_count":       len(h.config.Security.Tools),
				"knowledge_enabled": h.config.Knowledge.Enabled,
				"c2_enabled":        h.config.C2.EnabledEffective(),
			},
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "配置已应用",
		"tools_count": len(h.config.Security.Tools),
	})
}

// saveConfig 保存配置到文件
