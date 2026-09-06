package handler

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"secautomind-ai/internal/agents"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/mcp"
	"secautomind-ai/internal/mcp/builtin"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// GetConfigResponse 获取配置响应
type GetConfigResponse struct {
	AI         config.AIConfig          `json:"ai"`
	OpenAI     config.OpenAIConfig      `json:"openai"`
	Vision     config.VisionConfig      `json:"vision"`
	FOFA       config.FofaConfig        `json:"fofa"`
	ZoomEye    config.SpaceSearchConfig `json:"zoomeye"`
	Quake      config.SpaceSearchConfig `json:"quake"`
	Shodan     config.SpaceSearchConfig `json:"shodan"`
	MCP        config.MCPConfig         `json:"mcp"`
	Tools      []ToolConfigInfo         `json:"tools"`
	Agent      config.AgentConfig       `json:"agent"`
	Hitl       config.HitlConfig        `json:"hitl,omitempty"`
	Knowledge  config.KnowledgeConfig   `json:"knowledge"`
	Robots     config.RobotsConfig      `json:"robots,omitempty"`
	MultiAgent config.MultiAgentPublic  `json:"multi_agent,omitempty"`
	C2         config.C2Public          `json:"c2"`
}

// ToolConfigInfo 工具配置信息

// ToolConfigInfo 工具配置信息
type ToolConfigInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	IsExternal  bool                   `json:"is_external,omitempty"`  // 是否为外部MCP工具
	ExternalMCP string                 `json:"external_mcp,omitempty"` // 外部MCP名称（如果是外部工具）
	RoleEnabled *bool                  `json:"role_enabled,omitempty"` // 该工具在当前角色中是否启用（nil表示未指定角色或使用所有工具）
	InputSchema map[string]interface{} `json:"input_schema,omitempty"` // 工具参数 JSON Schema（用于前端展示详情）
}

// GetConfig 获取当前配置

// GetConfig 获取当前配置
func (h *ConfigHandler) GetConfig(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// 获取工具列表（包含内部和外部工具）
	// 首先从配置文件获取工具
	configToolMap := make(map[string]bool)
	tools := make([]ToolConfigInfo, 0, len(h.config.Security.Tools))

	for _, tool := range h.config.Security.Tools {
		configToolMap[tool.Name] = true
		info := ToolConfigInfo{
			Name:        tool.Name,
			Description: h.pickToolDescription(tool.ShortDescription, tool.Description),
			Enabled:     tool.Enabled,
			IsExternal:  false,
		}
		tools = append(tools, info)
	}

	// 从MCP服务器获取所有已注册的工具（包括直接注册的工具，如知识检索工具）
	if h.mcpServer != nil {
		mcpTools := h.mcpServer.GetAllTools()
		for _, mcpTool := range mcpTools {
			if configToolMap[mcpTool.Name] {
				continue
			}
			description := h.pickToolDescription(mcpTool.ShortDescription, mcpTool.Description)
			tools = append(tools, ToolConfigInfo{
				Name:        mcpTool.Name,
				Description: description,
				Enabled:     true,
				IsExternal:  false,
			})
		}
	}

	// 获取外部MCP工具（走缓存，持锁期间通常不阻塞）
	if h.externalMCPMgr != nil {
		ctx := context.Background()
		externalTools := h.getExternalMCPTools(ctx)
		for _, toolInfo := range externalTools {
			tools = append(tools, toolInfo)
		}
	}

	subAgentCount := len(h.config.MultiAgent.SubAgents)
	agentsDir := strings.TrimSpace(h.config.AgentsDir)
	if agentsDir == "" {
		agentsDir = "agents"
	}
	if !filepath.IsAbs(agentsDir) {
		agentsDir = filepath.Join(filepath.Dir(h.configPath), agentsDir)
	}
	if load, err := agents.LoadMarkdownAgentsDir(agentsDir); err == nil {
		subAgentCount = len(agents.MergeYAMLAndMarkdown(h.config.MultiAgent.SubAgents, load.SubAgents))
	}
	multiPub := config.MultiAgentPublic{
		Enabled:                                    h.config.MultiAgent.Enabled,
		RobotDefaultAgentMode:                      config.NormalizeRobotAgentMode(h.config.MultiAgent),
		BatchUseMultiAgent:                         h.config.MultiAgent.BatchUseMultiAgent,
		SubAgentCount:                              subAgentCount,
		Orchestration:                              config.NormalizeMultiAgentOrchestration(h.config.MultiAgent.Orchestration),
		PlanExecuteLoopMaxIterations:               h.config.MultiAgent.PlanExecuteLoopMaxIterations,
		SummarizationUserIntentLedgerMaxRunes:      h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerMaxRunesEffective(),
		SummarizationUserIntentLedgerEntryMaxRunes: h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunesEffective(),
		LatestUserMessageMaxRunes:                  h.config.MultiAgent.EinoMiddleware.LatestUserMessageMaxRunesEffective(),
		LatestUserMessageHeadRunes:                 h.config.MultiAgent.EinoMiddleware.LatestUserMessageHeadRunesEffective(),
		LatestUserMessageTailRunes:                 h.config.MultiAgent.EinoMiddleware.LatestUserMessageTailRunesEffective(),
		ModelRetryMaxRetries:                       h.config.MultiAgent.EinoMiddleware.ModelRetryMaxRetries,
		ModelRetryMaxBackoffSec:                    h.config.MultiAgent.EinoMiddleware.ModelRetryMaxBackoffSec,
		ModelFailoverChannels:                      append([]string(nil), h.config.MultiAgent.EinoMiddleware.ModelFailoverChannels...),
		ModelFailoverMaxRetries:                    h.config.MultiAgent.EinoMiddleware.ModelFailoverMaxRetries,
		ToolSearchAlwaysVisibleTools:               append([]string(nil), h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools...),
		ToolSearchAlwaysVisibleEffectiveTools: mergeToolNameLists(
			h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools,
			builtin.GetAllBuiltinTools(),
		),
	}

	c.JSON(http.StatusOK, GetConfigResponse{
		AI:         h.config.AI,
		OpenAI:     h.config.OpenAI,
		Vision:     h.config.Vision,
		FOFA:       h.config.FOFA,
		ZoomEye:    h.config.ZoomEye,
		Quake:      h.config.Quake,
		Shodan:     h.config.Shodan,
		MCP:        h.config.MCP,
		Tools:      tools,
		Agent:      h.config.Agent,
		Hitl:       h.config.Hitl,
		Knowledge:  h.config.Knowledge,
		C2:         h.config.C2.Public(),
		Robots:     h.config.Robots,
		MultiAgent: multiPub,
	})
}

// GetToolsResponse 获取工具列表响应（分页）

// GetToolsResponse 获取工具列表响应（分页）
type GetToolsResponse struct {
	Tools        []ToolConfigInfo `json:"tools"`
	Total        int              `json:"total"`
	TotalEnabled int              `json:"total_enabled"` // 已启用的工具总数
	Page         int              `json:"page"`
	PageSize     int              `json:"page_size"`
	TotalPages   int              `json:"total_pages"`
}

// GetTools 获取工具列表（支持分页和搜索）

// GetTools 获取工具列表（支持分页和搜索）
func (h *ConfigHandler) GetTools(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")

	// 解析分页参数
	page := 1
	pageSize := 20
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	// 解析搜索参数
	searchTerm := c.Query("search")
	searchTermLower := ""
	if searchTerm != "" {
		searchTermLower = strings.ToLower(searchTerm)
	}

	// 解析状态筛选: tool_filter=on|off（角色弹窗等优先，避免与网关/代理对 enabled 的特殊处理冲突）
	// 兼容旧参数 enabled=true|false
	var filterEnabled *bool
	toolFilter := strings.TrimSpace(strings.ToLower(c.Query("tool_filter")))
	switch toolFilter {
	case "on", "1", "true", "enabled":
		v := true
		filterEnabled = &v
	case "off", "0", "false", "disabled":
		v := false
		filterEnabled = &v
	default:
		enabledFilter := strings.TrimSpace(c.Query("enabled"))
		if enabledFilter == "true" {
			v := true
			filterEnabled = &v
		} else if enabledFilter == "false" {
			v := false
			filterEnabled = &v
		}
	}

	includeExternal := true
	if v := strings.TrimSpace(strings.ToLower(c.Query("include_external"))); v == "0" || v == "false" || v == "no" {
		includeExternal = false
	}
	refreshExternal := false
	if v := strings.TrimSpace(strings.ToLower(c.Query("refresh_external"))); v == "1" || v == "true" || v == "yes" {
		refreshExternal = true
	}

	// 按外部 MCP 名称筛选（MCP 管理页左侧卡片 → 右侧工具列表联动）
	externalMCPFilter := strings.TrimSpace(c.Query("external_mcp"))

	// 快照配置后立即释放锁，避免外部 MCP 网络 IO 阻塞整个配置子系统
	h.mu.RLock()
	securityTools := append([]config.ToolConfig(nil), h.config.Security.Tools...)
	roles := h.config.Roles
	toolDescriptionMode := h.config.Security.ToolDescriptionMode
	mcpServer := h.mcpServer
	externalMCPMgr := h.externalMCPMgr
	h.mu.RUnlock()

	pickDesc := func(shortDesc, fullDesc string) string {
		return pickToolDescriptionWithMode(toolDescriptionMode, shortDesc, fullDesc)
	}

	// 解析角色参数，用于过滤工具并标注启用状态
	roleName := c.Query("role")
	var roleToolsSet map[string]bool // 角色配置的工具集合
	var roleUsesAllTools bool = true // 角色是否使用所有工具（默认角色）
	if roleName != "" && roleName != "默认" && roles != nil {
		if role, exists := roles[roleName]; exists && role.Enabled {
			if len(role.Tools) > 0 {
				// 角色配置了工具列表，只使用这些工具
				roleToolsSet = make(map[string]bool)
				for _, toolKey := range role.Tools {
					roleToolsSet[toolKey] = true
				}
				roleUsesAllTools = false
			}
		}
	}

	// 获取所有内部工具并应用搜索过滤
	configToolMap := make(map[string]bool)
	allTools := make([]ToolConfigInfo, 0, len(securityTools))
	for _, tool := range securityTools {
		configToolMap[tool.Name] = true
		toolInfo := ToolConfigInfo{
			Name:        tool.Name,
			Description: pickDesc(tool.ShortDescription, tool.Description),
			Enabled:     tool.Enabled,
			IsExternal:  false,
		}

		// 根据角色配置标注工具状态
		if roleName != "" {
			if roleUsesAllTools {
				// 角色使用所有工具，标注启用的工具为role_enabled=true
				if tool.Enabled {
					roleEnabled := true
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					roleEnabled := false
					toolInfo.RoleEnabled = &roleEnabled
				}
			} else {
				// 角色配置了工具列表，检查工具是否在列表中
				// 内部工具使用工具名称作为key
				if roleToolsSet[tool.Name] {
					roleEnabled := tool.Enabled // 工具必须在角色列表中且本身启用
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					// 不在角色列表中，标记为false
					roleEnabled := false
					toolInfo.RoleEnabled = &roleEnabled
				}
			}
		}

		// 如果有关键词，进行搜索过滤
		if searchTermLower != "" {
			nameLower := strings.ToLower(toolInfo.Name)
			descLower := strings.ToLower(toolInfo.Description)
			if !strings.Contains(nameLower, searchTermLower) && !strings.Contains(descLower, searchTermLower) {
				continue // 不匹配，跳过
			}
		}

		// 状态筛选
		if filterEnabled != nil && toolInfo.Enabled != *filterEnabled {
			continue
		}

		allTools = append(allTools, toolInfo)
	}

	// 从MCP服务器获取所有已注册的工具（包括直接注册的工具，如知识检索工具）
	if mcpServer != nil {
		mcpTools := mcpServer.GetAllTools()
		for _, mcpTool := range mcpTools {
			// 跳过已经在配置文件中的工具（避免重复）
			if configToolMap[mcpTool.Name] {
				continue
			}

			description := pickDesc(mcpTool.ShortDescription, mcpTool.Description)

			toolInfo := ToolConfigInfo{
				Name:        mcpTool.Name,
				Description: description,
				Enabled:     true,
				IsExternal:  false,
			}

			// 根据角色配置标注工具状态
			if roleName != "" {
				if roleUsesAllTools {
					// 角色使用所有工具，直接注册的工具默认启用
					roleEnabled := true
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					// 角色配置了工具列表，检查工具是否在列表中
					// 内部工具使用工具名称作为key
					if roleToolsSet[mcpTool.Name] {
						roleEnabled := true // 在角色列表中且工具本身启用
						toolInfo.RoleEnabled = &roleEnabled
					} else {
						// 不在角色列表中，标记为false
						roleEnabled := false
						toolInfo.RoleEnabled = &roleEnabled
					}
				}
			}

			// 如果有关键词，进行搜索过滤
			if searchTermLower != "" {
				nameLower := strings.ToLower(toolInfo.Name)
				descLower := strings.ToLower(toolInfo.Description)
				if !strings.Contains(nameLower, searchTermLower) && !strings.Contains(descLower, searchTermLower) {
					continue // 不匹配，跳过
				}
			}

			// 状态筛选
			if filterEnabled != nil && toolInfo.Enabled != *filterEnabled {
				continue
			}

			allTools = append(allTools, toolInfo)
		}
	}

	// 获取外部MCP工具（可走缓存，不持有 config 锁）
	if includeExternal && externalMCPMgr != nil {
		if refreshExternal {
			externalMCPMgr.InvalidateAllToolCaches()
		}
		ctx := context.Background()
		externalTools := h.getExternalMCPToolsWithManager(ctx, externalMCPMgr, pickDesc)

		// 应用搜索过滤和角色配置
		for _, toolInfo := range externalTools {
			// 搜索过滤
			if searchTermLower != "" {
				nameLower := strings.ToLower(toolInfo.Name)
				descLower := strings.ToLower(toolInfo.Description)
				if !strings.Contains(nameLower, searchTermLower) && !strings.Contains(descLower, searchTermLower) {
					continue // 不匹配，跳过
				}
			}

			// 根据角色配置标注工具状态
			if roleName != "" {
				if roleUsesAllTools {
					// 角色使用所有工具，标注启用的工具为role_enabled=true
					roleEnabled := toolInfo.Enabled
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					// 角色配置了工具列表，检查工具是否在列表中
					// 外部工具使用 "mcpName::toolName" 格式作为key
					externalToolKey := fmt.Sprintf("%s::%s", toolInfo.ExternalMCP, toolInfo.Name)
					if roleToolsSet[externalToolKey] {
						roleEnabled := toolInfo.Enabled // 工具必须在角色列表中且本身启用
						toolInfo.RoleEnabled = &roleEnabled
					} else {
						// 不在角色列表中，标记为false
						roleEnabled := false
						toolInfo.RoleEnabled = &roleEnabled
					}
				}
			}

			// 状态筛选
			if filterEnabled != nil && toolInfo.Enabled != *filterEnabled {
				continue
			}

			allTools = append(allTools, toolInfo)
		}
	}

	// 如果角色配置了工具列表，过滤工具（只保留列表中的工具，但保留其他工具并标记为禁用）
	// 注意：这里我们不直接过滤掉工具，而是保留所有工具，但通过 role_enabled 字段标注状态
	// 这样前端可以显示所有工具，并标注哪些工具在当前角色中可用

	if externalMCPFilter != "" {
		filtered := make([]ToolConfigInfo, 0)
		for _, tool := range allTools {
			if tool.IsExternal && tool.ExternalMCP == externalMCPFilter {
				filtered = append(filtered, tool)
			}
		}
		allTools = filtered
	}

	// 统一按名称排序后再分页，避免配置文件中顺序导致「全部」与「仅已启用」前几页看起来完全一致
	sort.SliceStable(allTools, func(i, j int) bool {
		key := func(t ToolConfigInfo) string {
			if t.IsExternal && t.ExternalMCP != "" {
				return strings.ToLower(t.ExternalMCP + "::" + t.Name)
			}
			return strings.ToLower(t.Name)
		}
		return key(allTools[i]) < key(allTools[j])
	})

	total := len(allTools)
	// 统计已启用的工具数（在角色中的启用工具数）
	totalEnabled := 0
	for _, tool := range allTools {
		if tool.RoleEnabled != nil && *tool.RoleEnabled {
			totalEnabled++
		} else if tool.RoleEnabled == nil && tool.Enabled {
			// 如果未指定角色，统计所有启用的工具
			totalEnabled++
		}
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	// 计算分页范围
	offset := (page - 1) * pageSize
	end := offset + pageSize
	if end > total {
		end = total
	}

	var tools []ToolConfigInfo
	if offset < total {
		tools = allTools[offset:end]
	} else {
		tools = []ToolConfigInfo{}
	}

	c.JSON(http.StatusOK, GetToolsResponse{
		Tools:        tools,
		Total:        total,
		TotalEnabled: totalEnabled,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
	})
}

// UpdateConfigRequest 更新配置请求

// ToolEnableStatus 工具启用状态
type ToolEnableStatus struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	IsExternal  bool   `json:"is_external,omitempty"`  // 是否为外部MCP工具
	ExternalMCP string `json:"external_mcp,omitempty"` // 外部MCP名称（如果是外部工具）
}

// UpdateConfig 更新配置

// getExternalMCPTools 获取外部MCP工具列表（公共方法）
func (h *ConfigHandler) getExternalMCPTools(ctx context.Context) []ToolConfigInfo {
	if h.externalMCPMgr == nil {
		return nil
	}
	return h.getExternalMCPToolsWithManager(ctx, h.externalMCPMgr, h.pickToolDescription)
}

// getExternalMCPToolsWithManager 获取外部 MCP 工具（不持有 config 锁，供 GetTools 等热路径使用）

// getExternalMCPToolsWithManager 获取外部 MCP 工具（不持有 config 锁，供 GetTools 等热路径使用）
func (h *ConfigHandler) getExternalMCPToolsWithManager(
	ctx context.Context,
	mgr *mcp.ExternalMCPManager,
	pickDesc func(shortDesc, fullDesc string) string,
) []ToolConfigInfo {
	var result []ToolConfigInfo
	if mgr == nil {
		return result
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	externalTools, err := mgr.GetAllTools(timeoutCtx)
	if err != nil {
		h.logger.Warn("获取外部MCP工具失败（可能连接断开），尝试返回缓存的工具",
			zap.Error(err),
			zap.String("hint", "如果外部MCP工具未显示，请检查连接状态或点击刷新按钮"),
		)
	}

	if len(externalTools) == 0 {
		return result
	}

	externalMCPConfigs := mgr.GetConfigs()

	for _, externalTool := range externalTools {
		mcpName, actualToolName := h.parseExternalToolName(externalTool.Name)
		if mcpName == "" || actualToolName == "" {
			continue
		}

		enabled := h.calculateExternalToolEnabledWithManager(mcpName, actualToolName, externalMCPConfigs, mgr)

		result = append(result, ToolConfigInfo{
			Name:        actualToolName,
			Description: pickDesc(externalTool.ShortDescription, externalTool.Description),
			Enabled:     enabled,
			IsExternal:  true,
			ExternalMCP: mcpName,
		})
	}

	return result
}

// parseExternalToolName 解析外部工具名称（格式：mcpName::toolName）

// parseExternalToolName 解析外部工具名称（格式：mcpName::toolName）
func (h *ConfigHandler) parseExternalToolName(fullName string) (mcpName, toolName string) {
	idx := strings.Index(fullName, "::")
	if idx > 0 {
		return fullName[:idx], fullName[idx+2:]
	}
	return "", ""
}

// calculateExternalToolEnabled 计算外部工具的启用状态

// calculateExternalToolEnabled 计算外部工具的启用状态
func (h *ConfigHandler) calculateExternalToolEnabled(mcpName, toolName string, configs map[string]config.ExternalMCPServerConfig) bool {
	return h.calculateExternalToolEnabledWithManager(mcpName, toolName, configs, h.externalMCPMgr)
}

func (h *ConfigHandler) calculateExternalToolEnabledWithManager(
	mcpName, toolName string,
	configs map[string]config.ExternalMCPServerConfig,
	mgr *mcp.ExternalMCPManager,
) bool {
	cfg, exists := configs[mcpName]
	if !exists {
		return false
	}

	if !cfg.ExternalMCPEnable {
		return false
	}

	if cfg.ToolEnabled != nil {
		if toolEnabled, exists := cfg.ToolEnabled[toolName]; exists && !toolEnabled {
			return false
		}
	}

	if mgr == nil {
		return false
	}
	client, exists := mgr.GetClient(mcpName)
	if !exists || !client.IsConnected() {
		return false
	}

	return true
}

// pickToolDescription 根据 security.tool_description_mode 选择 short 或 full 描述并限制长度。
// 调用方若已持有 h.mu 读锁，须直接读 mode 并调用 pickToolDescriptionWithMode，避免嵌套 RLock 死锁。

// pickToolDescription 根据 security.tool_description_mode 选择 short 或 full 描述并限制长度。
// 调用方若已持有 h.mu 读锁，须直接读 mode 并调用 pickToolDescriptionWithMode，避免嵌套 RLock 死锁。
func (h *ConfigHandler) pickToolDescription(shortDesc, fullDesc string) string {
	return pickToolDescriptionWithMode(h.config.Security.ToolDescriptionMode, shortDesc, fullDesc)
}

func pickToolDescriptionWithMode(mode, shortDesc, fullDesc string) string {
	useFull := strings.TrimSpace(strings.ToLower(mode)) == "full"
	description := shortDesc
	if useFull {
		description = fullDesc
	} else if description == "" {
		description = fullDesc
	}
	if len(description) > 10000 {
		description = description[:10000] + "..."
	}
	return description
}

// GetToolSchema 获取单个工具的 inputSchema（按需加载，避免列表接口返回大量 schema 数据）

// GetToolSchema 获取单个工具的 inputSchema（按需加载，避免列表接口返回大量 schema 数据）
func (h *ConfigHandler) GetToolSchema(c *gin.Context) {
	toolName := c.Param("name")
	if toolName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "工具名称不能为空"})
		return
	}

	externalMCP := c.Query("external_mcp")
	if externalMCP != "" {
		h.mu.RLock()
		externalMCPMgr := h.externalMCPMgr
		h.mu.RUnlock()

		if externalMCPMgr != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			externalTools, _ := externalMCPMgr.GetAllTools(ctx)
			fullName := externalMCP + "::" + toolName
			for _, t := range externalTools {
				if t.Name == fullName {
					c.JSON(http.StatusOK, gin.H{"input_schema": t.InputSchema})
					return
				}
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "外部工具未找到"})
		return
	}

	h.mu.RLock()
	securityTools := append([]config.ToolConfig(nil), h.config.Security.Tools...)
	mcpServer := h.mcpServer
	h.mu.RUnlock()

	for _, tool := range securityTools {
		if tool.Name == toolName {
			c.JSON(http.StatusOK, gin.H{"input_schema": buildInputSchemaFromParams(tool.Parameters)})
			return
		}
	}

	// MCP 注册工具（如知识检索）
	if mcpServer != nil {
		for _, mt := range mcpServer.GetAllTools() {
			if mt.Name == toolName {
				c.JSON(http.StatusOK, gin.H{"input_schema": mt.InputSchema})
				return
			}
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "工具未找到"})
}

// buildInputSchemaFromParams 从 YAML 工具的 ParameterConfig 构建 JSON Schema（用于前端展示）。
// 不依赖 MCP 服务器注册状态，所有工具（包括未启用的）都能返回参数定义。

// buildInputSchemaFromParams 从 YAML 工具的 ParameterConfig 构建 JSON Schema（用于前端展示）。
// 不依赖 MCP 服务器注册状态，所有工具（包括未启用的）都能返回参数定义。
func buildInputSchemaFromParams(params []config.ParameterConfig) map[string]interface{} {
	if len(params) == 0 {
		return nil
	}

	properties := make(map[string]interface{})
	required := make([]string, 0)

	for _, p := range params {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		prop := map[string]interface{}{
			"type":        convertParamType(p.Type),
			"description": p.Description,
		}
		if p.Default != nil {
			prop["default"] = p.Default
		}
		if len(p.Options) > 0 {
			prop["enum"] = p.Options
		}
		properties[name] = prop
		if p.Required {
			required = append(required, name)
		}
	}

	schema := map[string]interface{}{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func convertParamType(t string) string {
	switch strings.TrimSpace(strings.ToLower(t)) {
	case "int", "integer", "number":
		return "number"
	case "bool", "boolean":
		return "boolean"
	case "array", "list":
		return "array"
	default:
		return "string"
	}
}
