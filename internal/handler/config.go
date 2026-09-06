package handler

import (
	"fmt"
	"sync"

	"secautomind-ai/internal/audit"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/database"
	"secautomind-ai/internal/knowledge"
	"secautomind-ai/internal/mcp"
	"secautomind-ai/internal/security"

	"go.uber.org/zap"
)

// KnowledgeToolRegistrar 知识库工具注册器接口
type KnowledgeToolRegistrar func() error

// VulnerabilityToolRegistrar 漏洞工具注册器接口

// VulnerabilityToolRegistrar 漏洞工具注册器接口
type VulnerabilityToolRegistrar func() error

// WebshellToolRegistrar WebShell 工具注册器接口（ApplyConfig 时重新注册）

// WebshellToolRegistrar WebShell 工具注册器接口（ApplyConfig 时重新注册）
type WebshellToolRegistrar func() error

// SkillsToolRegistrar Skills工具注册器接口

// SkillsToolRegistrar Skills工具注册器接口
type SkillsToolRegistrar func() error

// BatchTaskToolRegistrar 批量任务 MCP 工具注册器（ApplyConfig 时重新注册）

// BatchTaskToolRegistrar 批量任务 MCP 工具注册器（ApplyConfig 时重新注册）
type BatchTaskToolRegistrar func() error

// C2ToolRegistrar C2 MCP 工具注册器（ApplyConfig 时 ClearTools 之后调用）

// C2ToolRegistrar C2 MCP 工具注册器（ApplyConfig 时 ClearTools 之后调用）
type C2ToolRegistrar func() error

// C2Runtime ApplyConfig 时按配置启停 C2 子系统（由 internal/app.App 实现）

// C2Runtime ApplyConfig 时按配置启停 C2 子系统（由 internal/app.App 实现）
type C2Runtime interface {
	ReconcileC2AfterConfigApply() error
}

// RetrieverUpdater 检索器更新接口

// RetrieverUpdater 检索器更新接口
type RetrieverUpdater interface {
	UpdateConfig(config *knowledge.RetrievalConfig)
}

// KnowledgeInitializer 知识库初始化器接口

// KnowledgeInitializer 知识库初始化器接口
type KnowledgeInitializer func() (*KnowledgeHandler, error)

// AppUpdater App更新接口（用于更新App中的知识库组件）

// AppUpdater App更新接口（用于更新App中的知识库组件）
type AppUpdater interface {
	UpdateKnowledgeComponents(handler *KnowledgeHandler, manager interface{}, retriever interface{}, indexer interface{})
}

// RobotRestarter 机器人连接重启器（用于配置应用后重启钉钉/飞书长连接）

// RobotRestarter 机器人连接重启器（用于配置应用后重启钉钉/飞书长连接）
type RobotRestarter interface {
	RestartRobotConnections()
}

// ConfigHandler 配置处理器

// ConfigHandler 配置处理器
type ConfigHandler struct {
	configPath                 string
	config                     *config.Config
	mcpServer                  *mcp.Server
	executor                   *security.Executor
	agent                      AgentUpdater               // Agent接口，用于更新Agent配置
	attackChainHandler         AttackChainUpdater         // 攻击链处理器接口，用于更新配置
	externalMCPMgr             *mcp.ExternalMCPManager    // 外部MCP管理器
	knowledgeToolRegistrar     KnowledgeToolRegistrar     // 知识库工具注册器（可选）
	vulnerabilityToolRegistrar VulnerabilityToolRegistrar // 漏洞工具注册器（可选）
	webshellToolRegistrar      WebshellToolRegistrar      // WebShell 工具注册器（可选）
	skillsToolRegistrar        SkillsToolRegistrar        // Skills工具注册器（可选）
	batchTaskToolRegistrar     BatchTaskToolRegistrar     // 批量任务 MCP 工具（可选）
	c2ToolRegistrar            C2ToolRegistrar            // C2 MCP 工具（可选）
	c2Runtime                  C2Runtime                  // C2 启停（可选）
	retrieverUpdater           RetrieverUpdater           // 检索器更新器（可选）
	knowledgeInitializer       KnowledgeInitializer       // 知识库初始化器（可选）
	appUpdater                 AppUpdater                 // App更新器（可选）
	robotRestarter             RobotRestarter             // 机器人连接重启器（可选），ApplyConfig 时重启钉钉/飞书
	audit                      *audit.Service
	db                         *database.DB
	logger                     *zap.Logger
	mu                         sync.RWMutex
	lastEmbeddingConfig        *config.EmbeddingConfig // 上一次的嵌入模型配置（用于检测变更）
}

func (h *ConfigHandler) SetDB(db *database.DB) {
	h.db = db
}

func (h *ConfigHandler) validateRobotServiceAccounts(robots config.RobotsConfig) error {
	if h.db == nil {
		return fmt.Errorf("RBAC 服务不可用，无法校验机器人服务账号")
	}
	for platform, userID := range robots.ServiceAccountUserIDs() {
		user, err := h.db.GetRBACUserByID(userID)
		if err != nil {
			return fmt.Errorf("robots.%s.auth.service_user_id 对应用户不存在", platform)
		}
		if !user.Enabled {
			return fmt.Errorf("robots.%s.auth.service_user_id 对应用户已禁用", platform)
		}
	}
	return nil
}

// AttackChainUpdater 攻击链处理器更新接口

// AttackChainUpdater 攻击链处理器更新接口
type AttackChainUpdater interface {
	UpdateConfig(cfg *config.OpenAIConfig)
}

// AgentUpdater Agent更新接口

// AgentUpdater Agent更新接口
type AgentUpdater interface {
	UpdateConfig(cfg *config.OpenAIConfig)
	UpdateMaxIterations(maxIterations int)
	UpdateToolDescriptionMode(mode string)
}

// NewConfigHandler 创建新的配置处理器

// NewConfigHandler 创建新的配置处理器
func NewConfigHandler(configPath string, cfg *config.Config, mcpServer *mcp.Server, executor *security.Executor, agent AgentUpdater, attackChainHandler AttackChainUpdater, externalMCPMgr *mcp.ExternalMCPManager, logger *zap.Logger) *ConfigHandler {
	// 保存初始的嵌入模型配置（如果知识库已启用）
	var lastEmbeddingConfig *config.EmbeddingConfig
	if cfg.Knowledge.Enabled {
		lastEmbeddingConfig = &config.EmbeddingConfig{
			Provider: cfg.Knowledge.Embedding.Provider,
			Model:    cfg.Knowledge.Embedding.Model,
			BaseURL:  cfg.Knowledge.Embedding.BaseURL,
			APIKey:   cfg.Knowledge.Embedding.APIKey,
		}
	}
	return &ConfigHandler{
		configPath:          configPath,
		config:              cfg,
		mcpServer:           mcpServer,
		executor:            executor,
		agent:               agent,
		attackChainHandler:  attackChainHandler,
		externalMCPMgr:      externalMCPMgr,
		logger:              logger,
		lastEmbeddingConfig: lastEmbeddingConfig,
	}
}

// SetKnowledgeToolRegistrar 设置知识库工具注册器

// SetKnowledgeToolRegistrar 设置知识库工具注册器
func (h *ConfigHandler) SetKnowledgeToolRegistrar(registrar KnowledgeToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.knowledgeToolRegistrar = registrar
}

// SetVulnerabilityToolRegistrar 设置漏洞工具注册器

// SetVulnerabilityToolRegistrar 设置漏洞工具注册器
func (h *ConfigHandler) SetVulnerabilityToolRegistrar(registrar VulnerabilityToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.vulnerabilityToolRegistrar = registrar
}

// SetWebshellToolRegistrar 设置 WebShell 工具注册器

// SetWebshellToolRegistrar 设置 WebShell 工具注册器
func (h *ConfigHandler) SetWebshellToolRegistrar(registrar WebshellToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.webshellToolRegistrar = registrar
}

// SetSkillsToolRegistrar 设置Skills工具注册器

// SetSkillsToolRegistrar 设置Skills工具注册器
func (h *ConfigHandler) SetSkillsToolRegistrar(registrar SkillsToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.skillsToolRegistrar = registrar
}

// SetBatchTaskToolRegistrar 设置批量任务 MCP 工具注册器

// SetBatchTaskToolRegistrar 设置批量任务 MCP 工具注册器
func (h *ConfigHandler) SetBatchTaskToolRegistrar(registrar BatchTaskToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.batchTaskToolRegistrar = registrar
}

// SetC2ToolRegistrar 设置 C2 MCP 工具注册器

// SetC2ToolRegistrar 设置 C2 MCP 工具注册器
func (h *ConfigHandler) SetC2ToolRegistrar(registrar C2ToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.c2ToolRegistrar = registrar
}

// SetC2Runtime 设置 C2 运行时（Apply 时启停）

// SetC2Runtime 设置 C2 运行时（Apply 时启停）
func (h *ConfigHandler) SetC2Runtime(rt C2Runtime) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.c2Runtime = rt
}

// SetRetrieverUpdater 设置检索器更新器

// SetRetrieverUpdater 设置检索器更新器
func (h *ConfigHandler) SetRetrieverUpdater(updater RetrieverUpdater) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.retrieverUpdater = updater
}

// SetKnowledgeInitializer 设置知识库初始化器

// SetKnowledgeInitializer 设置知识库初始化器
func (h *ConfigHandler) SetKnowledgeInitializer(initializer KnowledgeInitializer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.knowledgeInitializer = initializer
}

// SetAppUpdater 设置App更新器

// SetAppUpdater 设置App更新器
func (h *ConfigHandler) SetAppUpdater(updater AppUpdater) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.appUpdater = updater
}

// SetRobotRestarter 设置机器人连接重启器（ApplyConfig 时用于重启钉钉/飞书长连接）

// SetRobotRestarter 设置机器人连接重启器（ApplyConfig 时用于重启钉钉/飞书长连接）
func (h *ConfigHandler) SetRobotRestarter(restarter RobotRestarter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.robotRestarter = restarter
}

// SetAudit wires platform audit logging.

// SetAudit wires platform audit logging.
func (h *ConfigHandler) SetAudit(s *audit.Service) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.audit = s
}

// ApplyWechatRobotBinding 微信 iLink 扫码绑定成功后写入配置并重启机器人连接

// ApplyWechatRobotBinding 微信 iLink 扫码绑定成功后写入配置并重启机器人连接
func (h *ConfigHandler) ApplyWechatRobotBinding(wc config.RobotWechatConfig) error {
	h.mu.Lock()
	wc.Enabled = true
	h.config.Robots.Wechat = wc
	h.mu.Unlock()
	if err := h.saveConfig(); err != nil {
		return err
	}
	if h.robotRestarter != nil {
		h.robotRestarter.RestartRobotConnections()
	}
	h.logger.Info("微信机器人绑定已保存",
		zap.String("ilink_bot_id", wc.ILinkBotID),
		zap.Bool("enabled", wc.Enabled),
	)
	return nil
}

// GetConfigResponse 获取配置响应
