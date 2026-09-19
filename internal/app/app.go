package app

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"secautomind-ai/internal/agent"
	"secautomind-ai/internal/audit"
	"secautomind-ai/internal/c2"
	"secautomind-ai/internal/collab"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/ctfplatform"
	"secautomind-ai/internal/database"
	"secautomind-ai/internal/handler"
	"secautomind-ai/internal/hitl"
	"secautomind-ai/internal/knowledge"
	"secautomind-ai/internal/logger"
	"secautomind-ai/internal/mcp"
	"secautomind-ai/internal/monitor"
	"secautomind-ai/internal/multiagent"
	"secautomind-ai/internal/security"
	"secautomind-ai/internal/skillpackage"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type App struct {
	config             *config.Config
	logger             *logger.Logger
	router             *gin.Engine
	mcpServer          *mcp.Server
	externalMCPMgr     *mcp.ExternalMCPManager
	agent              *agent.Agent
	executor           *security.Executor
	db                 *database.DB
	knowledgeDB        *database.DB // 知识库数据库连接（如果使用独立数据库）
	auth               *security.AuthManager
	knowledgeManager   *knowledge.Manager        // 知识库管理器（用于动态初始化）
	knowledgeRetriever *knowledge.Retriever      // 知识库检索器（用于动态初始化）
	knowledgeIndexer   *knowledge.Indexer        // 知识库索引器（用于动态初始化）
	knowledgeHandler   *handler.KnowledgeHandler // 知识库处理器（用于动态初始化）
	agentHandler       *handler.AgentHandler     // Agent处理器（用于更新知识库管理器）
	robotHandler       *handler.RobotHandler     // 机器人处理器（钉钉/飞书/企业微信等）
	robotMu            sync.Mutex                // 保护机器人长连接的 cancel
	dingCancel         context.CancelFunc        // 钉钉 Stream 取消函数，用于配置变更时重启
	larkCancel         context.CancelFunc        // 飞书长连接取消函数，用于配置变更时重启
	wechatCancel       context.CancelFunc        // 微信 iLink 长轮询取消函数
	telegramCancel     context.CancelFunc        // Telegram 长轮询取消函数
	slackCancel        context.CancelFunc        // Slack Socket Mode 取消函数
	discordCancel      context.CancelFunc        // Discord Gateway 取消函数
	qqCancel           context.CancelFunc        // QQ WebSocket 取消函数
	alertCancel        context.CancelFunc        // 漏洞提醒持久化投递 worker
	c2Manager          *c2.Manager               // C2 管理器（未启用 C2 时为 nil）
	c2Watchdog         *c2.SessionWatchdog       // C2 会话看门狗
	c2WatchdogCancel   context.CancelFunc        // 看门狗取消函数
	c2Handler          *handler.C2Handler        // C2 REST（与 Manager 生命周期同步）
	auditSvc           *audit.Service
	collabSvc          *collab.Service        // 「3 队员 + N Agent」协同作战服务
	collabHandler      *handler.CollabHandler // 协同作战 REST
	ctfPollCancel      context.CancelFunc     // CTF 平台轮询器取消函数（决赛自动解题；默认关闭）
}

// New 创建新应用

func New(cfg *config.Config, log *logger.Logger, configPath string) (*App, error) {
	if err := multiagent.InitADK(); err != nil {
		return nil, fmt.Errorf("初始化 Eino ADK: %w", err)
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// CORS中间件
	router.Use(corsMiddleware(cfg.Server.CORSAllowedOrigins))

	// 初始化数据库
	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "data/conversations.db"
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}

	db, err := database.NewDB(dbPath, log.Logger)
	if err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %w", err)
	}

	// 认证管理器（数据库初始化后挂载 RBAC）
	authManager := security.NewAuthManager(cfg.Auth.SessionDurationHours)

	// 启动时清理内联脚本缓存（超龄+超限）
	go security.CleanupInlineScriptCache(24*time.Hour, 200)
	if generatedPassword, err := authManager.AttachRBACStore(db); err != nil {
		return nil, fmt.Errorf("初始化RBAC失败: %w", err)
	} else if generatedPassword != "" {
		config.PrintBootstrapAdminPassword(generatedPassword)
		// 修复：GUI（windowsgui）模式下无控制台，stdout 的初始密码不可见——
		// 同时落盘到 data/ 目录，用户可打开文件查看（仅首次初始化生成时）。
		if pwFile := filepath.Join(filepath.Dir(dbPath), "admin_initial_password.txt"); pwFile != "" {
			content := "SecAutoMind 管理员初始凭据（仅首次启动生成，登录后请立即在「设置」中修改密码）\n\n" +
				"用户名: admin\n密码:   " + generatedPassword + "\n\n" +
				"删除本文件即可在下次重启时重新初始化（慎用）。\n"
			if wErr := os.WriteFile(pwFile, []byte(content), 0600); wErr != nil {
				log.Logger.Warn("写入初始密码提示文件失败", zap.Error(wErr))
			} else {
				fmt.Printf("初始密码已保存至: %s\n", pwFile)
			}
		}
	}
	for platform, userID := range cfg.Robots.ServiceAccountUserIDs() {
		user, userErr := db.GetRBACUserByID(userID)
		if userErr != nil || !user.Enabled {
			return nil, fmt.Errorf("robots.%s.auth.service_user_id 必须指向已启用的 RBAC 用户", platform)
		}
	}

	auditSvc := audit.NewService(db, cfg, log.Logger)
	audit.RegisterConversationCreateHook(auditSvc)
	auditSvc.PurgeExpired()
	audit.StartRetentionLoop(auditSvc, log.Logger)
	if err := db.PurgeWorkflowPackageLifecycle(time.Now().UTC()); err != nil {
		log.Logger.Warn("清理过期工作流包记录失败", zap.Error(err))
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := db.PurgeWorkflowPackageLifecycle(time.Now().UTC()); err != nil {
				log.Logger.Warn("清理过期工作流包记录失败", zap.Error(err))
			}
		}
	}()

	monitorRetention := monitor.NewService(db, cfg, log.Logger)
	monitorRetention.PurgeExpired()
	monitor.StartRetentionLoop(monitorRetention, log.Logger)

	if err := handler.NewHITLManager(db, log.Logger).EnsureSchema(); err != nil {
		log.Logger.Warn("初始化 HITL 表失败", zap.Error(err))
	}
	hitlRetention := hitl.NewService(db, cfg, log.Logger)
	hitlRetention.PurgeExpired()
	hitl.StartRetentionLoop(hitlRetention, log.Logger)

	// 创建MCP服务器（带数据库持久化）
	mcpServer := mcp.NewServerWithStorage(log.Logger, db)
	mcpServer.SetToolAuthorizer(mcpToolAuthorizer(db))
	mcpServer.ConfigureHTTPToolCallTimeoutFromAgentMinutes(cfg.Agent.ToolTimeoutMinutes)
	mcpServer.ConfigureToolWaitTimeoutSeconds(cfg.Agent.ToolWaitTimeoutSeconds)
	mcpServer.ConfigureToolResultMaxBytes(cfg.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
	mcpServer.ConfigureToolResultSpillRoot(cfg.MultiAgent.EinoMiddleware.ReductionRootDir)

	// 创建安全工具执行器
	executor := security.NewExecutor(&cfg.Security, mcpServer, log.Logger)
	executor.SetShellNoOutputTimeoutSeconds(cfg.Agent.ShellNoOutputTimeoutSeconds)
	executor.SetToolOutputMaxBytes(cfg.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
	executor.SetToolOutputSpillRoot(cfg.MultiAgent.EinoMiddleware.ReductionRootDir)

	// 注册工具
	executor.RegisterTools(mcpServer)

	// 注册 CTF 确定性求解器（实战赛解题：先确定性后 LLM，零 token 消耗）
	mcp.RegisterCTFSolvers(mcpServer)

	// 注册漏洞记录工具
	registerVulnerabilityTools(mcpServer, db, log.Logger)
	registerAssetTools(mcpServer, db, log.Logger)
	registerProjectFactTools(mcpServer, db, cfg, log.Logger)
	registerVisionTools(mcpServer, cfg, log.Logger)

	// 创建外部MCP管理器（使用与内部MCP服务器相同的存储）
	externalMCPMgr := mcp.NewExternalMCPManagerWithStorage(log.Logger, db)
	externalMCPMgr.SetToolAuthorizer(externalMCPToolAuthorizer())
	externalMCPMgr.ConfigureToolWaitTimeoutSeconds(cfg.Agent.ToolWaitTimeoutSeconds)
	externalMCPMgr.ConfigureToolResultMaxBytes(cfg.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
	externalMCPMgr.ConfigureToolResultSpillRoot(cfg.MultiAgent.EinoMiddleware.ReductionRootDir)
	externalMCPMgr.ConfigureResilience(mcp.ExternalMCPResilienceConfig{
		MaxConcurrentPerServer:  cfg.Agent.ExternalMCPMaxConcurrentPerServer,
		MaxConcurrentTotal:      cfg.Agent.ExternalMCPMaxConcurrentTotal,
		CircuitFailureThreshold: cfg.Agent.ExternalMCPCircuitFailureThreshold,
		CircuitCooldown:         time.Duration(cfg.Agent.ExternalMCPCircuitCooldownSeconds) * time.Second,
	})
	mcp.RegisterExecutionControlTools(mcpServer, externalMCPMgr)
	if cfg.ExternalMCP.Servers != nil {
		externalMCPMgr.LoadConfigs(&cfg.ExternalMCP)
		// 启动所有启用的外部MCP客户端
		externalMCPMgr.StartAllEnabled()
	}

	execReconciler := monitor.NewExecutionReconciler(db, mcpServer, externalMCPMgr, log.Logger)
	execReconciler.ReconcileOnStartup()
	monitor.StartStaleRunningReconcileLoop(execReconciler, log.Logger)

	// 创建Agent
	maxIterations := cfg.Agent.MaxIterations
	if maxIterations <= 0 {
		maxIterations = 30 // 默认值
	}
	agent := agent.NewAgent(&cfg.OpenAI, &cfg.Agent, mcpServer, externalMCPMgr, log.Logger, maxIterations)
	agent.UpdateToolDescriptionMode(cfg.Security.ToolDescriptionMode)

	// 初始化知识库模块（如果启用）
	var knowledgeManager *knowledge.Manager
	var knowledgeRetriever *knowledge.Retriever
	var knowledgeIndexer *knowledge.Indexer
	var knowledgeHandler *handler.KnowledgeHandler

	var knowledgeDBConn *database.DB
	log.Logger.Debug("检查知识库配置", zap.Bool("enabled", cfg.Knowledge.Enabled))
	if cfg.Knowledge.Enabled {
		// 确定知识库数据库路径
		knowledgeDBPath := cfg.Database.KnowledgeDBPath
		var knowledgeDB *sql.DB

		if knowledgeDBPath != "" {
			// 使用独立的知识库数据库
			// 确保目录存在
			if err := os.MkdirAll(filepath.Dir(knowledgeDBPath), 0755); err != nil {
				return nil, fmt.Errorf("创建知识库数据库目录失败: %w", err)
			}

			var err error
			knowledgeDBConn, err = database.NewKnowledgeDB(knowledgeDBPath, log.Logger)
			if err != nil {
				return nil, fmt.Errorf("初始化知识库数据库失败: %w", err)
			}
			knowledgeDB = knowledgeDBConn.DB
			log.Logger.Info("使用独立的知识库数据库", zap.String("path", knowledgeDBPath))
		} else {
			// 向后兼容：使用会话数据库
			knowledgeDB = db.DB
			log.Logger.Info("使用会话数据库存储知识库数据（建议配置knowledge_db_path以分离数据）")
		}

		// 创建知识库管理器
		knowledgeManager = knowledge.NewManager(knowledgeDB, cfg.Knowledge.BasePath, log.Logger)

		// 创建嵌入器
		// 使用OpenAI配置的API Key（如果知识库配置中没有指定）
		if cfg.Knowledge.Embedding.APIKey == "" {
			cfg.Knowledge.Embedding.APIKey = cfg.OpenAI.APIKey
		}
		if cfg.Knowledge.Embedding.BaseURL == "" {
			cfg.Knowledge.Embedding.BaseURL = cfg.OpenAI.BaseURL
		}

		embedder, err := knowledge.NewEmbedder(context.Background(), &cfg.Knowledge, &cfg.OpenAI, log.Logger)
		if err != nil {
			return nil, fmt.Errorf("初始化知识库嵌入器失败: %w", err)
		}

		// 创建检索器（Eino MultiQuery + 重排流水线）
		retrievalConfig := knowledge.RetrievalConfigFromYAML(cfg.Knowledge.Retrieval)
		knowledgeRetriever = knowledge.NewRetriever(knowledgeDB, embedder, retrievalConfig, log.Logger)
		if err := knowledge.WireRetrieverPipeline(context.Background(), knowledgeRetriever, &cfg.OpenAI); err != nil {
			return nil, fmt.Errorf("初始化知识库检索流水线失败: %w", err)
		}

		// 创建索引器（Eino Compose 链）
		knowledgeIndexer, err = knowledge.NewIndexer(context.Background(), knowledgeDB, embedder, log.Logger, &cfg.Knowledge)
		if err != nil {
			return nil, fmt.Errorf("初始化知识库索引器失败: %w", err)
		}

		// 注册知识检索工具到MCP服务器
		knowledge.RegisterKnowledgeTool(mcpServer, knowledgeRetriever, knowledgeManager, log.Logger)

		// 创建知识库API处理器
		knowledgeHandler = handler.NewKnowledgeHandler(knowledgeManager, knowledgeRetriever, knowledgeIndexer, db, log.Logger)
		knowledgeHandler.SetAudit(auditSvc)
		log.Logger.Info("知识库模块初始化完成", zap.Bool("handler_created", knowledgeHandler != nil))

		// 扫描知识库并建立索引（异步）
		go func() {
			itemsToIndex, err := knowledgeManager.ScanKnowledgeBase()
			if err != nil {
				log.Logger.Warn("扫描知识库失败", zap.Error(err))
				return
			}

			// 检查是否已有索引
			hasIndex, err := knowledgeIndexer.HasIndex()
			if err != nil {
				log.Logger.Warn("检查索引状态失败", zap.Error(err))
				return
			}

			if hasIndex {
				// 如果已有索引，只索引新添加或更新的项
				if len(itemsToIndex) > 0 {
					log.Logger.Info("检测到已有知识库索引，开始增量索引", zap.Int("count", len(itemsToIndex)))
					ctx := context.Background()
					consecutiveFailures := 0
					var firstFailureItemID string
					var firstFailureError error
					failedCount := 0

					for _, itemID := range itemsToIndex {
						if err := knowledgeIndexer.IndexItem(ctx, itemID); err != nil {
							failedCount++
							consecutiveFailures++

							if consecutiveFailures == 1 {
								firstFailureItemID = itemID
								firstFailureError = err
								log.Logger.Warn("索引知识项失败", zap.String("itemId", itemID), zap.Error(err))
							}

							// 如果连续失败2次，立即停止增量索引
							if consecutiveFailures >= 2 {
								log.Logger.Error("连续索引失败次数过多，立即停止增量索引",
									zap.Int("consecutiveFailures", consecutiveFailures),
									zap.Int("totalItems", len(itemsToIndex)),
									zap.String("firstFailureItemId", firstFailureItemID),
									zap.Error(firstFailureError),
								)
								break
							}
							continue
						}

						// 成功时重置连续失败计数
						if consecutiveFailures > 0 {
							consecutiveFailures = 0
							firstFailureItemID = ""
							firstFailureError = nil
						}
					}
					log.Logger.Info("增量索引完成", zap.Int("totalItems", len(itemsToIndex)), zap.Int("failedCount", failedCount))
				} else {
					log.Logger.Info("检测到已有知识库索引，没有需要索引的新项或更新项")
				}
				return
			}

			// 冷启动：仅为尚无向量的知识项构建索引（与 IndexMissing 语义一致）
			log.Logger.Info("未检测到知识库索引，开始自动构建索引")
			ctx := context.Background()
			if err := knowledgeIndexer.IndexMissing(ctx); err != nil {
				log.Logger.Warn("自动构建知识库索引失败", zap.Error(err))
			}
		}()
	}

	// 配置文件路径必须由入口传入（与 flag -config 一致）。勿再用 os.Args[1]，否则 ./secautomind-ai --https 会把 --https 当成路径。
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = "config.yaml"
	}

	skillsDir := skillpackage.SkillsRootFromConfig(cfg.SkillsDir, configPath)
	log.Logger.Debug("Skills 目录（Eino ADK skill 中间件 + Web 管理 API）", zap.String("skillsDir", skillsDir))
	configDir := filepath.Dir(configPath)
	plantaskRel := strings.TrimSpace(cfg.MultiAgent.EinoMiddleware.PlantaskRelDir)
	if plantaskRel == "" {
		plantaskRel = ".eino/plantask"
	}
	plantaskBase := filepath.Join(skillsDir, plantaskRel)
	// Match eino_adk_run_loop: checkpoint_dir is used as configured (relative to process CWD when not absolute).
	checkpointBase := strings.TrimSpace(cfg.MultiAgent.EinoMiddleware.CheckpointDir)
	reductionRoot := strings.TrimSpace(cfg.MultiAgent.EinoMiddleware.ReductionRootDir)
	workspaceRoot := strings.TrimSpace(cfg.Agent.WorkspaceRootDir)
	db.SetEinoConversationDirs(plantaskBase, checkpointBase, reductionRoot, workspaceRoot)
	agent.SetPromptBaseDir(configDir)

	agentsDir := cfg.AgentsDir
	if agentsDir == "" {
		agentsDir = "agents"
	}
	if !filepath.IsAbs(agentsDir) {
		agentsDir = filepath.Join(configDir, agentsDir)
	}
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		log.Logger.Warn("创建 agents 目录失败", zap.String("path", agentsDir), zap.Error(err))
	}
	markdownAgentsHandler := handler.NewMarkdownAgentsHandler(agentsDir)
	markdownAgentsHandler.SetAudit(auditSvc)
	log.Logger.Debug("多代理 Markdown 子 Agent 目录", zap.String("agentsDir", agentsDir))

	// 创建处理器
	agentHandler := handler.NewAgentHandler(agent, db, cfg, log.Logger)
	agentHandler.SetAudit(auditSvc)
	agentHandler.SetAgentsMarkdownDir(agentsDir)
	// 如果知识库已启用，设置知识库管理器到AgentHandler以便记录检索日志
	if knowledgeManager != nil {
		agentHandler.SetKnowledgeManager(knowledgeManager)
	}
	// CTF presolve 钩子：在 Agent 推理前先跑确定性预解层（0 token），命中则跳过 Agent。
	ctfPresolve := ctfplatform.NewPresolver(log.Logger)
	ctfAnalyzer := ctfplatform.NewTaskAnalyzer()
	// 接线平台层：构造真实 DasCTFPlatform（baseURL/token 仅从环境变量读取——
	// DASCTF_BASE_URL / DASCTF_TOKEN / CTF_AGENT_PLATFORM_TOKEN，绝不硬编码），
	// 取代原先传 nil 的占位，使「预解/推理 → 平台提交」闭环真正可用。
	ctfPlatform := ctfplatform.NewDasCTFPlatform("", "", log.Logger)
	ctfIntegrator := ctfplatform.NewPresolveAgentIntegrator(ctfPresolve, ctfAnalyzer, ctfPlatform, log.Logger)
	agentHandler.SetCTFPresolveIntegrator(ctfIntegrator)

	// ── CTF 平台轮询器（决赛自动解题+提交）──
	// 默认关闭；需环境变量 CTF_POLL_ENABLED=true 才启用。SubmitAfterSolve 默认 false，
	// 仅当 CTF_AUTOSOLVE_SUBMIT=true 才向真实平台自动提交，杜绝误提交。
	// 取消函数先存局部变量，待 App 实例构造后回填（与 alertCancel 同一模式）。
	var ctfPollCancel context.CancelFunc
	if strings.EqualFold(os.Getenv("CTF_POLL_ENABLED"), "true") {
		pollInterval := 30 * time.Second
		if v := strings.TrimSpace(os.Getenv("CTF_POLL_INTERVAL")); v != "" {
			if secs, e := strconv.Atoi(v); e == nil && secs > 0 {
				pollInterval = time.Duration(secs) * time.Second
			}
		}
		pc := ctfplatform.DefaultPollerConfig()
		pc.PollInterval = pollInterval
		pc.SubmitAfterSolve = strings.EqualFold(os.Getenv("CTF_AUTOSOLVE_SUBMIT"), "true")
		// 🔴 决赛关键链（09-17 补的生产缺口）：对 HasInstance 的题自动「起靶机 → 取地址 →
		//    并入题目描述」。此前 CreateInstance/GetAccess 从未被生产代码调用，需要靶机的题
		//    会因"没有可打的地址"整题 0 分。默认关；决赛按 runbook 设 CTF_AUTO_BUILD_ENV=true。
		pc.AutoBuildEnv = strings.EqualFold(os.Getenv("CTF_AUTO_BUILD_ENV"), "true")
		// 附件链（09-18 补）：对 HasAttachment 的题自动下载附件并并入描述，激活执行层求解器。
		// 默认关：DownloadAttachment 仍是存根（官方附件端点待确认），链路已由演练验证。
		pc.AutoFetchAttachment = strings.EqualFold(os.Getenv("CTF_AUTO_FETCH_ATTACHMENT"), "true")
		// 求解器：确定性预解层（0 token）。仅返回 flag 形态候选，避免误提交。
		solver := func(ctx context.Context, ch *ctfplatform.Challenge) ([]string, error) {
			res := ctfPresolve.Presolve(ctx, ch, nil)
			if !res.Solved {
				return nil, nil
			}
			return ctfplatform.FilterFlagCandidates(res.Flags), nil
		}
		poller := ctfplatform.NewPoller(ctfPlatform, solver, pc, log.Logger)
		poller.SetAdvisor(ctfPlatform) // 注入抗打击建议（连续 429 阶梯 / WAF 冷却跳过）
		pollCtx, pollCancel := context.WithCancel(context.Background())
		ctfPollCancel = pollCancel
		go func() {
			if err := poller.RunForever(pollCtx); err != nil && err != context.Canceled {
				log.Logger.Error("CTF 平台轮询器异常退出", zap.Error(err))
			}
		}()
		log.Logger.Info("CTF 平台轮询器已启用",
			zap.Duration("interval", pollInterval),
			zap.Bool("auto_submit", pc.SubmitAfterSolve))
	}
	monitorHandler := handler.NewMonitorHandler(mcpServer, executor, db, log.Logger)
	monitorHandler.SetAudit(auditSvc)
	monitorHandler.SetMonitorRetention(monitorRetention)
	monitorHandler.SetExternalMCPManager(externalMCPMgr) // 设置外部MCP管理器，以便获取外部MCP执行记录
	monitorHandler.SetTaskManager(agentHandler.TaskManager())
	monitorHandler.SetAgentHandler(agentHandler)
	notificationHandler := handler.NewNotificationHandler(db, agentHandler, log.Logger)
	authHandler := handler.NewAuthHandler(authManager, cfg, configPath, log.Logger)
	authHandler.SetAudit(auditSvc)
	attackChainHandler := handler.NewAttackChainHandler(db, &cfg.OpenAI, log.Logger)
	vulnerabilityHandler := handler.NewVulnerabilityHandler(db, log.Logger)
	assetHandler := handler.NewAssetHandler(db, log.Logger)
	projectHandler := handler.NewProjectHandler(db, log.Logger)
	rbacHandler := handler.NewRBACHandler(db, log.Logger)
	rbacHandler.SetAudit(auditSvc)
	rbacHandler.SetAuthManager(authManager)
	workflowHandler := handler.NewWorkflowHandler(db, log.Logger)
	workflowHandler.SetAudit(auditSvc)
	workflowHandler.SetRuntime(agent, cfg)
	vulnerabilityHandler.SetAudit(auditSvc)
	webshellHandler := handler.NewWebShellHandler(log.Logger, db)
	webshellHandler.SetAudit(auditSvc)
	chatUploadsHandler := handler.NewChatUploadsHandler(log.Logger, db)
	chatUploadsHandler.SetAudit(auditSvc)
	registerWebshellTools(mcpServer, db, webshellHandler, log.Logger)
	registerWebshellManagementTools(mcpServer, db, webshellHandler, log.Logger)
	configHandler := handler.NewConfigHandler(configPath, cfg, mcpServer, executor, agent, attackChainHandler, externalMCPMgr, log.Logger)
	configHandler.SetDB(db)
	configHandler.SetAudit(auditSvc)
	agentHandler.SetHitlToolWhitelistSaver(configHandler)
	agentHandler.SetHitlAuditStrategySaver(configHandler)
	agentHandler.SetHitlDefaultReviewerSaver(configHandler)
	externalMCPHandler := handler.NewExternalMCPHandler(externalMCPMgr, cfg, configPath, log.Logger)
	externalMCPHandler.SetAudit(auditSvc)
	roleHandler := handler.NewRoleHandler(cfg, configPath, log.Logger)
	roleHandler.SetAudit(auditSvc)
	skillsHandler := handler.NewSkillsHandler(cfg, configPath, log.Logger)
	skillsHandler.SetAudit(auditSvc)
	fofaHandler := handler.NewFofaHandler(cfg, log.Logger)
	terminalHandler := handler.NewTerminalHandler(log.Logger)
	if db != nil {
		skillsHandler.SetDB(db) // 设置数据库连接以便获取调用统计
	}

	// ============================================================================
	// 初始化 C2 模块（可按配置关闭，节省本机部署资源）
	// ============================================================================
	c2Manager, c2Watchdog, watchdogCancel := setupC2Runtime(cfg, db, agentHandler, log.Logger)
	if c2Manager != nil {
		registerC2Tools(mcpServer, c2Manager, log.Logger, cfg.Server.Port)
	}
	c2Handler := handler.NewC2Handler(c2Manager, log.Logger)
	c2Handler.SetAudit(auditSvc)

	// 创建OpenAPI处理器
	conversationHandler := handler.NewConversationHandler(db, log.Logger)
	conversationHandler.SetAudit(auditSvc)
	conversationHandler.SetTaskStopper(agentHandler)
	conversationHandler.SetTaskStateProvider(agentHandler)
	auditHandler := handler.NewAuditHandler(db, auditSvc, log.Logger)
	robotHandler := handler.NewRobotHandler(cfg, db, agentHandler, log.Logger)
	robotHandler.SetAudit(auditSvc)
	db.SetVulnerabilityCreatedHook(robotHandler.NotifyNewVulnerability)
	openAPIHandler := handler.NewOpenAPIHandler(db, log.Logger, conversationHandler, agentHandler)

	// 协同作战（B2/C1–C5）：席位 + 任务池 + 卡死回收 + 总览。
	// 与既有 batch-tasks 并存：前者是「3 人+N Agent 抢同一批题」，后者是「一人批量喂题」。
	collabSvc := collab.New(collab.Options{DB: db, Audit: auditSvc, Logger: log.Logger})
	collabHandler := handler.NewCollabHandler(collabSvc, log.Logger)

	// 创建 App 实例（部分字段稍后填充）
	app := &App{
		config:             cfg,
		logger:             log,
		router:             router,
		mcpServer:          mcpServer,
		externalMCPMgr:     externalMCPMgr,
		agent:              agent,
		executor:           executor,
		db:                 db,
		knowledgeDB:        knowledgeDBConn,
		auth:               authManager,
		knowledgeManager:   knowledgeManager,
		knowledgeRetriever: knowledgeRetriever,
		knowledgeIndexer:   knowledgeIndexer,
		knowledgeHandler:   knowledgeHandler,
		collabSvc:          collabSvc,
		collabHandler:      collabHandler,
		agentHandler:       agentHandler,
		robotHandler:       robotHandler,
		c2Manager:          c2Manager,
		c2Watchdog:         c2Watchdog,
		c2WatchdogCancel:   watchdogCancel,
		c2Handler:          c2Handler,
		auditSvc:           auditSvc,
	}
	// 飞书/钉钉长连接（无需公网），启用时在后台启动；后续前端应用配置时会通过 RestartRobotConnections 重启
	app.startRobotConnections()
	alertCtx, alertCancel := context.WithCancel(context.Background())
	app.alertCancel = alertCancel
	go robotHandler.RunVulnerabilityAlertWorker(alertCtx)

	// 回填 CTF 平台轮询器取消函数（仅当 CTF_POLL_ENABLED=true 时才非 nil），
	// 供 Shutdown 优雅停止轮询 goroutine。
	app.ctfPollCancel = ctfPollCancel

	// 设置漏洞工具注册器（内置工具，必须设置）
	vulnerabilityRegistrar := func() error {
		registerVulnerabilityTools(mcpServer, db, log.Logger)
		registerAssetTools(mcpServer, db, log.Logger)
		registerProjectFactTools(mcpServer, db, cfg, log.Logger)
		registerVisionTools(mcpServer, cfg, log.Logger)
		return nil
	}
	configHandler.SetVulnerabilityToolRegistrar(vulnerabilityRegistrar)

	// 设置 WebShell 工具注册器（ApplyConfig 时重新注册）
	webshellRegistrar := func() error {
		registerWebshellTools(mcpServer, db, webshellHandler, log.Logger)
		registerWebshellManagementTools(mcpServer, db, webshellHandler, log.Logger)
		return nil
	}
	configHandler.SetWebshellToolRegistrar(webshellRegistrar)

	// Skills 由 Eino ADK skill 中间件提供（多代理）；此处不注册 MCP 形态的技能工具
	configHandler.SetSkillsToolRegistrar(func() error { return nil })

	handler.RegisterBatchTaskMCPTools(mcpServer, agentHandler, log.Logger)
	batchTaskToolRegistrar := func() error {
		handler.RegisterBatchTaskMCPTools(mcpServer, agentHandler, log.Logger)
		return nil
	}
	configHandler.SetBatchTaskToolRegistrar(batchTaskToolRegistrar)

	// 设置知识库初始化器（用于动态初始化，需要在 App 创建后设置）
	configHandler.SetKnowledgeInitializer(func() (*handler.KnowledgeHandler, error) {
		knowledgeHandler, err := initializeKnowledge(cfg, db, knowledgeDBConn, mcpServer, agentHandler, app, log.Logger)
		if err != nil {
			return nil, err
		}

		// 动态初始化后，设置知识库工具注册器和检索器更新器
		// 这样后续 ApplyConfig 时就能重新注册工具了
		if app.knowledgeRetriever != nil && app.knowledgeManager != nil {
			// 创建闭包，捕获knowledgeRetriever和knowledgeManager的引用
			registrar := func() error {
				knowledge.RegisterKnowledgeTool(mcpServer, app.knowledgeRetriever, app.knowledgeManager, log.Logger)
				return nil
			}
			configHandler.SetKnowledgeToolRegistrar(registrar)
			// 设置检索器更新器，以便在ApplyConfig时更新检索器配置
			configHandler.SetRetrieverUpdater(app.knowledgeRetriever)
			log.Logger.Info("动态初始化后已设置知识库工具注册器和检索器更新器")
		}

		return knowledgeHandler, nil
	})

	// 如果知识库已启用，设置知识库工具注册器和检索器更新器
	if cfg.Knowledge.Enabled && knowledgeRetriever != nil && knowledgeManager != nil {
		// 创建闭包，捕获knowledgeRetriever和knowledgeManager的引用
		registrar := func() error {
			knowledge.RegisterKnowledgeTool(mcpServer, knowledgeRetriever, knowledgeManager, log.Logger)
			return nil
		}
		configHandler.SetKnowledgeToolRegistrar(registrar)
		// 设置检索器更新器，以便在ApplyConfig时更新检索器配置
		configHandler.SetRetrieverUpdater(knowledgeRetriever)
	}

	// 设置机器人连接重启器，前端应用配置后无需重启服务即可使钉钉/飞书/微信新配置生效
	configHandler.SetRobotRestarter(app)

	wechatRobotHandler := handler.NewWechatRobotHandler(cfg, configHandler, log.Logger)

	configHandler.SetC2Runtime(app)
	configHandler.SetC2ToolRegistrar(func() error {
		if app.config.C2.EnabledEffective() && app.c2Manager != nil {
			registerC2Tools(mcpServer, app.c2Manager, log.Logger, app.config.Server.Port)
		}
		return nil
	})

	// 设置路由（使用 App 实例以便动态获取 handler）
	setupRoutes(
		router,
		authHandler,
		agentHandler,
		monitorHandler,
		notificationHandler,
		conversationHandler,
		robotHandler,
		wechatRobotHandler,
		configHandler,
		externalMCPHandler,
		attackChainHandler,
		app, // 传递 App 实例以便动态获取 knowledgeHandler
		vulnerabilityHandler,
		assetHandler,
		projectHandler,
		workflowHandler,
		webshellHandler,
		chatUploadsHandler,
		roleHandler,
		skillsHandler,
		markdownAgentsHandler,
		fofaHandler,
		terminalHandler,
		app.c2Handler,
		auditHandler,
		auditSvc,
		rbacHandler,
		mcpServer,
		authManager,
		openAPIHandler,
		collabHandler,
	)

	// 协同任务池的卡死回收循环随应用启动；进程退出即终止。
	app.collabSvc.StartReaper()

	return app, nil

}

// mcpHandlerWithAuth 在鉴权通过后转发到 MCP 处理；若配置了 auth_header 则校验请求头，否则直接放行

func setupRoutes(
	router *gin.Engine,
	authHandler *handler.AuthHandler,
	agentHandler *handler.AgentHandler,
	monitorHandler *handler.MonitorHandler,
	notificationHandler *handler.NotificationHandler,
	conversationHandler *handler.ConversationHandler,
	robotHandler *handler.RobotHandler,
	wechatRobotHandler *handler.WechatRobotHandler,
	configHandler *handler.ConfigHandler,
	externalMCPHandler *handler.ExternalMCPHandler,
	attackChainHandler *handler.AttackChainHandler,
	app *App, // 传递 App 实例以便动态获取 knowledgeHandler
	vulnerabilityHandler *handler.VulnerabilityHandler,
	assetHandler *handler.AssetHandler,
	projectHandler *handler.ProjectHandler,
	workflowHandler *handler.WorkflowHandler,
	webshellHandler *handler.WebShellHandler,
	chatUploadsHandler *handler.ChatUploadsHandler,
	roleHandler *handler.RoleHandler,
	skillsHandler *handler.SkillsHandler,
	markdownAgentsHandler *handler.MarkdownAgentsHandler,
	fofaHandler *handler.FofaHandler,
	terminalHandler *handler.TerminalHandler,
	c2Handler *handler.C2Handler,
	auditHandler *handler.AuditHandler,
	auditSvc *audit.Service,
	rbacHandler *handler.RBACHandler,
	mcpServer *mcp.Server,
	authManager *security.AuthManager,
	openAPIHandler *handler.OpenAPIHandler,
	collabHandler *handler.CollabHandler,
) {
	// API路由
	api := router.Group("/api")

	// 认证相关路由
	authRoutes := api.Group("/auth")
	loginRL := security.NewRateLimiter(10, 1*time.Minute)
	{
		authRoutes.POST("/login", security.RateLimitMiddleware(loginRL), authHandler.Login)
		authRoutes.POST("/logout", security.AuthMiddleware(authManager), authHandler.Logout)
		authRoutes.POST("/change-password", security.AuthMiddleware(authManager), security.RequirePermission("auth:self"), authHandler.ChangePassword)
		authRoutes.GET("/validate", security.AuthMiddleware(authManager), authHandler.Validate)
		authRoutes.POST("/robot-binding-code", security.AuthMiddleware(authManager), security.RequirePermission("auth:self"), robotHandler.CreateRobotBindingCode)
		authRoutes.GET("/robot-bindings", security.AuthMiddleware(authManager), security.RequirePermission("auth:self"), robotHandler.ListMyRobotBindings)
		authRoutes.DELETE("/robot-bindings/:id", security.AuthMiddleware(authManager), security.RequirePermission("auth:self"), robotHandler.DeleteMyRobotBinding)
	}

	// 首启初始化向导（首次启动设置管理员专属密码；本地首启无需登录）
	setupRoutes := api.Group("/setup")
	{
		setupRoutes.GET("/status", authHandler.SetupStatus)
		setupRoutes.POST("/complete", security.RateLimitMiddleware(loginRL), authHandler.SetupComplete)
	}

	// 机器人回调（无需登录，供企业微信/钉钉/飞书服务器调用）
	// 添加速率限制：每个 IP 每分钟最多 60 次请求，防止滥用
	robotRL := security.NewRateLimiter(60, 1*time.Minute)
	robotGroup := api.Group("/robot")
	robotGroup.Use(security.RateLimitMiddleware(robotRL))
	{
		robotGroup.GET("/wecom", robotHandler.HandleWecomGET)
		robotGroup.POST("/wecom", robotHandler.HandleWecomPOST)
		robotGroup.POST("/dingtalk", robotHandler.HandleDingtalkPOST)
		robotGroup.POST("/lark", robotHandler.HandleLarkPOST)
	}

	protected := api.Group("")
	protected.Use(security.AuthMiddleware(authManager))
	protected.Use(security.RBACMiddlewareWithDenyHook(app.db, func(c *gin.Context, reason, permission string) {
		if auditSvc != nil {
			auditSvc.Record(c, audit.Entry{
				Level: "warn", Category: "rbac", Action: "access_denied", Result: "failure",
				Message: "RBAC 拒绝访问", ResourceType: "route", ResourceID: c.FullPath(),
				Detail: map[string]interface{}{"reason": reason, "permission": permission, "method": c.Request.Method},
			})
		}
	}))
	{
		protected.GET("/rbac/me", rbacHandler.Me)
		protected.GET("/rbac/metadata", rbacHandler.Metadata)
		protected.GET("/rbac/users", rbacHandler.ListUsers)
		protected.POST("/rbac/users", rbacHandler.CreateUser)
		protected.PUT("/rbac/users/:id", rbacHandler.UpdateUser)
		protected.DELETE("/rbac/users/:id", rbacHandler.DeleteUser)
		protected.GET("/rbac/roles", rbacHandler.ListRoles)
		protected.POST("/rbac/roles", rbacHandler.CreateRole)
		protected.PUT("/rbac/roles/:id", rbacHandler.UpdateRole)
		protected.DELETE("/rbac/roles/:id", rbacHandler.DeleteRole)
		protected.GET("/rbac/resource-assignments", rbacHandler.ListResourceAssignments)
		protected.GET("/rbac/resources", rbacHandler.ListAssignableResources)
		protected.POST("/rbac/resource-assignments", rbacHandler.AssignResource)
		protected.DELETE("/rbac/resource-assignments/:id", rbacHandler.DeleteResourceAssignment)

		// 机器人测试（需登录）：POST /api/robot/test，body: {"platform":"dingtalk","user_id":"test","text":"帮助"}，用于验证机器人逻辑
		protected.POST("/robot/test", robotHandler.HandleRobotTest)

		// 微信 iLink 扫码绑定（需登录）
		protected.POST("/robot/wechat/qrcode", wechatRobotHandler.HandleWechatQRCode)
		protected.GET("/robot/wechat/qrcode/status", wechatRobotHandler.HandleWechatQRCodeStatus)
		protected.POST("/robot/wechat/qrcode/verify", wechatRobotHandler.HandleWechatVerifyCode)
		protected.GET("/robot/wechat/status", wechatRobotHandler.HandleWechatStatus)

		// Eino ADK 单代理（ChatModelAgent + Runner；不依赖 multi_agent.enabled）
		protected.POST("/eino-agent", agentHandler.EinoSingleAgentLoop)
		protected.POST("/eino-agent/stream", agentHandler.EinoSingleAgentLoopStream)
		protected.GET("/hitl/pending", agentHandler.ListHITLPending)
		protected.GET("/hitl/logs", agentHandler.ListHITLLogs)
		protected.DELETE("/hitl/logs", agentHandler.DeleteHITLLogs)
		protected.GET("/hitl/logs/:id", agentHandler.GetHITLLog)
		protected.POST("/hitl/decision", agentHandler.DecideHITLInterrupt)
		protected.POST("/hitl/dismiss", agentHandler.DismissHITLInterrupt)
		protected.GET("/hitl/config/:conversationId", agentHandler.GetHITLConversationConfig)
		protected.PUT("/hitl/config", agentHandler.UpsertHITLConversationConfig)
		protected.GET("/hitl/tool-whitelist", agentHandler.GetHITLGlobalToolWhitelist)
		protected.PUT("/hitl/tool-whitelist", agentHandler.SetHITLGlobalToolWhitelist)
		protected.POST("/hitl/tool-whitelist", agentHandler.MergeHITLGlobalToolWhitelist)
		protected.GET("/hitl/default-config", agentHandler.GetHITLDefaultConfig)
		protected.PUT("/hitl/default-config", agentHandler.UpdateHITLDefaultConfig)
		protected.GET("/hitl/default-reviewer", agentHandler.GetHITLDefaultReviewer)
		protected.PUT("/hitl/default-reviewer", agentHandler.UpdateHITLDefaultReviewer)
		protected.GET("/hitl/audit-strategy", agentHandler.GetHITLAuditStrategy)
		protected.PUT("/hitl/audit-strategy", agentHandler.UpdateHITLAuditStrategy)
		// Agent Loop 取消与任务列表
		protected.POST("/agent-loop/cancel", agentHandler.CancelAgentLoop)
		protected.GET("/agent-loop/tasks", agentHandler.ListAgentTasks)
		protected.GET("/agent-loop/task-events", agentHandler.SubscribeAgentTaskEvents)
		protected.GET("/agent-loop/tasks/completed", agentHandler.ListCompletedTasks)

		// Eino DeepAgent 多代理（与单 Agent 并存，需 config.multi_agent.enabled）
		// 多代理路由常注册；是否可用由运行时 h.config.MultiAgent.Enabled 决定（应用配置后无需重启）
		protected.POST("/multi-agent", agentHandler.MultiAgentLoop)
		protected.POST("/multi-agent/stream", agentHandler.MultiAgentLoopStream)
		protected.GET("/multi-agent/markdown-agents", markdownAgentsHandler.ListMarkdownAgents)
		protected.GET("/multi-agent/markdown-agents/:filename", markdownAgentsHandler.GetMarkdownAgent)
		protected.POST("/multi-agent/markdown-agents", markdownAgentsHandler.CreateMarkdownAgent)
		protected.PUT("/multi-agent/markdown-agents/:filename", markdownAgentsHandler.UpdateMarkdownAgent)
		protected.DELETE("/multi-agent/markdown-agents/:filename", markdownAgentsHandler.DeleteMarkdownAgent)

		// 信息收集 - FOFA 查询（后端代理）
		protected.POST("/fofa/search", fofaHandler.Search)
		// 信息收集 - 自然语言解析为 FOFA 语法（需人工确认后再查询）
		protected.POST("/fofa/parse", fofaHandler.ParseNaturalLanguage)

		// 资产管理
		protected.GET("/assets", assetHandler.List)
		protected.GET("/assets/selection", assetHandler.Selection)
		protected.GET("/assets/stats", assetHandler.Stats)
		protected.POST("/assets/import", assetHandler.Import)
		protected.POST("/assets/scan-links", assetHandler.RecordScans)
		protected.PUT("/assets/bulk", assetHandler.BulkUpdate)
		protected.PUT("/assets/project-binding", assetHandler.UpdateProjectBinding)
		protected.POST("/assets/batch-delete", assetHandler.BatchDelete)
		protected.POST("/assets/merge", security.RequirePermission("asset:write"), assetHandler.Merge)
		protected.PUT("/assets/:id", assetHandler.Update)
		protected.DELETE("/assets/:id", assetHandler.Delete)

		// 批量任务管理
		protected.POST("/batch-tasks", agentHandler.CreateBatchQueue)
		protected.GET("/batch-tasks", agentHandler.ListBatchQueues)
		protected.GET("/batch-tasks/:queueId", agentHandler.GetBatchQueue)
		protected.POST("/batch-tasks/:queueId/start", agentHandler.StartBatchQueue)
		protected.POST("/batch-tasks/:queueId/rerun", agentHandler.RerunBatchQueue)
		protected.POST("/batch-tasks/:queueId/pause", agentHandler.PauseBatchQueue)
		protected.PUT("/batch-tasks/:queueId/metadata", agentHandler.UpdateBatchQueueMetadata)
		protected.PUT("/batch-tasks/:queueId/schedule", agentHandler.UpdateBatchQueueSchedule)
		protected.PUT("/batch-tasks/:queueId/schedule-enabled", agentHandler.SetBatchQueueScheduleEnabled)
		protected.DELETE("/batch-tasks/:queueId", agentHandler.DeleteBatchQueue)
		protected.PUT("/batch-tasks/:queueId/tasks/:taskId", agentHandler.UpdateBatchTask)
		protected.POST("/batch-tasks/:queueId/tasks/:taskId/run", agentHandler.RunSingleBatchTask)
		protected.POST("/batch-tasks/:queueId/tasks", agentHandler.AddBatchTask)
		protected.DELETE("/batch-tasks/:queueId/tasks/:taskId", agentHandler.DeleteBatchTask)

		// 协同作战（3 队员 + N Agent）：席位 / 任务池 / 总览。
		// 权限复用既有 tasks:* 命名空间，不新增权限项，避免 RBAC 目录漂移。
		protected.GET("/collab/overview", collabHandler.Overview)
		protected.GET("/collab/seats", collabHandler.ListSeats)
		protected.POST("/collab/seats", security.RequirePermission("tasks:write"), collabHandler.CreateSeat)
		protected.GET("/collab/seats/:id", collabHandler.GetSeat)
		protected.PUT("/collab/seats/:id", security.RequirePermission("tasks:write"), collabHandler.UpdateSeat)
		protected.DELETE("/collab/seats/:id", security.RequirePermission("tasks:delete"), collabHandler.DeleteSeat)
		protected.GET("/collab/tasks", collabHandler.ListTasks)
		protected.POST("/collab/tasks", security.RequirePermission("tasks:write"), collabHandler.EnqueueTask)
		protected.GET("/collab/tasks/:id", collabHandler.GetTask)
		protected.POST("/collab/tasks/:id/claim", security.RequirePermission("tasks:write"), collabHandler.ClaimTask)
		protected.POST("/collab/tasks/:id/complete", security.RequirePermission("tasks:write"), collabHandler.CompleteTask)
		protected.POST("/collab/tasks/:id/abandon", security.RequirePermission("tasks:write"), collabHandler.AbandonTask)
		protected.POST("/collab/tasks/:id/renew", security.RequirePermission("tasks:write"), collabHandler.RenewTask)
		protected.POST("/collab/reaper/run", security.RequirePermission("tasks:write"), collabHandler.RunReaper)

		// 对话历史
		protected.GET("/usage/tokens", conversationHandler.GetTokenUsageStats)
		protected.POST("/conversations", conversationHandler.CreateConversation)
		protected.GET("/conversations", conversationHandler.ListConversations)
		protected.GET("/conversations/:id", conversationHandler.GetConversation)
		protected.GET("/conversations/:id/token-usage", conversationHandler.GetConversationTokenUsageStats)
		protected.GET("/conversations/:id/plan-tasks", conversationHandler.GetConversationPlanTasks)
		protected.GET("/messages/:id/process-details", conversationHandler.GetMessageProcessDetails)
		protected.GET("/process-details/:id", conversationHandler.GetProcessDetail)
		protected.PUT("/conversations/:id", conversationHandler.UpdateConversation)
		protected.PUT("/conversations/:id/project", conversationHandler.SetConversationProject)
		protected.DELETE("/conversations/:id", conversationHandler.DeleteConversation)
		protected.POST("/conversations/:id/delete-turn", conversationHandler.DeleteConversationTurn)
		protected.PUT("/conversations/:id/pinned", conversationHandler.UpdateConversationPinned)

		// 监控
		protected.GET("/monitor", monitorHandler.Monitor)
		protected.GET("/monitor/execution/:id", monitorHandler.GetExecution)
		protected.POST("/monitor/execution/:id/cancel", monitorHandler.CancelExecution)
		protected.POST("/monitor/executions/names", monitorHandler.BatchGetToolNames)
		protected.DELETE("/monitor/execution/:id", monitorHandler.DeleteExecution)
		protected.DELETE("/monitor/executions", monitorHandler.DeleteExecutions)
		protected.GET("/monitor/stats", monitorHandler.GetStats)
		protected.GET("/monitor/calls-timeline", monitorHandler.GetCallsTimeline)
		protected.GET("/notifications/summary", notificationHandler.GetSummary)
		protected.POST("/notifications/read", notificationHandler.MarkRead)

		// 配置管理
		protected.GET("/config", configHandler.GetConfig)
		protected.GET("/config/tools", configHandler.GetTools)
		protected.GET("/config/tools/:name/schema", configHandler.GetToolSchema)
		protected.PUT("/config", configHandler.UpdateConfig)
		protected.POST("/config/apply", configHandler.ApplyConfig)
		protected.POST("/config/test-openai", configHandler.TestOpenAI)
		protected.POST("/config/test-vision", configHandler.TestVision)
		protected.POST("/config/list-models", configHandler.ListModels)

		// 系统设置 - 终端（执行命令，提高运维效率）
		protected.POST("/terminal/run", terminalHandler.RunCommand)
		protected.POST("/terminal/run/stream", terminalHandler.RunCommandStream)
		protected.GET("/terminal/ws", terminalHandler.RunCommandWS)

		// 平台审计日志
		protected.GET("/audit/meta", auditHandler.Meta)
		protected.GET("/audit/summary", auditHandler.Summary)
		protected.GET("/audit/logs", auditHandler.ListLogs)
		protected.GET("/audit/logs/export", auditHandler.ExportLogs)
		protected.GET("/audit/logs/:id", auditHandler.GetLog)

		// 外部MCP管理
		protected.GET("/external-mcp", externalMCPHandler.GetExternalMCPs)
		protected.GET("/external-mcp/stats", externalMCPHandler.GetExternalMCPStats)
		protected.GET("/external-mcp/:name", externalMCPHandler.GetExternalMCP)
		protected.PUT("/external-mcp/:name", externalMCPHandler.AddOrUpdateExternalMCP)
		protected.DELETE("/external-mcp/:name", externalMCPHandler.DeleteExternalMCP)
		protected.POST("/external-mcp/:name/start", externalMCPHandler.StartExternalMCP)
		protected.POST("/external-mcp/:name/stop", externalMCPHandler.StopExternalMCP)

		// 攻击链可视化
		protected.GET("/attack-chain/:conversationId", attackChainHandler.GetAttackChain)
		protected.POST("/attack-chain/:conversationId/regenerate", attackChainHandler.RegenerateAttackChain)

		// 知识库管理（始终注册路由，通过 App 实例动态获取 handler）
		knowledgeRoutes := protected.Group("/knowledge")
		{
			knowledgeRoutes.GET("/categories", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"categories": []string{},
						"enabled":    false,
						"message":    "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.GetCategories(c)
			})
			knowledgeRoutes.GET("/items", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"items":   []interface{}{},
						"enabled": false,
						"message": "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.GetItems(c)
			})
			knowledgeRoutes.GET("/items/:id", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled": false,
						"message": "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.GetItem(c)
			})
			knowledgeRoutes.POST("/items", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled": false,
						"error":   "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.CreateItem(c)
			})
			knowledgeRoutes.PUT("/items/:id", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled": false,
						"error":   "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.UpdateItem(c)
			})
			knowledgeRoutes.DELETE("/items/:id", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled": false,
						"error":   "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.DeleteItem(c)
			})
			knowledgeRoutes.GET("/index-status", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled":          false,
						"total_items":      0,
						"indexed_items":    0,
						"progress_percent": 0,
						"is_complete":      false,
						"message":          "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.GetIndexStatus(c)
			})
			knowledgeRoutes.POST("/index", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled": false,
						"error":   "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.StartIndex(c)
			})
			knowledgeRoutes.POST("/scan", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled": false,
						"error":   "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.ScanKnowledgeBase(c)
			})
			knowledgeRoutes.GET("/retrieval-logs", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"logs":    []interface{}{},
						"enabled": false,
						"message": "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.GetRetrievalLogs(c)
			})
			knowledgeRoutes.DELETE("/retrieval-logs/:id", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled": false,
						"error":   "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.DeleteRetrievalLog(c)
			})
			knowledgeRoutes.POST("/search", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"results": []interface{}{},
						"enabled": false,
						"message": "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.Search(c)
			})
			knowledgeRoutes.GET("/stats", func(c *gin.Context) {
				if app.knowledgeHandler == nil {
					c.JSON(http.StatusOK, gin.H{
						"enabled":          false,
						"total_categories": 0,
						"total_items":      0,
						"message":          "知识库功能未启用，请前往系统设置启用知识检索功能",
					})
					return
				}
				app.knowledgeHandler.GetStats(c)
			})
		}

		// 漏洞管理
		protected.GET("/vulnerabilities", vulnerabilityHandler.ListVulnerabilities)
		protected.GET("/vulnerabilities/export", vulnerabilityHandler.ExportVulnerabilities)
		protected.DELETE("/vulnerabilities/batch", vulnerabilityHandler.BatchDeleteVulnerabilities)
		protected.GET("/vulnerabilities/filter-options", vulnerabilityHandler.GetVulnerabilityFilterOptions)
		protected.GET("/vulnerabilities/stats", vulnerabilityHandler.GetVulnerabilityStats)
		protected.GET("/vulnerability-alerts/subscription", vulnerabilityHandler.GetMyAlertSubscription)
		protected.PUT("/vulnerability-alerts/subscription", vulnerabilityHandler.UpdateMyAlertSubscription)
		protected.GET("/vulnerabilities/:id", vulnerabilityHandler.GetVulnerability)
		protected.POST("/vulnerabilities", vulnerabilityHandler.CreateVulnerability)
		protected.PUT("/vulnerabilities/:id", vulnerabilityHandler.UpdateVulnerability)
		protected.DELETE("/vulnerabilities/:id", vulnerabilityHandler.DeleteVulnerability)

		// 项目管理与事实黑板
		protected.GET("/projects/dashboard-summary", projectHandler.GetDashboardSummary)
		protected.GET("/projects", projectHandler.ListProjects)
		protected.POST("/projects", projectHandler.CreateProject)
		protected.GET("/projects/:id/stats", projectHandler.GetProjectStats)
		protected.GET("/projects/:id/conversations", projectHandler.ListProjectConversations)
		protected.GET("/projects/:id", projectHandler.GetProject)
		protected.PUT("/projects/:id", projectHandler.UpdateProject)
		protected.DELETE("/projects/:id", projectHandler.DeleteProject)
		protected.GET("/projects/:id/fact-graph", projectHandler.GetFactGraph)
		protected.GET("/projects/:id/fact-edges", projectHandler.ListFactEdges)
		protected.POST("/projects/:id/fact-edges", projectHandler.CreateFactEdge)
		protected.DELETE("/projects/:id/fact-edges/:edgeId", projectHandler.DeleteFactEdge)
		protected.POST("/projects/:id/promote-attack-chain/:conversationId", projectHandler.PromoteAttackChain)
		protected.GET("/projects/:id/facts", projectHandler.ListFacts)
		protected.POST("/projects/:id/facts", projectHandler.CreateFact)
		protected.PUT("/projects/:id/facts/:factId", projectHandler.UpdateFact)
		protected.DELETE("/projects/:id/facts/:factId", projectHandler.DeleteFact)
		protected.POST("/projects/:id/facts/deprecate", projectHandler.DeprecateFact)
		protected.POST("/projects/:id/facts/restore", projectHandler.RestoreFact)

		// WebShell 管理（代理执行 + 连接配置存 SQLite）
		protected.GET("/webshell/connections", webshellHandler.ListConnections)
		protected.POST("/webshell/connections", webshellHandler.CreateConnection)
		protected.GET("/webshell/connections/:id/ai-history", webshellHandler.GetAIHistory)
		protected.GET("/webshell/connections/:id/ai-conversations", webshellHandler.ListAIConversations)
		protected.GET("/webshell/connections/:id/state", webshellHandler.GetConnectionState)
		protected.PUT("/webshell/connections/:id", webshellHandler.UpdateConnection)
		protected.PUT("/webshell/connections/:id/state", webshellHandler.SaveConnectionState)
		protected.DELETE("/webshell/connections/:id", webshellHandler.DeleteConnection)
		protected.POST("/webshell/exec", webshellHandler.Exec)
		protected.POST("/webshell/file", webshellHandler.FileOp)

		// C2 管理（未启用时返回 503，避免 Handler 空指针）
		c2Routes := protected.Group("/c2")
		c2Routes.Use(func(c *gin.Context) {
			if app.c2Manager == nil {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"error":   "c2_disabled",
					"message": "C2 功能已在系统设置中关闭",
					"enabled": false,
				})
				return
			}
			c.Next()
		})
		c2Routes.GET("/listeners", c2Handler.ListListeners)
		c2Routes.POST("/listeners", c2Handler.CreateListener)
		c2Routes.GET("/listeners/:id", c2Handler.GetListener)
		c2Routes.PUT("/listeners/:id", c2Handler.UpdateListener)
		c2Routes.DELETE("/listeners/:id", c2Handler.DeleteListener)
		c2Routes.POST("/listeners/:id/start", c2Handler.StartListener)
		c2Routes.POST("/listeners/:id/stop", c2Handler.StopListener)
		c2Routes.GET("/sessions", c2Handler.ListSessions)
		c2Routes.DELETE("/sessions", c2Handler.DeleteSessions)
		c2Routes.GET("/sessions/:id", c2Handler.GetSession)
		c2Routes.DELETE("/sessions/:id", c2Handler.DeleteSession)
		c2Routes.PUT("/sessions/:id/sleep", c2Handler.SetSessionSleep)
		c2Routes.PUT("/sessions/:id/note", c2Handler.SetSessionNote)
		c2Routes.GET("/tasks", c2Handler.ListTasks)
		c2Routes.DELETE("/tasks", c2Handler.DeleteTasks)
		c2Routes.GET("/tasks/:id", c2Handler.GetTask)
		c2Routes.POST("/tasks", c2Handler.CreateTask)
		c2Routes.POST("/tasks/:id/cancel", c2Handler.CancelTask)
		c2Routes.GET("/tasks/:id/wait", c2Handler.WaitTask)
		c2Routes.POST("/sessions/:id/tasks", c2Handler.CreateTask)
		c2Routes.POST("/payloads/oneliner", c2Handler.PayloadOneliner)
		c2Routes.POST("/payloads/build", c2Handler.PayloadBuild)
		c2Routes.GET("/payloads/:id/download", c2Handler.PayloadDownload)
		c2Routes.GET("/events", c2Handler.ListEvents)
		c2Routes.DELETE("/events", c2Handler.DeleteEvents)
		c2Routes.GET("/events/stream", c2Handler.EventStream)
		c2Routes.POST("/files/upload", c2Handler.UploadFileForImplant)
		c2Routes.GET("/files", c2Handler.ListFiles)
		c2Routes.GET("/tasks/:id/result-file", c2Handler.DownloadResultFile)
		c2Routes.GET("/profiles", c2Handler.ListProfiles)
		c2Routes.GET("/profiles/:id", c2Handler.GetProfile)
		c2Routes.POST("/profiles", c2Handler.CreateProfile)
		c2Routes.PUT("/profiles/:id", c2Handler.UpdateProfile)
		c2Routes.DELETE("/profiles/:id", c2Handler.DeleteProfile)

		// 对话附件（chat_uploads）管理
		protected.GET("/chat-uploads", chatUploadsHandler.List)
		protected.GET("/chat-uploads/export", chatUploadsHandler.Export)
		protected.GET("/chat-uploads/download", chatUploadsHandler.Download)
		protected.GET("/chat-uploads/path", chatUploadsHandler.ResolvePath)
		protected.GET("/chat-uploads/content", chatUploadsHandler.GetContent)
		protected.POST("/chat-uploads", chatUploadsHandler.Upload)
		protected.POST("/chat-uploads/mkdir", chatUploadsHandler.Mkdir)
		protected.DELETE("/chat-uploads", chatUploadsHandler.Delete)
		protected.PUT("/chat-uploads/rename", chatUploadsHandler.Rename)
		protected.PUT("/chat-uploads/content", chatUploadsHandler.PutContent)

		// 角色管理
		protected.GET("/roles", roleHandler.GetRoles)
		protected.GET("/roles/:name", roleHandler.GetRole)
		protected.POST("/roles", roleHandler.CreateRole)
		protected.PUT("/roles/:name", roleHandler.UpdateRole)
		protected.DELETE("/roles/:name", roleHandler.DeleteRole)

		// 工作流定义（图结构固定，业务字段保存在 graph_json 中）
		protected.GET("/workflows/runs/pending", workflowHandler.ListPendingRuns)
		protected.GET("/workflows/runs/:runId/replay", workflowHandler.ReplayRun)
		protected.GET("/workflows/runs/:runId", workflowHandler.GetRun)
		protected.POST("/workflows/runs/:runId/resume", workflowHandler.ResumeRun)
		protected.POST("/workflows/validate", workflowHandler.Validate)
		protected.POST("/workflows/dry-run", workflowHandler.DryRun)
		protected.POST("/workflows/generate-draft", workflowHandler.GenerateDraft)
		protected.GET("/workflows/:id/package", workflowHandler.ExportPackage)
		protected.POST("/workflow-package-inspections", workflowHandler.CreatePackageInspection)
		protected.GET("/workflow-package-inspections/:inspectionId", workflowHandler.GetPackageInspection)
		protected.POST("/workflow-package-imports", workflowHandler.ApplyPackageImport)
		protected.GET("/workflow-package-imports/:importId", workflowHandler.GetPackageImport)
		protected.GET("/workflows", workflowHandler.List)
		protected.GET("/workflows/:id", workflowHandler.Get)
		protected.POST("/workflows", workflowHandler.Create)
		protected.PUT("/workflows/:id", workflowHandler.Update)
		protected.DELETE("/workflows/:id", workflowHandler.Delete)

		// Skills管理（具体路径需注册在 /skills/:name 之前）
		protected.GET("/skills", skillsHandler.GetSkills)
		protected.GET("/skills/stats", skillsHandler.GetSkillStats)
		protected.DELETE("/skills/stats", skillsHandler.ClearSkillStats)
		protected.GET("/skills/:name/files", skillsHandler.ListSkillPackageFiles)
		protected.GET("/skills/:name/file", skillsHandler.GetSkillPackageFile)
		protected.PUT("/skills/:name/file", skillsHandler.PutSkillPackageFile)
		protected.GET("/skills/:name/bound-roles", skillsHandler.GetSkillBoundRoles)
		protected.POST("/skills", skillsHandler.CreateSkill)
		protected.PUT("/skills/:name", skillsHandler.UpdateSkill)
		protected.DELETE("/skills/:name", skillsHandler.DeleteSkill)
		protected.DELETE("/skills/:name/stats", skillsHandler.ClearSkillStatsByName)
		protected.GET("/skills/:name", skillsHandler.GetSkill)

		// MCP端点
		protected.POST("/mcp", func(c *gin.Context) {
			mcpServer.HandleHTTP(c.Writer, c.Request)
		})

		// OpenAPI结果聚合端点（可选，用于获取对话的完整结果）
		protected.GET("/conversations/:id/results", openAPIHandler.GetConversationResults)
	}

	// OpenAPI规范（需要认证，避免暴露API结构信息）
	protected.GET("/openapi/spec", openAPIHandler.GetOpenAPISpec)

	// API文档页面（公开访问，但需要登录后才能使用API）
	router.GET("/api-docs", func(c *gin.Context) {
		c.HTML(http.StatusOK, "api-docs.html", nil)
	})

	// 静态文件（自 v2 起从嵌入二进制的前端资源服务，单文件分发、任意目录双击即用）
	router.StaticFS("/static", http.FS(webStaticSub()))
	router.SetHTMLTemplate(template.Must(template.ParseFS(webTemplatesSub(), "*.html")))

	// 前端页面
	router.GET("/", func(c *gin.Context) {
		version := app.config.Version
		if version == "" {
			version = "v1.0.0"
		}
		c.HTML(http.StatusOK, "index.html", gin.H{"Version": version})
	})
}

// registerWebshellTools 注册 WebShell 相关 MCP 工具，供 AI 助手在指定连接上执行命令与文件操作
