package app

import (
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/mcp"
	"secautomind-ai/internal/vision"

	"go.uber.org/zap"
)

func registerVisionTools(mcpServer *mcp.Server, cfg *config.Config, logger *zap.Logger) {
	vision.RegisterAnalyzeImageTool(mcpServer, cfg, logger)
}
