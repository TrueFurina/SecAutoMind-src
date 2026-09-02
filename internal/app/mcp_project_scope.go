package app

import (
	"context"
	"strings"

	"secautomind-ai/internal/database"
	"secautomind-ai/internal/mcp"
)

func mcpEffectiveProjectFilter(ctx context.Context, db *database.DB) string {
	if projectID := strings.TrimSpace(mcp.MCPProjectIDFromContext(ctx)); projectID != "" {
		return projectID
	}
	if conversationID := mcpAuthorizationConversationID(ctx); conversationID != "" {
		if db != nil {
			if projectID, err := db.GetConversationProjectID(conversationID); err == nil {
				if projectID = strings.TrimSpace(projectID); projectID != "" {
					return projectID
				}
			}
		}
		return database.ProjectFilterUnbound
	}
	return ""
}
