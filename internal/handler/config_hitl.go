package handler

import (
	"strings"

	"secautomind-ai/internal/config"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func mergeHitlToolWhitelistSlice(existing, add []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(existing)+len(add))
	for _, list := range [][]string{existing, add} {
		for _, t := range list {
			n := strings.ToLower(strings.TrimSpace(t))
			if n == "" {
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

// SetHitlToolWhitelist 将全局免审批工具白名单整表写入 config.yaml（替换，非合并）。

// SetHitlToolWhitelist 将全局免审批工具白名单整表写入 config.yaml（替换，非合并）。
func (h *ConfigHandler) SetHitlToolWhitelist(tools []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.ToolWhitelist = mergeHitlToolWhitelistSlice(nil, tools)
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL 全局工具白名单已写入配置文件",
		zap.Int("count", len(h.config.Hitl.ToolWhitelist)),
	)
	return nil
}

// MergeHitlToolWhitelistIntoConfig 将会话侧栏提交的免审批工具名合并进内存配置并写入 config.yaml（与全局白名单去重规则一致：小写键、保留首次出现的原始大小写）。

// MergeHitlToolWhitelistIntoConfig 将会话侧栏提交的免审批工具名合并进内存配置并写入 config.yaml（与全局白名单去重规则一致：小写键、保留首次出现的原始大小写）。
func (h *ConfigHandler) MergeHitlToolWhitelistIntoConfig(add []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	merged := mergeHitlToolWhitelistSlice(h.config.Hitl.ToolWhitelist, add)
	h.config.Hitl.ToolWhitelist = merged
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL 全局工具白名单已合并写入配置文件",
		zap.Int("count", len(merged)),
	)
	return nil
}

func updateHitlConfig(doc *yaml.Node, cfg config.HitlConfig) {
	root := doc.Content[0]
	hitlNode := ensureMap(root, "hitl")
	auditModelNode := ensureMap(hitlNode, "audit_model")
	setStringInMap(auditModelNode, "provider", cfg.AuditModel.Provider)
	setStringInMap(auditModelNode, "base_url", cfg.AuditModel.BaseURL)
	setStringInMap(auditModelNode, "api_key", cfg.AuditModel.APIKey)
	setStringInMap(auditModelNode, "model", cfg.AuditModel.Model)
	// flow 样式 [a, b, c] 单行展示，工具多时比块序列省行数
	setFlowStringSliceInMap(hitlNode, "tool_whitelist", cfg.ToolWhitelist)
	setStringInMap(hitlNode, "default_mode", cfg.EffectiveDefaultMode())
	setStringInMap(hitlNode, "default_reviewer", cfg.EffectiveDefaultReviewer())
	setIntInMap(hitlNode, "default_timeout_seconds", cfg.EffectiveDefaultTimeoutSeconds())
	setIntInMap(hitlNode, "retention_days", cfg.RetentionDaysEffective())
	setStringInMap(hitlNode, "audit_agent_prompt", cfg.AuditAgentPrompt)
	setStringInMap(hitlNode, "audit_agent_prompt_review_edit", cfg.AuditAgentPromptReviewEdit)
}

// UpdateHitlDefaultConfig 更新全局默认人机协同配置并写入 config.yaml。

// UpdateHitlDefaultConfig 更新全局默认人机协同配置并写入 config.yaml。
func (h *ConfigHandler) UpdateHitlDefaultConfig(mode, reviewer string, timeoutSeconds int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.DefaultMode = config.HitlConfig{DefaultMode: mode}.EffectiveDefaultMode()
	h.config.Hitl.DefaultReviewer = config.HitlConfig{DefaultReviewer: reviewer}.EffectiveDefaultReviewer()
	if timeoutSeconds < 0 {
		timeoutSeconds = 0
	}
	h.config.Hitl.DefaultTimeoutSeconds = &timeoutSeconds
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL 全局默认配置已写入配置文件",
		zap.String("default_mode", h.config.Hitl.DefaultMode),
		zap.String("default_reviewer", h.config.Hitl.DefaultReviewer),
		zap.Int("default_timeout_seconds", timeoutSeconds),
	)
	return nil
}

// UpdateHitlDefaultReviewer 更新全局默认审批方并写入 config.yaml。

// UpdateHitlDefaultReviewer 更新全局默认审批方并写入 config.yaml。
func (h *ConfigHandler) UpdateHitlDefaultReviewer(reviewer string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.DefaultReviewer = config.HitlConfig{DefaultReviewer: reviewer}.EffectiveDefaultReviewer()
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL 全局默认审批方已写入配置文件", zap.String("default_reviewer", h.config.Hitl.DefaultReviewer))
	return nil
}

// UpdateHitlAuditAgentStrategy 更新审批/审查编辑两套审计 Agent 提示词并写入 config.yaml。

// UpdateHitlAuditAgentStrategy 更新审批/审查编辑两套审计 Agent 提示词并写入 config.yaml。
func (h *ConfigHandler) UpdateHitlAuditAgentStrategy(approvalPrompt, reviewEditPrompt string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.AuditAgentPrompt = strings.TrimSpace(approvalPrompt)
	h.config.Hitl.AuditAgentPromptReviewEdit = strings.TrimSpace(reviewEditPrompt)
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL 审计 Agent 提示词已写入配置文件")
	return nil
}
