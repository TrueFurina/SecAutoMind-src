package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"secautomind-ai/internal/audit"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// loginRateLimiter 登录失败限流器（内存级，服务重启后重置）。
// 每用户 5 次失败内不限；超过 5 次后锁定 5 分钟。
type loginRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
}

type loginAttempt struct {
	failures int
	lockedAt time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{entries: make(map[string]*loginAttempt)}
}

const (
	maxLoginFailures = 5
	lockoutDuration  = 5 * time.Minute
)

// Check 检查用户是否被锁定。返回 (locked, remainingSeconds)。
func (l *loginRateLimiter) Check(username string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[username]
	if !ok || e.failures < maxLoginFailures {
		return false, 0
	}
	elapsed := time.Since(e.lockedAt)
	if elapsed >= lockoutDuration {
		// 锁定期已过，重置
		delete(l.entries, username)
		return false, 0
	}
	remaining := int((lockoutDuration - elapsed).Seconds())
	return true, remaining
}

// RecordFailure 记录一次登录失败。
func (l *loginRateLimiter) RecordFailure(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[username]
	if !ok {
		l.entries[username] = &loginAttempt{failures: 1}
		return
	}
	// 如果已过锁定期，重置计数
	if e.failures >= maxLoginFailures && time.Since(e.lockedAt) >= lockoutDuration {
		l.entries[username] = &loginAttempt{failures: 1}
		return
	}
	e.failures++
	if e.failures >= maxLoginFailures {
		e.lockedAt = time.Now()
	}
}

// Reset 成功登录后重置计数。
func (l *loginRateLimiter) Reset(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, username)
}

// AuthHandler handles authentication-related endpoints.
type AuthHandler struct {
	manager    *security.AuthManager
	config     *config.Config
	configPath string
	logger     *zap.Logger
	audit      *audit.Service
	// loginLimiter 登录失败限流（内存级，服务重启后重置）
	loginLimiter *loginRateLimiter
}

// SetAudit wires platform audit logging.
func (h *AuthHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(manager *security.AuthManager, cfg *config.Config, configPath string, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		manager:      manager,
		config:       cfg,
		configPath:   configPath,
		logger:       logger,
		loginLimiter: newLoginRateLimiter(),
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password" binding:"required"`
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// Login verifies password and returns a session token.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码不能为空"})
		return
	}

	username := strings.TrimSpace(req.Username)

	// 限流检查：5 次失败后锁定 5 分钟
	if locked, remaining := h.loginLimiter.Check(username); locked {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":           "登录失败次数过多，账号已临时锁定",
			"locked":          true,
			"retry_after_sec": remaining,
		})
		return
	}

	token, expiresAt, err := h.manager.Authenticate(req.Username, req.Password)
	if err != nil {
		h.loginLimiter.RecordFailure(username)
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{
				Level:    "warn",
				Category: "auth",
				Action:   "login",
				Result:   "failure",
				Message:  "登录失败：密码错误",
				Actor:    username,
			})
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}
	// 成功登录重置计数
	h.loginLimiter.Reset(username)
	session, _ := h.manager.ValidateToken(token)

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category:    "auth",
			Action:      "login",
			Result:      "success",
			SessionHint: audit.HintFromToken(token),
			Message:     "登录成功",
			Actor:       session.Username,
			Detail: map[string]interface{}{
				"expires_at": expiresAt.UTC().Format(time.RFC3339),
			},
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"token":               token,
		"expires_at":          expiresAt.UTC().Format(time.RFC3339),
		"session_duration_hr": h.manager.SessionDurationHours(),
		"user": gin.H{
			"id":           session.UserID,
			"username":     session.Username,
			"display_name": session.DisplayName,
		},
		"roles":             session.Roles,
		"permissions":       permissionKeys(session.Permissions),
		"permission_scopes": session.PermissionScopes,
		"scope":             session.Scope,
	})
}

// Logout revokes the current session token.
func (h *AuthHandler) Logout(c *gin.Context) {
	token := c.GetString(security.ContextAuthTokenKey)
	if token == "" {
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
			token = strings.TrimSpace(authHeader[7:])
		} else {
			token = strings.TrimSpace(authHeader)
		}
	}

	h.manager.RevokeToken(token)
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "auth",
			Action:   "logout",
			Result:   "success",
			Message:  "退出登录",
		})
	}
	c.JSON(http.StatusOK, gin.H{"message": "已退出登录"})
}

// ChangePassword updates the login password.
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数无效"})
		return
	}

	oldPassword := strings.TrimSpace(req.OldPassword)
	newPassword := strings.TrimSpace(req.NewPassword)

	if oldPassword == "" || newPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前密码和新密码均不能为空"})
		return
	}

	if len(newPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码长度至少需要 8 位"})
		return
	}

	if oldPassword == newPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码不能与旧密码相同"})
		return
	}

	session, _ := security.CurrentSession(c)
	if session.Username == "" {
		session.Username = "admin"
	}
	if !h.manager.CheckUserPassword(session.Username, oldPassword) {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{
				Level:    "warn",
				Category: "auth",
				Action:   "change_password",
				Result:   "failure",
				Message:  "修改密码失败：当前密码不正确",
			})
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前密码不正确"})
		return
	}

	if session.UserID == "" {
		session.UserID = "admin"
	}
	if err := h.manager.UpdateUserPassword(session.UserID, newPassword); err != nil {
		if h.logger != nil {
			h.logger.Error("更新用户密码失败", zap.Error(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户密码失败"})
		return
	}

	if h.logger != nil {
		h.logger.Info("登录密码已更新，所有会话已失效")
	}

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "auth",
			Action:   "change_password",
			Result:   "success",
			Message:  "登录密码已修改",
		})
	}

	c.JSON(http.StatusOK, gin.H{"message": "密码已更新，请使用新密码重新登录"})
}

// Validate returns the current session status.
func (h *AuthHandler) Validate(c *gin.Context) {
	token := c.GetString(security.ContextAuthTokenKey)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "会话无效"})
		return
	}

	session, ok := h.manager.ValidateToken(token)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "会话已过期"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      session.Token,
		"expires_at": session.ExpiresAt.UTC().Format(time.RFC3339),
		"user": gin.H{
			"id":           session.UserID,
			"username":     session.Username,
			"display_name": session.DisplayName,
		},
		"roles":             session.Roles,
		"permissions":       permissionKeys(session.Permissions),
		"permission_scopes": session.PermissionScopes,
		"scope":             session.Scope,
	})
}

func permissionKeys(perms map[string]bool) []string {
	keys := make([]string, 0, len(perms))
	for key, ok := range perms {
		if ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// initialPasswordFile 返回首启初始密码文件路径（与 app.go bootstrap 落盘路径一致）。
// 该文件存在 = 平台尚未完成"首次向导"（管理员还没设置专属密码）。
func (h *AuthHandler) initialPasswordFile() string {
	dbPath := "data/conversations.db"
	if h.config != nil && strings.TrimSpace(h.config.Database.Path) != "" {
		dbPath = h.config.Database.Path
	}
	return filepath.Join(filepath.Dir(dbPath), "admin_initial_password.txt")
}

// SetupStatus 首启向导状态：管理员是否已完成首次密码设置。
func (h *AuthHandler) SetupStatus(c *gin.Context) {
	_, err := os.Stat(h.initialPasswordFile())
	needsSetup := err == nil
	c.JSON(http.StatusOK, gin.H{
		"needs_setup": needsSetup,
		"hint":        "首次启动请先设置管理员专属密码",
	})
}

type setupCompleteRequest struct {
	InitialPassword string `json:"initialPassword"`
	NewPassword     string `json:"newPassword"`
}

// SetupComplete 完成首启向导：校验一次性初始密码 → 设置管理员专属密码 → 删除初始密码文件。
// 该接口仅在 needs_setup 阶段可用（无需登录，本地首启场景）。
func (h *AuthHandler) SetupComplete(c *gin.Context) {
	var req setupCompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数无效"})
		return
	}
	initial := strings.TrimSpace(req.InitialPassword)
	newPwd := strings.TrimSpace(req.NewPassword)
	if initial == "" || newPwd == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "初始密码和新密码均不能为空"})
		return
	}
	if len(newPwd) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码长度至少需要 8 位"})
		return
	}

	// 仅首启阶段允许（初始密码文件存在才可走向导）
	if _, err := os.Stat(h.initialPasswordFile()); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "平台已完成初始化，请直接登录"})
		return
	}

	// 校验一次性初始密码（admin 内置账号）
	if !h.manager.CheckUserPassword("admin", initial) {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{
				Level:    "warn",
				Category: "auth",
				Action:   "setup_complete",
				Result:   "failure",
				Message:  "首启向导：初始密码不正确",
				Actor:    "admin",
			})
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "初始密码不正确，请查看 data/admin_initial_password.txt"})
		return
	}

	// 更新为管理员专属密码
	if err := h.manager.UpdateUserPassword("admin", newPwd); err != nil {
		if h.logger != nil {
			h.logger.Error("首启向导设置密码失败", zap.Error(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "设置密码失败"})
		return
	}

	// 删除初始密码文件（一次性凭据使命完成）
	_ = os.Remove(h.initialPasswordFile())

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "auth",
			Action:   "setup_complete",
			Result:   "success",
			Message:  "首次初始化完成，管理员专属密码已设置",
			Actor:    "admin",
		})
	}

	c.JSON(http.StatusOK, gin.H{"message": "初始化完成，请使用新密码登录"})
}
