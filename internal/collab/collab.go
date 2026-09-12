// Package collab 实现「3 队员 + N Agent」协同作战的席位、任务池、卡死回收与总览。
//
// 设计定稿见 docs/zh-CN/collab-design.md。本包只承载 B2/C1–C5，与既有
// internal/handler/batch_task_manager.go（一人批量喂 N 题的队列语义）并存，互不改动。
//
// 两条不可动摇的不变式：
//
//   - 任务级并发安全**只**依赖 DB 的条件式 UPDATE（database.ClaimCollabTask），
//     绝不做「先 SELECT 判断再 UPDATE」——中间窗口会让两人/两 Agent 同时认为自己是领取者。
//   - 所有回写带 claim_token；任务被回收后旧持有者的晚到回写会被静默丢弃。
package collab

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	"secautomind-ai/internal/audit"
	"secautomind-ai/internal/database"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// 哨兵错误：handler 据此映射 HTTP 状态码，避免把内部细节漏给前端。
var (
	ErrInvalidArgument    = errors.New("collab: 参数非法")
	ErrSeatNotFound       = errors.New("collab: 席位不存在")
	ErrTaskNotFound       = errors.New("collab: 任务不存在")
	ErrTaskNotClaimable   = errors.New("collab: 任务已被领取或不存在")
	ErrClaimTokenMismatch = errors.New("collab: 领取令牌不匹配（任务可能已被回收或转手）")
	ErrSeatForbidden      = errors.New("collab: 席位无权执行该操作")
	ErrNotAssignee        = errors.New("collab: 只有任务当前领取者可执行该操作")
)

// 审计分类与动作。赛后可按 resource_id（任务/席位 ID）回放完整协同链。
const (
	auditCategory = "collab"

	ActionSeatCreate  = "seat_create"
	ActionSeatUpdate  = "seat_update"
	ActionSeatDelete  = "seat_delete"
	ActionTaskEnqueue = "task_enqueue"
	ActionTaskClaim   = "task_claim"
	ActionTaskReject  = "task_claim_rejected"
	ActionTaskDone    = "task_complete"
	ActionTaskAbandon = "task_abandon"
	ActionTaskRenew   = "task_renew"
	ActionTaskReap    = "task_reap"
)

// 默认参数。墙钟是「硬上限」，不是「预计耗时」——宁可宽一点也不要误杀正常长任务。
const (
	defaultWallClock      = 10 * time.Minute
	defaultReaperInterval = 15 * time.Second
)

// Actor 标识发起协同操作的调用方身份，用于席位越权判定（F4）。
//
// 本服务不自行解析平台角色：IsAdmin 由 HTTP 层按既有 RBAC 判定后传入
// （当前映射为持有 tasks:delete 权限）。Username 为空表示系统内部调用
// （reaper、Agent 工作台），此时不受席位归属约束。
type Actor struct {
	Username string
	IsAdmin  bool
}

// Options 装配参数。测试可注入 Now / ReaperInterval，避免真等墙钟。
type Options struct {
	DB             *database.DB
	Audit          *audit.Service
	Logger         *zap.Logger
	Now            func() time.Time
	WallClock      time.Duration
	ReaperInterval time.Duration
}

// Service 协同作战服务。零值不可用，必须经 New 构造。
type Service struct {
	db             *database.DB
	audit          *audit.Service
	logger         *zap.Logger
	now            func() time.Time
	wallClock      time.Duration
	reaperInterval time.Duration

	mu      sync.Mutex
	stopCh  chan struct{}
	doneCh  chan struct{}
	running bool
}

// New 构造协同服务。
func New(opts Options) *Service {
	s := &Service{
		db:             opts.DB,
		audit:          opts.Audit,
		logger:         opts.Logger,
		now:            opts.Now,
		wallClock:      opts.WallClock,
		reaperInterval: opts.ReaperInterval,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.wallClock <= 0 {
		s.wallClock = defaultWallClock
	}
	if s.reaperInterval <= 0 {
		s.reaperInterval = defaultReaperInterval
	}
	return s
}

// DB 暴露底层数据库句柄，供 handler 装配期做健康检查等只读用途。
func (s *Service) DB() *database.DB { return s.db }

// ── 内部工具 ────────────────────────────────────────────────────────

func newID(prefix string) string {
	return prefix + "_" + strings.ReplaceAll(uuid.New().String(), "-", "")
}

// nullStr 空串 → NULL，避免 collab_seats/conversation_id 等可选列落成空字符串
// （空串与 NULL 在「是否已绑定」判定上语义不同）。
func nullStr(v string) sql.NullString {
	v = strings.TrimSpace(v)
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: v, Valid: true}
}

func strOf(v sql.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.String
}

func timePtr(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
}

func (s *Service) auditEvent(actor Actor, action, result, message, resourceType, resourceID string, detail map[string]interface{}) {
	if s.audit == nil {
		return
	}
	name := strings.TrimSpace(actor.Username)
	if name == "" {
		name = "system"
	}
	level := "info"
	if result == "failure" {
		level = "warn"
	}
	s.audit.RecordSystem(audit.Entry{
		Level:        level,
		Category:     auditCategory,
		Action:       action,
		Result:       result,
		Actor:        name,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Message:      message,
		Detail:       detail,
	})
}

func (s *Service) warn(msg string, fields ...zap.Field) {
	if s.logger != nil {
		s.logger.Warn(msg, fields...)
	}
}
