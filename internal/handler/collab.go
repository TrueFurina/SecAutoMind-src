package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"secautomind-ai/internal/collab"
	"secautomind-ai/internal/database"
	"secautomind-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// CollabHandler 暴露「3 队员 + N Agent」协同作战的 HTTP 接口。
//
// 职责边界：本层只做「身份解析 + 入参绑定 + 错误映射」，协同语义全在
// internal/collab.Service。这里不复制任何并发/超时判定逻辑。
type CollabHandler struct {
	svc    *collab.Service
	logger *zap.Logger
}

// NewCollabHandler 构造协同 handler；svc 为 nil 时所有路由返回 503。
func NewCollabHandler(svc *collab.Service, logger *zap.Logger) *CollabHandler {
	return &CollabHandler{svc: svc, logger: logger}
}

// actorFrom 从 gin 上下文解析调用方身份。
//
// IsAdmin 取「全局 scope」——platform 既有 RBAC 里 RBACScopeAll 即超级视角，
// 本层不另造角色判定。
func actorFrom(c *gin.Context) collab.Actor {
	session, _ := security.CurrentSession(c)
	return collab.Actor{
		Username: strings.TrimSpace(session.Username),
		IsAdmin:  session.Scope == database.RBACScopeAll,
	}
}

// writeCollabErr 把服务层哨兵错误映射为 HTTP 状态码。
func writeCollabErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, collab.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, collab.ErrSeatNotFound), errors.Is(err, collab.ErrTaskNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, collab.ErrSeatForbidden), errors.Is(err, collab.ErrNotAssignee):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, collab.ErrClaimTokenMismatch):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

func (h *CollabHandler) ready(c *gin.Context) bool {
	if h == nil || h.svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "协同服务未启用"})
		return false
	}
	return true
}

// ── 席位 ────────────────────────────────────────────────────────────

func (h *CollabHandler) ListSeats(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	seats, err := h.svc.ListSeats()
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"seats": seats})
}

func (h *CollabHandler) CreateSeat(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var req collab.CreateSeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	seat, err := h.svc.CreateSeat(actorFrom(c), req)
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"seat": seat})
}

func (h *CollabHandler) GetSeat(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	seat, err := h.svc.GetSeat(c.Param("id"))
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"seat": seat})
}

func (h *CollabHandler) UpdateSeat(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var req collab.UpdateSeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	seat, err := h.svc.UpdateSeat(actorFrom(c), c.Param("id"), req)
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"seat": seat})
}

func (h *CollabHandler) DeleteSeat(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	if err := h.svc.DeleteSeat(actorFrom(c), c.Param("id")); err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ── 任务池 ──────────────────────────────────────────────────────────

func (h *CollabHandler) ListTasks(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	tasks, err := h.svc.ListTasks(c.Query("status"), c.Query("seat_id"))
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func (h *CollabHandler) GetTask(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	task, err := h.svc.GetTask(c.Param("id"))
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": task})
}

func (h *CollabHandler) EnqueueTask(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var req collab.EnqueueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	task, err := h.svc.Enqueue(actorFrom(c), req)
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": task})
}

type collabSeatActionRequest struct {
	SeatID        string `json:"seat_id"`
	Token         string `json:"claim_token"`
	Result        string `json:"result"`
	Reason        string `json:"reason"`
	ExtendSeconds int    `json:"extend_seconds"`
}

// ClaimTask 原子领取。**领取失败（输掉竞争）返回 200 + claimed=false**，
// 这不是错误——并发下必然有人输，调用方应换下一题而非重试。
func (h *CollabHandler) ClaimTask(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var req collabSeatActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := h.svc.Claim(actorFrom(c), c.Param("id"), req.SeatID)
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"claimed": res.Claimed, "claim_token": res.ClaimToken,
		"wall_clock_deadline": res.WallClockDeadline, "task": res.Task})
}

func (h *CollabHandler) CompleteTask(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var req collabSeatActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.Complete(actorFrom(c), c.Param("id"), req.SeatID, req.Token, req.Result); err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *CollabHandler) AbandonTask(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var req collabSeatActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.Abandon(actorFrom(c), c.Param("id"), req.SeatID, req.Token, req.Reason); err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *CollabHandler) RenewTask(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var req collabSeatActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	deadline, err := h.svc.Renew(actorFrom(c), c.Param("id"), req.SeatID, req.Token,
		time.Duration(req.ExtendSeconds)*time.Second)
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "wall_clock_deadline": deadline})
}

// ── 总览与回收 ──────────────────────────────────────────────────────

func (h *CollabHandler) Overview(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	ov, err := h.svc.Overview()
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, ov)
}

// RunReaper 手动触发一次卡死回收。后台循环已按固定间隔自动跑，
// 此接口只为现场演示提供「即时可复现」的触发点。
func (h *CollabHandler) RunReaper(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	n, err := h.svc.ReapOnce()
	if err != nil {
		writeCollabErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"returned": n, "reaper_running": h.svc.ReaperRunning()})
}
