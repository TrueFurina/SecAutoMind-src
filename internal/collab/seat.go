package collab

import (
	"fmt"
	"strings"
	"time"

	"secautomind-ai/internal/database"

	"database/sql"
)

// Seat 是协同作战中的一个「席位」——人席（队员）或 Agent 席（工作台）。
//
// 演示场景：「3 名队员 + N 个 Agent 同时在线」，各方从同一任务池领题，互不串扰。
type Seat struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	DisplayName    string    `json:"display_name"`
	Username       string    `json:"username,omitempty"`
	RoleName       string    `json:"role_name,omitempty"`
	ConversationID string    `json:"conversation_id,omitempty"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// CreateSeatRequest 创建席位入参。
type CreateSeatRequest struct {
	Kind           string `json:"kind"`
	DisplayName    string `json:"display_name"`
	Username       string `json:"username"`
	RoleName       string `json:"role_name"`
	ConversationID string `json:"conversation_id"`
	Status         string `json:"status"`
}

// UpdateSeatRequest 更新席位入参；nil 字段表示不改。
type UpdateSeatRequest struct {
	DisplayName    *string `json:"display_name"`
	RoleName       *string `json:"role_name"`
	ConversationID *string `json:"conversation_id"`
	Status         *string `json:"status"`
}

func validSeatKind(k string) bool {
	return k == database.CollabSeatKindHuman || k == database.CollabSeatKindAgent
}

func validSeatStatus(st string) bool {
	switch st {
	case database.CollabSeatStatusIdle, database.CollabSeatStatusBusy, database.CollabSeatStatusOffline:
		return true
	}
	return false
}

func seatFromRow(r *database.CollabSeatRow) *Seat {
	return &Seat{
		ID:             r.ID,
		Kind:           r.Kind,
		DisplayName:    r.DisplayName,
		Username:       strOf(r.Username),
		RoleName:       strOf(r.RoleName),
		ConversationID: strOf(r.ConversationID),
		Status:         r.Status,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}

// authorizeSeat 判定「调用方能否以该席位身份行事」（失败模式 F4）。
//
// 规则刻意保守：队员席只能由本人驱动；Agent 席由平台内工作台驱动；
// 系统内部调用（Username 空）与管理员不受此约束。
func (s *Service) authorizeSeat(seat *database.CollabSeatRow, actor Actor) error {
	if actor.IsAdmin || strings.TrimSpace(actor.Username) == "" {
		return nil
	}
	if seat.Kind == database.CollabSeatKindAgent {
		return nil
	}
	owner := strOf(seat.Username)
	if owner == "" {
		// 未绑定登录账号的开放席位：任何已认证用户可代管（对齐「临时席位」用法）。
		return nil
	}
	if owner != strings.TrimSpace(actor.Username) {
		return fmt.Errorf("%w: 席位 %s 归属 %s", ErrSeatForbidden, seat.ID, owner)
	}
	return nil
}

func (s *Service) getSeatOrErr(seatID string) (*database.CollabSeatRow, error) {
	seatID = strings.TrimSpace(seatID)
	if seatID == "" {
		return nil, fmt.Errorf("%w: seat_id 不能为空", ErrInvalidArgument)
	}
	seat, err := s.db.GetCollabSeat(seatID)
	if err != nil {
		return nil, err
	}
	if seat == nil {
		return nil, ErrSeatNotFound
	}
	return seat, nil
}

// CreateSeat 创建席位。kind 必须是 human/agent；status 缺省 idle。
func (s *Service) CreateSeat(actor Actor, req CreateSeatRequest) (*Seat, error) {
	kind := strings.TrimSpace(req.Kind)
	if !validSeatKind(kind) {
		return nil, fmt.Errorf("%w: kind 必须是 human 或 agent", ErrInvalidArgument)
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		return nil, fmt.Errorf("%w: display_name 不能为空", ErrInvalidArgument)
	}
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = database.CollabSeatStatusIdle
	}
	if !validSeatStatus(status) {
		return nil, fmt.Errorf("%w: status 必须是 idle/busy/offline", ErrInvalidArgument)
	}
	if kind == database.CollabSeatKindHuman && strings.TrimSpace(req.Username) == "" {
		return nil, fmt.Errorf("%w: human 席位必须绑定 username（越权判定的依据）", ErrInvalidArgument)
	}

	now := s.now()
	row := &database.CollabSeatRow{
		ID:             newID("seat"),
		Kind:           kind,
		DisplayName:    name,
		Username:       nullStr(req.Username),
		RoleName:       nullStr(req.RoleName),
		ConversationID: nullStr(req.ConversationID),
		Status:         status,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.db.CreateCollabSeat(row); err != nil {
		return nil, err
	}
	s.auditEvent(actor, ActionSeatCreate, "success", "创建协同席位", "collab_seat", row.ID,
		map[string]interface{}{"kind": kind, "display_name": name, "role_name": strOf(row.RoleName)})
	return seatFromRow(row), nil
}

// ListSeats 列出全部席位（「3 人 + N Agent 同时在线」的在线态展示）。
func (s *Service) ListSeats() ([]*Seat, error) {
	rows, err := s.db.ListCollabSeats()
	if err != nil {
		return nil, err
	}
	out := make([]*Seat, 0, len(rows))
	for _, r := range rows {
		out = append(out, seatFromRow(r))
	}
	return out, nil
}

// GetSeat 取单个席位。
func (s *Service) GetSeat(seatID string) (*Seat, error) {
	row, err := s.getSeatOrErr(seatID)
	if err != nil {
		return nil, err
	}
	return seatFromRow(row), nil
}

// UpdateSeat 更新席位（展示名/角色/会话/状态）。
func (s *Service) UpdateSeat(actor Actor, seatID string, req UpdateSeatRequest) (*Seat, error) {
	row, err := s.getSeatOrErr(seatID)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSeat(row, actor); err != nil {
		return nil, err
	}

	next := seatFromRow(row)
	if req.DisplayName != nil {
		v := strings.TrimSpace(*req.DisplayName)
		if v == "" {
			return nil, fmt.Errorf("%w: display_name 不能为空", ErrInvalidArgument)
		}
		next.DisplayName = v
	}
	if req.RoleName != nil {
		next.RoleName = strings.TrimSpace(*req.RoleName)
	}
	if req.ConversationID != nil {
		next.ConversationID = strings.TrimSpace(*req.ConversationID)
	}
	if req.Status != nil {
		v := strings.TrimSpace(*req.Status)
		if !validSeatStatus(v) {
			return nil, fmt.Errorf("%w: status 必须是 idle/busy/offline", ErrInvalidArgument)
		}
		next.Status = v
	}

	row.DisplayName = next.DisplayName
	row.RoleName = nullStr(next.RoleName)
	row.ConversationID = nullStr(next.ConversationID)
	row.Status = next.Status
	row.UpdatedAt = s.now()

	if err := s.db.UpdateCollabSeat(row); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSeatNotFound
		}
		return nil, err
	}
	s.auditEvent(actor, ActionSeatUpdate, "success", "更新协同席位", "collab_seat", row.ID,
		map[string]interface{}{"status": row.Status, "role_name": strOf(row.RoleName)})
	return seatFromRow(row), nil
}

// DeleteSeat 删除席位。进行中的任务不会被连带删除——它们仍留在池子里，
// 由 reaper 按墙钟回收，避免「删个席位把未完成结论一起抹掉」。
func (s *Service) DeleteSeat(actor Actor, seatID string) error {
	row, err := s.getSeatOrErr(seatID)
	if err != nil {
		return err
	}
	if err := s.authorizeSeat(row, actor); err != nil {
		return err
	}
	if err := s.db.DeleteCollabSeat(row.ID); err != nil {
		return err
	}
	s.auditEvent(actor, ActionSeatDelete, "success", "删除协同席位", "collab_seat", row.ID,
		map[string]interface{}{"kind": row.Kind, "display_name": row.DisplayName})
	return nil
}
