package database

import (
	"database/sql"
	"fmt"
	"time"
)

// 协同任务状态。注意「卡死退回」不是一个持久状态，而是
// status 回到 pending + return_count 递增 的事件，由总览层渲染为「卡点」。
const (
	CollabTaskStatusPending = "pending" // 待领
	CollabTaskStatusClaimed = "claimed" // 进行中
	CollabTaskStatusDone    = "done"    // 已完成
)

// 协同席位类型与状态
const (
	CollabSeatKindHuman = "human"
	CollabSeatKindAgent = "agent"

	CollabSeatStatusIdle    = "idle"
	CollabSeatStatusBusy    = "busy"
	CollabSeatStatusOffline = "offline"
)

// CollabSeatRow 协同席位数据库行
type CollabSeatRow struct {
	ID             string
	Kind           string
	DisplayName    string
	Username       sql.NullString
	RoleName       sql.NullString
	ConversationID sql.NullString
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// CollabTaskRow 协同任务池数据库行
type CollabTaskRow struct {
	ID                string
	Title             string
	Message           string
	Status            string
	AssigneeSeatID    sql.NullString
	ClaimToken        sql.NullString
	ClaimedAt         sql.NullTime
	WallClockDeadline sql.NullTime
	StartedAt         sql.NullTime
	CompletedAt       sql.NullTime
	Result            sql.NullString
	Error             sql.NullString
	ReturnCount       int
	ProjectID         sql.NullString
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ── 席位 ────────────────────────────────────────────────────────────

// CreateCollabSeat 创建席位
func (db *DB) CreateCollabSeat(s *CollabSeatRow) error {
	_, err := db.Exec(`
		INSERT INTO collab_seats
			(id, kind, display_name, username, role_name, conversation_id, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Kind, s.DisplayName, s.Username, s.RoleName, s.ConversationID, s.Status, s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("创建协同席位失败: %w", err)
	}
	return nil
}

// GetCollabSeat 按 ID 取席位
func (db *DB) GetCollabSeat(id string) (*CollabSeatRow, error) {
	row := db.QueryRow(`
		SELECT id, kind, display_name, username, role_name, conversation_id, status, created_at, updated_at
		FROM collab_seats WHERE id = ?`, id)
	s := &CollabSeatRow{}
	err := row.Scan(&s.ID, &s.Kind, &s.DisplayName, &s.Username, &s.RoleName,
		&s.ConversationID, &s.Status, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询协同席位失败: %w", err)
	}
	return s, nil
}

// ListCollabSeats 列出全部席位（演示「3 人 + N Agent 同时在线」用）
func (db *DB) ListCollabSeats() ([]*CollabSeatRow, error) {
	rows, err := db.Query(`
		SELECT id, kind, display_name, username, role_name, conversation_id, status, created_at, updated_at
		FROM collab_seats ORDER BY kind ASC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("列出协同席位失败: %w", err)
	}
	defer rows.Close()

	var out []*CollabSeatRow
	for rows.Next() {
		s := &CollabSeatRow{}
		if err := rows.Scan(&s.ID, &s.Kind, &s.DisplayName, &s.Username, &s.RoleName,
			&s.ConversationID, &s.Status, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描协同席位失败: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateCollabSeat 更新席位（展示名/角色/会话/状态）
func (db *DB) UpdateCollabSeat(s *CollabSeatRow) error {
	res, err := db.Exec(`
		UPDATE collab_seats
		   SET display_name = ?, role_name = ?, conversation_id = ?, status = ?, updated_at = ?
		 WHERE id = ?`,
		s.DisplayName, s.RoleName, s.ConversationID, s.Status, s.UpdatedAt, s.ID)
	if err != nil {
		return fmt.Errorf("更新协同席位失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteCollabSeat 删除席位
func (db *DB) DeleteCollabSeat(id string) error {
	_, err := db.Exec(`DELETE FROM collab_seats WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除协同席位失败: %w", err)
	}
	return nil
}

// ── 任务池 ──────────────────────────────────────────────────────────

// EnqueueCollabTask 任务入池（状态 pending）
func (db *DB) EnqueueCollabTask(t *CollabTaskRow) error {
	_, err := db.Exec(`
		INSERT INTO collab_tasks
			(id, title, message, status, assignee_seat_id, claim_token, claimed_at,
			 wall_clock_deadline, started_at, completed_at, result, error,
			 return_count, project_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, ?, ?, ?)`,
		t.ID, t.Title, t.Message, CollabTaskStatusPending, t.ProjectID, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("任务入池失败: %w", err)
	}
	return nil
}

const collabTaskColumns = `id, title, message, status, assignee_seat_id, claim_token,
	claimed_at, wall_clock_deadline, started_at, completed_at, result, error,
	return_count, project_id, created_at, updated_at`

func scanCollabTask(sc interface {
	Scan(dest ...interface{}) error
}) (*CollabTaskRow, error) {
	t := &CollabTaskRow{}
	err := sc.Scan(&t.ID, &t.Title, &t.Message, &t.Status, &t.AssigneeSeatID, &t.ClaimToken,
		&t.ClaimedAt, &t.WallClockDeadline, &t.StartedAt, &t.CompletedAt, &t.Result, &t.Error,
		&t.ReturnCount, &t.ProjectID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// GetCollabTask 按 ID 取任务
func (db *DB) GetCollabTask(id string) (*CollabTaskRow, error) {
	row := db.QueryRow(`SELECT `+collabTaskColumns+` FROM collab_tasks WHERE id = ?`, id)
	t, err := scanCollabTask(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询协同任务失败: %w", err)
	}
	return t, nil
}

// ListCollabTasks 列出任务；status 为空表示全部，seatID 非空表示只看该席位的任务。
// 排序即总览要求：**卡点（退池次数多）置顶**，其次进行中、待领、已完成，同档按创建时间。
func (db *DB) ListCollabTasks(status, seatID string) ([]*CollabTaskRow, error) {
	q := `SELECT ` + collabTaskColumns + ` FROM collab_tasks WHERE 1=1`
	args := []interface{}{}
	if status != "" {
		q += ` AND status = ?`
		args = append(args, status)
	}
	if seatID != "" {
		q += ` AND assignee_seat_id = ?`
		args = append(args, seatID)
	}
	q += ` ORDER BY return_count DESC,
	       CASE status WHEN 'claimed' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
	       created_at ASC`

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("列出协同任务失败: %w", err)
	}
	defer rows.Close()

	var out []*CollabTaskRow
	for rows.Next() {
		t, err := scanCollabTask(rows)
		if err != nil {
			return nil, fmt.Errorf("扫描协同任务失败: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ClaimCollabTask 原子领取。
//
// 并发安全**完全**依赖这条条件式 UPDATE：把「任务仍是 pending」作为 WHERE 条件，
// 靠 RowsAffected 判定归属。绝不做「先 SELECT 判断再 UPDATE」——那中间有窗口，
// 两人/两 Agent 会同时认为自己是领到的人（西湖论剑 stuck_loop 7410 次的同源问题）。
//
// 返回 claimed=true 表示本次调用抢到了该任务；false 表示已被别人领走或不存在。
func (db *DB) ClaimCollabTask(taskID, seatID, token string, now time.Time, deadline *time.Time) (bool, error) {
	res, err := db.Exec(`
		UPDATE collab_tasks
		   SET status = ?, assignee_seat_id = ?, claim_token = ?, claimed_at = ?,
		       wall_clock_deadline = ?, started_at = COALESCE(started_at, ?), updated_at = ?
		 WHERE id = ? AND status = ?`,
		CollabTaskStatusClaimed, seatID, token, now, deadline, now, now,
		taskID, CollabTaskStatusPending)
	if err != nil {
		return false, fmt.Errorf("原子领取失败: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("原子领取结果判定失败: %w", err)
	}
	return n == 1, nil
}

// CompleteCollabTask 完成任务。必须持对 claim_token：任务被回收后旧持有者晚到的回写会被拒绝。
func (db *DB) CompleteCollabTask(taskID, token, result string, now time.Time) (bool, error) {
	res, err := db.Exec(`
		UPDATE collab_tasks
		   SET status = ?, result = ?, error = '', completed_at = ?, updated_at = ?
		 WHERE id = ? AND status = ? AND claim_token = ?`,
		CollabTaskStatusDone, result, now, now, taskID, CollabTaskStatusClaimed, token)
	if err != nil {
		return false, fmt.Errorf("完成任务失败: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("完成结果判定失败: %w", err)
	}
	return n == 1, nil
}

// AbandonCollabTask 主动放弃：凭 token 退回池（return_count+1）
func (db *DB) AbandonCollabTask(taskID, token, reason string, now time.Time) (bool, error) {
	res, err := db.Exec(`
		UPDATE collab_tasks
		   SET status = ?, assignee_seat_id = NULL, claim_token = NULL, claimed_at = NULL,
		       wall_clock_deadline = NULL, error = ?, return_count = return_count + 1, updated_at = ?
		 WHERE id = ? AND status = ? AND claim_token = ?`,
		CollabTaskStatusPending, reason, now, taskID, CollabTaskStatusClaimed, token)
	if err != nil {
		return false, fmt.Errorf("放弃任务失败: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("放弃结果判定失败: %w", err)
	}
	return n == 1, nil
}

// ReturnStaleCollabTasks 卡死回收：把已过墙钟硬限的进行中任务退回池。
// 返回本次回收条数。不做 token 校验——这是系统级的超时裁决，不是某个持有者的回写。
func (db *DB) ReturnStaleCollabTasks(now time.Time) (int64, error) {
	res, err := db.Exec(`
		UPDATE collab_tasks
		   SET status = ?, assignee_seat_id = NULL, claim_token = NULL, claimed_at = NULL,
		       wall_clock_deadline = NULL, return_count = return_count + 1,
		       error = ?, updated_at = ?
		 WHERE status = ? AND wall_clock_deadline IS NOT NULL AND wall_clock_deadline <= ?`,
		CollabTaskStatusPending, "wall-clock timeout: 已自动退回池", now,
		CollabTaskStatusClaimed, now)
	if err != nil {
		return 0, fmt.Errorf("卡死回收失败: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("卡死回收结果判定失败: %w", err)
	}
	return n, nil
}

// RenewCollabTaskDeadline 心跳续期：正常跑的长任务延长墙钟，避免被 reaper 误杀。
func (db *DB) RenewCollabTaskDeadline(taskID, token string, deadline time.Time, now time.Time) (bool, error) {
	res, err := db.Exec(`
		UPDATE collab_tasks SET wall_clock_deadline = ?, updated_at = ?
		 WHERE id = ? AND status = ? AND claim_token = ?`,
		deadline, now, taskID, CollabTaskStatusClaimed, token)
	if err != nil {
		return false, fmt.Errorf("续期失败: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("续期结果判定失败: %w", err)
	}
	return n == 1, nil
}

// CountCollabTasksByStatus 按状态计数（总览汇总用）
func (db *DB) CountCollabTasksByStatus() (map[string]int, error) {
	rows, err := db.Query(`SELECT status, COUNT(*) FROM collab_tasks GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("统计协同任务失败: %w", err)
	}
	defer rows.Close()

	out := map[string]int{
		CollabTaskStatusPending: 0,
		CollabTaskStatusClaimed: 0,
		CollabTaskStatusDone:    0,
	}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, fmt.Errorf("扫描协同任务统计失败: %w", err)
		}
		out[st] = n
	}
	return out, rows.Err()
}
