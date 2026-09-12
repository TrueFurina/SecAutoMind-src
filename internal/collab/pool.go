package collab

import (
	"fmt"
	"strings"
	"time"

	"secautomind-ai/internal/database"
)

// Task 是对外暴露的任务视图（数据库行 → JSON 友好结构）。
//
// ReturnCount > 0 即「卡点」：被退池过，总览里置顶展示（C3）。
type Task struct {
	ID                string     `json:"id"`
	Title             string     `json:"title"`
	Message           string     `json:"message"`
	Status            string     `json:"status"`
	AssigneeSeatID    string     `json:"assignee_seat_id,omitempty"`
	ClaimedAt         *time.Time `json:"claimed_at,omitempty"`
	WallClockDeadline *time.Time `json:"wall_clock_deadline,omitempty"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	Result            string     `json:"result,omitempty"`
	Error             string     `json:"error,omitempty"`
	ReturnCount       int        `json:"return_count"`
	ProjectID         string     `json:"project_id,omitempty"`
	ElapsedSeconds    float64    `json:"elapsed_seconds"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// EnqueueRequest 任务入池入参。
type EnqueueRequest struct {
	Title     string `json:"title"`
	Message   string `json:"message"`
	ProjectID string `json:"project_id"`
}

// ClaimResult 领取结果。
//
// Claimed=false 且 err=nil 表示**输掉了并发竞争**（任务已被别人领走）——这是正常结果，
// 调用方应换下一题，而不是当成故障重试。
type ClaimResult struct {
	Claimed           bool       `json:"claimed"`
	TaskID            string     `json:"task_id"`
	ClaimToken        string     `json:"claim_token,omitempty"`
	WallClockDeadline *time.Time `json:"wall_clock_deadline,omitempty"`
	Task              *Task      `json:"task,omitempty"`
}

func (s *Service) taskView(t *database.CollabTaskRow) *Task {
	v := &Task{
		ID:                t.ID,
		Title:             t.Title,
		Message:           t.Message,
		Status:            t.Status,
		AssigneeSeatID:    strOf(t.AssigneeSeatID),
		ClaimedAt:         timePtr(t.ClaimedAt),
		WallClockDeadline: timePtr(t.WallClockDeadline),
		StartedAt:         timePtr(t.StartedAt),
		CompletedAt:       timePtr(t.CompletedAt),
		Result:            strOf(t.Result),
		Error:             strOf(t.Error),
		ReturnCount:       t.ReturnCount,
		ProjectID:         strOf(t.ProjectID),
		CreatedAt:         t.CreatedAt,
		UpdatedAt:         t.UpdatedAt,
	}
	v.ElapsedSeconds = elapsedSeconds(v, s.now())
	return v
}

func (s *Service) taskViews(rows []*database.CollabTaskRow) []*Task {
	now := s.now()
	out := make([]*Task, 0, len(rows))
	for _, r := range rows {
		v := &Task{
			ID:                r.ID,
			Title:             r.Title,
			Message:           r.Message,
			Status:            r.Status,
			AssigneeSeatID:    strOf(r.AssigneeSeatID),
			ClaimedAt:         timePtr(r.ClaimedAt),
			WallClockDeadline: timePtr(r.WallClockDeadline),
			StartedAt:         timePtr(r.StartedAt),
			CompletedAt:       timePtr(r.CompletedAt),
			Result:            strOf(r.Result),
			Error:             strOf(r.Error),
			ReturnCount:       r.ReturnCount,
			ProjectID:         strOf(r.ProjectID),
			CreatedAt:         r.CreatedAt,
			UpdatedAt:         r.UpdatedAt,
		}
		v.ElapsedSeconds = elapsedSeconds(v, now)
		out = append(out, v)
	}
	return out
}

// elapsedSeconds 耗时口径：已完成取「完成-领取」，进行中取「现在-领取」，
// 未领取或无领取时间则为 0。负值钳到 0（时钟抖动/注入时钟不该产生负耗时）。
func elapsedSeconds(t *Task, now time.Time) float64 {
	if t.ClaimedAt == nil {
		return 0
	}
	end := now
	if t.CompletedAt != nil {
		end = *t.CompletedAt
	}
	d := end.Sub(*t.ClaimedAt).Seconds()
	if d < 0 {
		return 0
	}
	return d
}

// Enqueue 任务入池（状态 pending，任何人可领）。
func (s *Service) Enqueue(actor Actor, req EnqueueRequest) (*Task, error) {
	title := strings.TrimSpace(req.Title)
	if title == "" {
		return nil, fmt.Errorf("%w: title 不能为空", ErrInvalidArgument)
	}
	message := strings.TrimSpace(req.Message)
	if message == "" {
		return nil, fmt.Errorf("%w: message 不能为空（Agent 需要可执行的题面）", ErrInvalidArgument)
	}

	now := s.now()
	row := &database.CollabTaskRow{
		ID:        newID("ctask"),
		Title:     title,
		Message:   message,
		ProjectID: nullStr(req.ProjectID),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.db.EnqueueCollabTask(row); err != nil {
		return nil, err
	}
	s.auditEvent(actor, ActionTaskEnqueue, "success", "协同任务入池", "collab_task", row.ID,
		map[string]interface{}{"title": title, "project_id": strOf(row.ProjectID)})

	// 回读以获得 DB 侧默认值（status/return_count），避免内存态与库态不一致。
	stored, err := s.db.GetCollabTask(row.ID)
	if err != nil || stored == nil {
		return s.taskView(row), nil
	}
	return s.taskView(stored), nil
}

// Claim 原子领取任务。
//
// 并发安全**完全**交给 database.ClaimCollabTask 的条件式 UPDATE。这里刻意
// 不做「先查状态再改」——那是西湖论剑 stuck_loop 7410 次的同源问题。
func (s *Service) Claim(actor Actor, taskID, seatID string) (*ClaimResult, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("%w: task_id 不能为空", ErrInvalidArgument)
	}
	seat, err := s.getSeatOrErr(seatID)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSeat(seat, actor); err != nil {
		return nil, err
	}

	now := s.now()
	deadline := now.Add(s.wallClock)
	token := newID("claim")

	claimed, err := s.db.ClaimCollabTask(taskID, seat.ID, token, now, &deadline)
	if err != nil {
		return nil, err
	}
	if !claimed {
		// 输掉竞争：区分「不存在」与「已被领走/已完成」，都对调用方等义——换下一题。
		existing, gerr := s.db.GetCollabTask(taskID)
		if gerr == nil && existing == nil {
			return nil, ErrTaskNotFound
		}
		detail := map[string]interface{}{"seat_id": seat.ID}
		if gerr == nil && existing != nil {
			detail["current_status"] = existing.Status
			detail["assignee_seat_id"] = strOf(existing.AssigneeSeatID)
		}
		s.auditEvent(actor, ActionTaskReject, "failure", "领取失败：任务已被领取或已完成", "collab_task", taskID, detail)
		return &ClaimResult{Claimed: false, TaskID: taskID}, nil
	}

	s.auditEvent(actor, ActionTaskClaim, "success", "领取协同任务", "collab_task", taskID,
		map[string]interface{}{
			"seat_id":             seat.ID,
			"seat_kind":           seat.Kind,
			"wall_clock_deadline": deadline.Format(time.RFC3339),
		})

	res := &ClaimResult{Claimed: true, TaskID: taskID, ClaimToken: token, WallClockDeadline: &deadline}
	if stored, err := s.db.GetCollabTask(taskID); err == nil && stored != nil {
		res.Task = s.taskView(stored)
	}
	return res, nil
}

// Complete 完成任务。必须持对 claim_token——任务被回收后旧持有者晚到的回写会被拒绝（F3）。
func (s *Service) Complete(actor Actor, taskID, seatID, token, result string) error {
	task, seat, err := s.loadForWrite(actor, taskID, seatID)
	if err != nil {
		return err
	}
	if err := s.assertAssignee(task, seat.ID); err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("%w: claim_token 不能为空", ErrInvalidArgument)
	}

	ok, err := s.db.CompleteCollabTask(task.ID, token, result, s.now())
	if err != nil {
		return err
	}
	if !ok {
		s.auditEvent(actor, ActionTaskDone, "failure", "完成被拒：领取令牌不匹配", "collab_task", task.ID,
			map[string]interface{}{"seat_id": seat.ID})
		return ErrClaimTokenMismatch
	}
	s.auditEvent(actor, ActionTaskDone, "success", "完成协同任务", "collab_task", task.ID,
		map[string]interface{}{"seat_id": seat.ID, "result_bytes": len(result)})
	return nil
}

// Abandon 主动放弃：凭 token 退回池（return_count+1，总览里成为卡点）。
func (s *Service) Abandon(actor Actor, taskID, seatID, token, reason string) error {
	task, seat, err := s.loadForWrite(actor, taskID, seatID)
	if err != nil {
		return err
	}
	if err := s.assertAssignee(task, seat.ID); err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("%w: claim_token 不能为空", ErrInvalidArgument)
	}

	ok, err := s.db.AbandonCollabTask(task.ID, token, reason, s.now())
	if err != nil {
		return err
	}
	if !ok {
		s.auditEvent(actor, ActionTaskAbandon, "failure", "放弃被拒：领取令牌不匹配", "collab_task", task.ID,
			map[string]interface{}{"seat_id": seat.ID})
		return ErrClaimTokenMismatch
	}
	s.auditEvent(actor, ActionTaskAbandon, "success", "放弃协同任务并退回池", "collab_task", task.ID,
		map[string]interface{}{"seat_id": seat.ID, "reason": reason})
	return nil
}

// Renew 心跳续期：延长墙钟，避免正常跑的长任务被 reaper 误杀（F6）。
// extend <= 0 时按默认墙钟续。
func (s *Service) Renew(actor Actor, taskID, seatID, token string, extend time.Duration) (*time.Time, error) {
	task, seat, err := s.loadForWrite(actor, taskID, seatID)
	if err != nil {
		return nil, err
	}
	if err := s.assertAssignee(task, seat.ID); err != nil {
		return nil, err
	}
	if extend <= 0 {
		extend = s.wallClock
	}
	deadline := s.now().Add(extend)
	ok, err := s.db.RenewCollabTaskDeadline(task.ID, token, deadline, s.now())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrClaimTokenMismatch
	}
	s.auditEvent(actor, ActionTaskRenew, "success", "续期协同任务墙钟", "collab_task", task.ID,
		map[string]interface{}{"seat_id": seat.ID, "wall_clock_deadline": deadline.Format(time.RFC3339)})
	return &deadline, nil
}

// ListTasks 列出任务。status 为空表示全部；seatID 非空表示只看该席位名下任务。
func (s *Service) ListTasks(status, seatID string) ([]*Task, error) {
	rows, err := s.db.ListCollabTasks(strings.TrimSpace(status), strings.TrimSpace(seatID))
	if err != nil {
		return nil, err
	}
	return s.taskViews(rows), nil
}

// GetTask 取单个任务。
func (s *Service) GetTask(taskID string) (*Task, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("%w: task_id 不能为空", ErrInvalidArgument)
	}
	row, err := s.db.GetCollabTask(taskID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrTaskNotFound
	}
	return s.taskView(row), nil
}

// loadForWrite 是完成/放弃/续期的公共前置：取任务、取席位、校验席位归属。
func (s *Service) loadForWrite(actor Actor, taskID, seatID string) (*database.CollabTaskRow, *database.CollabSeatRow, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, nil, fmt.Errorf("%w: task_id 不能为空", ErrInvalidArgument)
	}
	seat, err := s.getSeatOrErr(seatID)
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorizeSeat(seat, actor); err != nil {
		return nil, nil, err
	}
	task, err := s.db.GetCollabTask(taskID)
	if err != nil {
		return nil, nil, err
	}
	if task == nil {
		return nil, nil, ErrTaskNotFound
	}
	return task, seat, nil
}

// assertAssignee 校验「操作者正是任务当前领取者」——队员席之间的隔离线（F4）。
// 注意：这里只是快速失败给出清晰错误；真正的并发裁决仍是 DB 的条件式 UPDATE。
func (s *Service) assertAssignee(task *database.CollabTaskRow, seatID string) error {
	if task.Status != database.CollabTaskStatusClaimed {
		return fmt.Errorf("%w: 任务当前状态为 %s", ErrNotAssignee, task.Status)
	}
	if strOf(task.AssigneeSeatID) != seatID {
		return fmt.Errorf("%w: 任务由席位 %s 持有", ErrNotAssignee, strOf(task.AssigneeSeatID))
	}
	return nil
}
