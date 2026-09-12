package collab

import (
	"time"

	"secautomind-ai/internal/database"
)

// SeatLoad 单个席位的负载视图。
type SeatLoad struct {
	SeatID      string `json:"seat_id"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	RoleName    string `json:"role_name,omitempty"`
	ActiveCount int    `json:"active_count"` // 名下进行中任务数
	DoneCount   int    `json:"done_count"`   // 名下已完成任务数
}

// Overview 演示现场「一屏全览」的聚合结果。
//
// 排序契约：Tasks 由 DB 侧给出——**卡点（return_count>0）置顶**，其次进行中、
// 待领、已完成。StuckTasks 是其中的卡点子集，单独拎出来方便前端高亮。
type Overview struct {
	GeneratedAt      time.Time      `json:"generated_at"`
	Totals           map[string]int `json:"totals"`
	Total            int            `json:"total"`
	StuckCount       int            `json:"stuck_count"`
	Seats            []*SeatLoad    `json:"seats"`
	Tasks            []*Task        `json:"tasks"`
	StuckTasks       []*Task        `json:"stuck_tasks"`
	ReaperRunning    bool           `json:"reaper_running"`
	WallClockSeconds float64        `json:"wall_clock_seconds"`
}

// Overview 聚合任务 × 负责人 × 状态 × 耗时 × 卡点。
func (s *Service) Overview() (*Overview, error) {
	totals, err := s.db.CountCollabTasksByStatus()
	if err != nil {
		return nil, err
	}
	taskRows, err := s.db.ListCollabTasks("", "")
	if err != nil {
		return nil, err
	}
	seatRows, err := s.db.ListCollabSeats()
	if err != nil {
		return nil, err
	}

	tasks := s.taskViews(taskRows)

	// 席位负载：按 assignee_seat_id 归集，避免 N+1 查询。
	active := map[string]int{}
	done := map[string]int{}
	for _, r := range taskRows {
		seatID := strOf(r.AssigneeSeatID)
		if seatID == "" {
			continue
		}
		switch r.Status {
		case database.CollabTaskStatusClaimed:
			active[seatID]++
		case database.CollabTaskStatusDone:
			done[seatID]++
		}
	}
	seats := make([]*SeatLoad, 0, len(seatRows))
	for _, r := range seatRows {
		seats = append(seats, &SeatLoad{
			SeatID:      r.ID,
			DisplayName: r.DisplayName,
			Kind:        r.Kind,
			Status:      r.Status,
			RoleName:    strOf(r.RoleName),
			ActiveCount: active[r.ID],
			DoneCount:   done[r.ID],
		})
	}

	stuck := make([]*Task, 0)
	for _, t := range tasks {
		if t.ReturnCount > 0 {
			stuck = append(stuck, t)
		}
	}

	total := 0
	for _, n := range totals {
		total += n
	}

	return &Overview{
		GeneratedAt:      s.now(),
		Totals:           totals,
		Total:            total,
		StuckCount:       len(stuck),
		Seats:            seats,
		Tasks:            tasks,
		StuckTasks:       stuck,
		ReaperRunning:    s.ReaperRunning(),
		WallClockSeconds: s.wallClock.Seconds(),
	}, nil
}
