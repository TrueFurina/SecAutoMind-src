package collab

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"secautomind-ai/internal/audit"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/database"

	"go.uber.org/zap"
)

// ── 测试脚手架 ──────────────────────────────────────────────────────

// fakeClock 可注入时钟：reaper 测试据此推进时间，无需真等墙钟。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "collab.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestService(t *testing.T) (*Service, *fakeClock) {
	t.Helper()
	svc, clk, _ := newTestServiceWithAudit(t)
	return svc, clk
}

func newTestServiceWithAudit(t *testing.T) (*Service, *fakeClock, *database.DB) {
	t.Helper()
	db := newTestDB(t)
	clk := &fakeClock{t: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)}
	svc := New(Options{
		DB:             db,
		Audit:          audit.NewService(db, &config.Config{}, zap.NewNop()),
		Logger:         zap.NewNop(),
		Now:            clk.Now,
		WallClock:      5 * time.Minute,
		ReaperInterval: 50 * time.Millisecond,
	})
	return svc, clk, db
}

func mustSeat(t *testing.T, svc *Service, req CreateSeatRequest) *Seat {
	t.Helper()
	s, err := svc.CreateSeat(Actor{IsAdmin: true}, req)
	if err != nil {
		t.Fatalf("CreateSeat(%s): %v", req.DisplayName, err)
	}
	return s
}

func mustAgentSeat(t *testing.T, svc *Service, name string) *Seat {
	t.Helper()
	return mustSeat(t, svc, CreateSeatRequest{Kind: database.CollabSeatKindAgent, DisplayName: name})
}

func mustHumanSeat(t *testing.T, svc *Service, name, username string) *Seat {
	t.Helper()
	return mustSeat(t, svc, CreateSeatRequest{
		Kind: database.CollabSeatKindHuman, DisplayName: name, Username: username,
	})
}

func mustEnqueue(t *testing.T, svc *Service, title string) *Task {
	t.Helper()
	tk, err := svc.Enqueue(Actor{IsAdmin: true}, EnqueueRequest{Title: title, Message: "题面:" + title})
	if err != nil {
		t.Fatalf("Enqueue(%s): %v", title, err)
	}
	return tk
}

// ── C1 席位模型 ─────────────────────────────────────────────────────

func TestCollabSeatLifecycle(t *testing.T) {
	svc, _ := newTestService(t)

	h := mustHumanSeat(t, svc, "张三", "alice")
	if h.Kind != database.CollabSeatKindHuman || h.Status != database.CollabSeatStatusIdle {
		t.Fatalf("席位默认态不对: kind=%s status=%s", h.Kind, h.Status)
	}
	a := mustAgentSeat(t, svc, "Agent-1")

	seats, err := svc.ListSeats()
	if err != nil {
		t.Fatalf("ListSeats: %v", err)
	}
	if len(seats) != 2 {
		t.Fatalf("期望 2 个席位，实得 %d", len(seats))
	}

	// human 席必须绑定 username——它是越权判定的唯一依据。
	if _, err := svc.CreateSeat(Actor{IsAdmin: true}, CreateSeatRequest{
		Kind: database.CollabSeatKindHuman, DisplayName: "无主席",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("human 席缺 username 应被拒，实得 err=%v", err)
	}
	// kind 白名单
	if _, err := svc.CreateSeat(Actor{IsAdmin: true}, CreateSeatRequest{
		Kind: "robot", DisplayName: "x",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("非法 kind 应被拒，实得 err=%v", err)
	}

	busy := database.CollabSeatStatusBusy
	upd, err := svc.UpdateSeat(Actor{IsAdmin: true}, a.ID, UpdateSeatRequest{Status: &busy, RoleName: strPtr("web")})
	if err != nil {
		t.Fatalf("UpdateSeat: %v", err)
	}
	if upd.Status != busy || upd.RoleName != "web" {
		t.Fatalf("更新未生效: %+v", upd)
	}

	if err := svc.DeleteSeat(Actor{IsAdmin: true}, h.ID); err != nil {
		t.Fatalf("DeleteSeat: %v", err)
	}
	if _, err := svc.GetSeat(h.ID); !errors.Is(err, ErrSeatNotFound) {
		t.Fatalf("删除后应查不到，实得 err=%v", err)
	}
}

func strPtr(s string) *string { return &s }

// F4：队员席只能由本人驱动，不能借用别人的席位身份。
func TestCollabSeatAuthorizationRejectsForeignSeat(t *testing.T) {
	svc, _ := newTestService(t)
	alice := mustHumanSeat(t, svc, "张三", "alice")
	bob := mustHumanSeat(t, svc, "李四", "bob")
	task := mustEnqueue(t, svc, "recon")

	bobActor := Actor{Username: "bob"}
	// bob 冒用 alice 的席位 → 拒
	if _, err := svc.Claim(bobActor, task.ID, alice.ID); !errors.Is(err, ErrSeatForbidden) {
		t.Fatalf("冒用他人席位应被拒，实得 err=%v", err)
	}
	// bob 用自己的席位 → 放行
	if _, err := svc.Claim(bobActor, task.ID, bob.ID); err != nil {
		t.Fatalf("本人席位应可领取，实得 err=%v", err)
	}
	// Agent 席由平台驱动，任何已认证用户可代管
	agent := mustAgentSeat(t, svc, "Agent-1")
	open := mustEnqueue(t, svc, "web")
	if _, err := svc.Claim(bobActor, open.ID, agent.ID); err != nil {
		t.Fatalf("Agent 席应可代管，实得 err=%v", err)
	}
}

// F4 另一半：非本人领取的任务，写操作拒绝、读放行。
func TestCollabNonAssigneeWriteRejectedReadAllowed(t *testing.T) {
	svc, _ := newTestService(t)
	alice := mustHumanSeat(t, svc, "张三", "alice")
	bob := mustHumanSeat(t, svc, "李四", "bob")
	task := mustEnqueue(t, svc, "pwn")

	claim, err := svc.Claim(Actor{Username: "alice"}, task.ID, alice.ID)
	if err != nil || !claim.Claimed {
		t.Fatalf("alice 领取失败: claimed=%v err=%v", claim != nil && claim.Claimed, err)
	}

	// bob 用自己的席位去完成 alice 的任务 → 拒
	if err := svc.Complete(Actor{Username: "bob"}, task.ID, bob.ID, claim.ClaimToken, "伪造结论"); !errors.Is(err, ErrNotAssignee) {
		t.Fatalf("非领取者完成应被拒，实得 err=%v", err)
	}
	if err := svc.Abandon(Actor{Username: "bob"}, task.ID, bob.ID, claim.ClaimToken, "捣乱"); !errors.Is(err, ErrNotAssignee) {
		t.Fatalf("非领取者放弃应被拒，实得 err=%v", err)
	}

	// 读放行：bob 能看到 alice 的进度
	tasks, err := svc.ListTasks("", "")
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if len(tasks) != 1 || tasks[0].AssigneeSeatID != alice.ID {
		t.Fatalf("队员应可只读他人进度，实得 %+v", tasks)
	}
}

// ── C2 任务池与原子领取 ─────────────────────────────────────────────

func TestCollabClaimCompleteFlow(t *testing.T) {
	svc, _ := newTestService(t)
	seat := mustAgentSeat(t, svc, "Agent-1")
	task := mustEnqueue(t, svc, "web-1")

	claim, err := svc.Claim(Actor{}, task.ID, seat.ID)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !claim.Claimed || claim.ClaimToken == "" || claim.WallClockDeadline == nil {
		t.Fatalf("领取结果缺字段: %+v", claim)
	}
	if claim.Task == nil || claim.Task.Status != database.CollabTaskStatusClaimed {
		t.Fatalf("领取后任务状态应为 claimed，实得 %+v", claim.Task)
	}

	// 二次领取：不是错误，是输掉竞争
	again, err := svc.Claim(Actor{}, task.ID, seat.ID)
	if err != nil {
		t.Fatalf("二次领取不应报错（应返回未抢到）: %v", err)
	}
	if again.Claimed {
		t.Fatal("同一任务被二次领取成功 —— 原子性失效")
	}

	if err := svc.Complete(Actor{}, task.ID, seat.ID, claim.ClaimToken, "flag{ok}"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got, err := svc.GetTask(task.ID)
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if got.Status != database.CollabTaskStatusDone || got.Result != "flag{ok}" {
		t.Fatalf("完成态不对: %+v", got)
	}
	if got.ElapsedSeconds < 0 {
		t.Fatalf("耗时为负: %v", got.ElapsedSeconds)
	}
}

// C2 验收：并发 5 个领取者抢 10 个任务，每个任务恰好 1 个赢家。
func TestCollabConcurrentClaimNoDuplicate(t *testing.T) {
	svc, _ := newTestService(t)

	const taskCount, claimerCount = 10, 5
	taskIDs := make([]string, 0, taskCount)
	for i := 0; i < taskCount; i++ {
		taskIDs = append(taskIDs, mustEnqueue(t, svc, "t").ID)
	}
	seats := make([]string, 0, claimerCount)
	for i := 0; i < claimerCount; i++ {
		seats = append(seats, mustAgentSeat(t, svc, "Agent").ID)
	}

	var mu sync.Mutex
	wins := map[string]int{}
	losers := 0

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, seatID := range seats {
		wg.Add(1)
		go func(seatID string) {
			defer wg.Done()
			<-start
			for _, tid := range taskIDs {
				res, err := svc.Claim(Actor{}, tid, seatID)
				if err != nil {
					t.Errorf("Claim(%s): %v", tid, err)
					return
				}
				mu.Lock()
				if res.Claimed {
					wins[tid]++
				} else {
					losers++
				}
				mu.Unlock()
			}
		}(seatID)
	}
	close(start)
	wg.Wait()

	for _, tid := range taskIDs {
		if wins[tid] != 1 {
			t.Fatalf("任务 %s 被领取 %d 次（期望恰好 1 次）—— 原子领取失效", tid, wins[tid])
		}
	}
	if losers != taskCount*(claimerCount-1) {
		t.Fatalf("落败次数应为 %d，实得 %d", taskCount*(claimerCount-1), losers)
	}
}

func TestCollabAbandonReturnsTaskToPool(t *testing.T) {
	svc, _ := newTestService(t)
	seat := mustAgentSeat(t, svc, "Agent-1")
	task := mustEnqueue(t, svc, "crypto")

	claim, err := svc.Claim(Actor{}, task.ID, seat.ID)
	if err != nil || !claim.Claimed {
		t.Fatalf("Claim: claimed=%v err=%v", claim != nil && claim.Claimed, err)
	}
	if err := svc.Abandon(Actor{}, task.ID, seat.ID, claim.ClaimToken, "工具缺失"); err != nil {
		t.Fatalf("Abandon: %v", err)
	}
	got, err := svc.GetTask(task.ID)
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if got.Status != database.CollabTaskStatusPending || got.ReturnCount != 1 {
		t.Fatalf("放弃后应回 pending 且 return_count=1，实得 %+v", got)
	}
	if got.AssigneeSeatID != "" {
		t.Fatalf("放弃后应清空 assignee，实得 %q", got.AssigneeSeatID)
	}
	// 退回池后别人可领
	other := mustAgentSeat(t, svc, "Agent-2")
	if res, err := svc.Claim(Actor{}, task.ID, other.ID); err != nil || !res.Claimed {
		t.Fatalf("退回池后应可被他人领取: claimed=%v err=%v", res != nil && res.Claimed, err)
	}
}

// ── C4 墙钟硬限与卡死回收 ───────────────────────────────────────────

func TestCollabReaperReturnsStaleTaskAndSparesRenewed(t *testing.T) {
	svc, clk := newTestService(t)
	seat := mustAgentSeat(t, svc, "Agent-1")

	stuck := mustEnqueue(t, svc, "卡死题")
	healthy := mustEnqueue(t, svc, "长跑题")

	claimStuck, err := svc.Claim(Actor{}, stuck.ID, seat.ID)
	if err != nil || !claimStuck.Claimed {
		t.Fatalf("Claim(stuck): %+v %v", claimStuck, err)
	}
	claimHealthy, err := svc.Claim(Actor{}, healthy.ID, seat.ID)
	if err != nil || !claimHealthy.Claimed {
		t.Fatalf("Claim(healthy): %+v %v", claimHealthy, err)
	}

	// 长跑任务心跳续期，把墙钟推后（F6：不该被误杀）
	if _, err := svc.Renew(Actor{}, healthy.ID, seat.ID, claimHealthy.ClaimToken, 30*time.Minute); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	clk.Advance(6 * time.Minute) // 越过原始 5 分钟硬限

	n, err := svc.ReapOnce()
	if err != nil {
		t.Fatalf("ReapOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("应只回收 1 条卡死任务，实得 %d", n)
	}

	gotStuck, _ := svc.GetTask(stuck.ID)
	if gotStuck.Status != database.CollabTaskStatusPending || gotStuck.ReturnCount != 1 {
		t.Fatalf("卡死任务应回池且 return_count=1，实得 %+v", gotStuck)
	}
	if gotStuck.Error == "" {
		t.Fatal("卡死任务应记录 error 说明（供总览标记卡点）")
	}

	gotHealthy, _ := svc.GetTask(healthy.ID)
	if gotHealthy.Status != database.CollabTaskStatusClaimed || gotHealthy.ReturnCount != 0 {
		t.Fatalf("续期任务不该被回收，实得 %+v", gotHealthy)
	}
	// 不阻塞其它任务：健康任务仍能正常完成
	if err := svc.Complete(Actor{}, healthy.ID, seat.ID, claimHealthy.ClaimToken, "flag{long}"); err != nil {
		t.Fatalf("健康任务完成失败: %v", err)
	}
}

// F3：任务被回收并转手后，旧持有者拿旧 token 回写必须被拒。
func TestCollabStaleHolderWriteRejected(t *testing.T) {
	svc, clk := newTestService(t)
	seat := mustAgentSeat(t, svc, "Agent-1")
	task := mustEnqueue(t, svc, "web")

	first, err := svc.Claim(Actor{}, task.ID, seat.ID)
	if err != nil || !first.Claimed {
		t.Fatalf("首次领取失败: %+v %v", first, err)
	}

	clk.Advance(6 * time.Minute)
	if n, err := svc.ReapOnce(); err != nil || n != 1 {
		t.Fatalf("回收应命中 1 条: n=%d err=%v", n, err)
	}

	second, err := svc.Claim(Actor{}, task.ID, seat.ID)
	if err != nil || !second.Claimed {
		t.Fatalf("回收后应可重新领取: %+v %v", second, err)
	}
	if second.ClaimToken == first.ClaimToken {
		t.Fatal("重新领取应换发新 token")
	}

	if err := svc.Complete(Actor{}, task.ID, seat.ID, first.ClaimToken, "旧结论"); !errors.Is(err, ErrClaimTokenMismatch) {
		t.Fatalf("旧 token 回写应被拒，实得 err=%v", err)
	}
	if err := svc.Abandon(Actor{}, task.ID, seat.ID, first.ClaimToken, "旧放弃"); !errors.Is(err, ErrClaimTokenMismatch) {
		t.Fatalf("旧 token 放弃应被拒，实得 err=%v", err)
	}
	if err := svc.Complete(Actor{}, task.ID, seat.ID, second.ClaimToken, "新结论"); err != nil {
		t.Fatalf("新 token 回写应成功，实得 err=%v", err)
	}
}

func TestCollabReaperLifecycle(t *testing.T) {
	svc, _ := newTestService(t)

	if svc.ReaperRunning() {
		t.Fatal("未启动时不应在跑")
	}
	svc.StartReaper()
	svc.StartReaper() // 幂等
	if !svc.ReaperRunning() {
		t.Fatal("启动后应在跑")
	}
	svc.StopReaper()
	if svc.ReaperRunning() {
		t.Fatal("停止后不应在跑")
	}
	svc.StopReaper() // 幂等
}

// ── C3 总览聚合 ─────────────────────────────────────────────────────

func TestCollabOverviewAggregation(t *testing.T) {
	svc, clk := newTestService(t)
	alice := mustHumanSeat(t, svc, "张三", "alice")
	agent := mustAgentSeat(t, svc, "Agent-1")

	done := mustEnqueue(t, svc, "已完成")
	active := mustEnqueue(t, svc, "进行中")
	stuck := mustEnqueue(t, svc, "卡点")
	pending := mustEnqueue(t, svc, "待领")

	// 卡点：领取→超时回收→再领（return_count=1，且回到进行中）
	c1, _ := svc.Claim(Actor{}, stuck.ID, alice.ID)
	clk.Advance(6 * time.Minute)
	if n, err := svc.ReapOnce(); err != nil || n != 1 {
		t.Fatalf("回收: n=%d err=%v", n, err)
	}
	if _, err := svc.Claim(Actor{}, stuck.ID, agent.ID); err != nil {
		t.Fatalf("卡点二次领取: %v", err)
	}
	_ = c1

	// 已完成
	cd, _ := svc.Claim(Actor{}, done.ID, agent.ID)
	if err := svc.Complete(Actor{}, done.ID, agent.ID, cd.ClaimToken, "ok"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// 进行中
	if _, err := svc.Claim(Actor{}, active.ID, alice.ID); err != nil {
		t.Fatalf("Claim(active): %v", err)
	}
	_ = pending

	ov, err := svc.Overview()
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if ov.Total != 4 {
		t.Fatalf("总任务数应为 4，实得 %d", ov.Total)
	}
	if ov.Totals[database.CollabTaskStatusDone] != 1 || ov.Totals[database.CollabTaskStatusPending] != 1 {
		t.Fatalf("按状态计数不对: %+v", ov.Totals)
	}
	if ov.StuckCount != 1 || len(ov.StuckTasks) != 1 || ov.StuckTasks[0].ID != stuck.ID {
		t.Fatalf("卡点识别不对: count=%d tasks=%+v", ov.StuckCount, ov.StuckTasks)
	}
	if ov.Tasks[0].ID != stuck.ID {
		t.Fatalf("卡点应置顶，实得首项 %s", ov.Tasks[0].ID)
	}
	if len(ov.Seats) != 2 {
		t.Fatalf("席位数应为 2，实得 %d", len(ov.Seats))
	}
	byID := map[string]*SeatLoad{}
	for _, s := range ov.Seats {
		byID[s.SeatID] = s
	}
	if byID[alice.ID].ActiveCount != 1 {
		t.Fatalf("alice 应持 1 个进行中任务，实得 %d", byID[alice.ID].ActiveCount)
	}
	if byID[agent.ID].DoneCount != 1 || byID[agent.ID].ActiveCount != 1 {
		t.Fatalf("agent 负载不对: %+v", byID[agent.ID])
	}
	if ov.WallClockSeconds != 300 {
		t.Fatalf("墙钟口径应为 300s，实得 %v", ov.WallClockSeconds)
	}
}

// ── C5 协同全程审计 ─────────────────────────────────────────────────

func TestCollabAuditTrailRecorded(t *testing.T) {
	svc, _, db := newTestServiceWithAudit(t)
	seat := mustAgentSeat(t, svc, "Agent-1")
	task := mustEnqueue(t, svc, "web")
	claim, err := svc.Claim(Actor{}, task.ID, seat.ID)
	if err != nil || !claim.Claimed {
		t.Fatalf("Claim: %+v %v", claim, err)
	}
	if err := svc.Complete(Actor{}, task.ID, seat.ID, claim.ClaimToken, "flag"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	logs, err := db.ListAuditLogs(database.ListAuditLogsFilter{Category: auditCategory, Limit: 100})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	actions := map[string]int{}
	for _, l := range logs {
		actions[l.Action]++
	}
	for _, want := range []string{ActionSeatCreate, ActionTaskEnqueue, ActionTaskClaim, ActionTaskDone} {
		if actions[want] == 0 {
			t.Fatalf("审计缺少动作 %s（实得 %+v）", want, actions)
		}
	}
	// 赛后可按任务 resource_id 回放
	byTask, err := db.ListAuditLogs(database.ListAuditLogsFilter{
		Category: auditCategory, ResourceID: task.ID, Limit: 100,
	})
	if err != nil {
		t.Fatalf("按任务回放: %v", err)
	}
	if len(byTask) < 2 {
		t.Fatalf("按任务应能回放领取+完成，实得 %d 条", len(byTask))
	}
}
