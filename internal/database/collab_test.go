package database

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newCollabTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "collab.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedCollabTask(t *testing.T, db *DB, id string) {
	t.Helper()
	now := time.Now()
	if err := db.EnqueueCollabTask(&CollabTaskRow{
		ID: id, Title: id, Message: "m", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("EnqueueCollabTask(%s): %v", id, err)
	}
}

// TestCollabClaimIsAtomicUnderConcurrency 验收标准 C2 的核心断言：
// 并发 5 个领取者抢 10 个任务 → 每个任务恰好被领走 1 次，0 重复领取。
//
// 这条测试一旦被改回「先 SELECT 判断再 UPDATE」的写法就必须 FAIL——
// 即它对实现做了变异约束（详见 TaskCollabMutationCheck 说明）。
func TestCollabClaimIsAtomicUnderConcurrency(t *testing.T) {
	db := newCollabTestDB(t)

	const tasks, claimers = 10, 5
	ids := make([]string, 0, tasks)
	for i := 0; i < tasks; i++ {
		id := fmt.Sprintf("task-%02d", i)
		seedCollabTask(t, db, id)
		ids = append(ids, id)
	}

	var mu sync.Mutex
	winners := map[string][]string{} // taskID -> 领到它的席位列表

	var wg sync.WaitGroup
	for c := 0; c < claimers; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			seat := fmt.Sprintf("seat-%d", c)
			for _, id := range ids {
				deadline := time.Now().Add(time.Hour)
				ok, err := db.ClaimCollabTask(id, seat, fmt.Sprintf("tok-%s-%d", id, c), time.Now(), &deadline)
				if err != nil {
					t.Errorf("ClaimCollabTask(%s, %s): %v", id, seat, err)
					return
				}
				if ok {
					mu.Lock()
					winners[id] = append(winners[id], seat)
					mu.Unlock()
				}
			}
		}(c)
	}
	wg.Wait()

	total := 0
	for _, id := range ids {
		got := winners[id]
		if len(got) != 1 {
			t.Fatalf("任务 %s 被领取 %d 次（期望恰好 1 次），领取者=%v —— 原子领取失效", id, len(got), got)
		}
		total += len(got)
	}
	if total != tasks {
		t.Fatalf("总成功领取数 = %d，期望 %d", total, tasks)
	}
}

// TestCollabClaimSecondClaimerRejected 同一任务第二次领取必须失败（无并发也要拦）
func TestCollabClaimSecondClaimerRejected(t *testing.T) {
	db := newCollabTestDB(t)
	seedCollabTask(t, db, "t1")

	dl := time.Now().Add(time.Hour)
	ok, err := db.ClaimCollabTask("t1", "seat-A", "tok-A", time.Now(), &dl)
	if err != nil || !ok {
		t.Fatalf("首次领取应成功：ok=%v err=%v", ok, err)
	}
	ok, err = db.ClaimCollabTask("t1", "seat-B", "tok-B", time.Now(), &dl)
	if err != nil {
		t.Fatalf("二次领取不应报错：%v", err)
	}
	if ok {
		t.Fatal("同一任务被二次领取成功 —— 原子领取失效")
	}
}

// TestCollabStaleTokenWriteRejected 失败模式 F3：任务被回收后，旧持有者晚到的回写必须被拒
func TestCollabStaleTokenWriteRejected(t *testing.T) {
	db := newCollabTestDB(t)
	seedCollabTask(t, db, "t1")

	dl := time.Now().Add(time.Hour)
	if ok, _ := db.ClaimCollabTask("t1", "seat-A", "tok-old", time.Now(), &dl); !ok {
		t.Fatal("首次领取失败")
	}
	if ok, err := db.AbandonCollabTask("t1", "tok-old", "主动放弃", time.Now()); err != nil || !ok {
		t.Fatalf("放弃应成功：ok=%v err=%v", ok, err)
	}
	// 旧 token 回写：任务已回池，必须拒绝
	ok, err := db.CompleteCollabTask("t1", "tok-old", "脏结果", time.Now())
	if err != nil {
		t.Fatalf("旧 token 回写不应报错：%v", err)
	}
	if ok {
		t.Fatal("旧 token 回写被接受 —— claim_token 校验失效")
	}

	// 新持有者正常完成
	dl2 := time.Now().Add(time.Hour)
	if ok, _ := db.ClaimCollabTask("t1", "seat-B", "tok-new", time.Now(), &dl2); !ok {
		t.Fatal("重新领取失败")
	}
	if ok, err := db.CompleteCollabTask("t1", "tok-new", "正确结果", time.Now()); err != nil || !ok {
		t.Fatalf("新持有者完成应成功：ok=%v err=%v", ok, err)
	}
	got, err := db.GetCollabTask("t1")
	if err != nil {
		t.Fatalf("GetCollabTask: %v", err)
	}
	if got.Status != CollabTaskStatusDone || got.Result.String != "正确结果" {
		t.Fatalf("终态错误：status=%s result=%q", got.Status, got.Result.String)
	}
	if got.ReturnCount != 1 {
		t.Fatalf("return_count = %d，期望 1", got.ReturnCount)
	}
}

// TestCollabReturnStaleTasks 验收标准 C4：墙钟到点自动退池，且退池后任务可被再次领取
func TestCollabReturnStaleTasks(t *testing.T) {
	db := newCollabTestDB(t)
	seedCollabTask(t, db, "stuck")
	seedCollabTask(t, db, "healthy")

	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	if ok, _ := db.ClaimCollabTask("stuck", "seat-A", "tok-A", time.Now(), &past); !ok {
		t.Fatal("领取 stuck 失败")
	}
	if ok, _ := db.ClaimCollabTask("healthy", "seat-B", "tok-B", time.Now(), &future); !ok {
		t.Fatal("领取 healthy 失败")
	}

	n, err := db.ReturnStaleCollabTasks(time.Now())
	if err != nil {
		t.Fatalf("ReturnStaleCollabTasks: %v", err)
	}
	if n != 1 {
		t.Fatalf("回收条数 = %d，期望 1（只回收 stuck，不误杀 healthy）", n)
	}

	stuck, _ := db.GetCollabTask("stuck")
	if stuck.Status != CollabTaskStatusPending {
		t.Fatalf("stuck 状态 = %s，期望 %s（应已退回池）", stuck.Status, CollabTaskStatusPending)
	}
	if stuck.AssigneeSeatID.Valid && stuck.AssigneeSeatID.String != "" {
		t.Fatalf("stuck 的 assignee 未清空：%v", stuck.AssigneeSeatID)
	}
	if stuck.ReturnCount != 1 {
		t.Fatalf("stuck return_count = %d，期望 1", stuck.ReturnCount)
	}
	healthy, _ := db.GetCollabTask("healthy")
	if healthy.Status != CollabTaskStatusClaimed {
		t.Fatalf("healthy 状态 = %s，期望 %s（不得被误杀）", healthy.Status, CollabTaskStatusClaimed)
	}

	// 退池后可被重新领取
	dl := time.Now().Add(time.Hour)
	if ok, _ := db.ClaimCollabTask("stuck", "seat-C", "tok-C", time.Now(), &dl); !ok {
		t.Fatal("退池后的任务应可被重新领取")
	}
}

// TestCollabRenewPreventsReaper 失败模式 F6：正常跑的长任务续期后不得被误杀
func TestCollabRenewPreventsReaper(t *testing.T) {
	db := newCollabTestDB(t)
	seedCollabTask(t, db, "long")

	soon := time.Now().Add(time.Second)
	if ok, _ := db.ClaimCollabTask("long", "seat-A", "tok-A", time.Now(), &soon); !ok {
		t.Fatal("领取失败")
	}
	if ok, err := db.RenewCollabTaskDeadline("long", "tok-A", time.Now().Add(time.Hour), time.Now()); err != nil || !ok {
		t.Fatalf("续期应成功：ok=%v err=%v", ok, err)
	}
	n, err := db.ReturnStaleCollabTasks(time.Now())
	if err != nil {
		t.Fatalf("ReturnStaleCollabTasks: %v", err)
	}
	if n != 0 {
		t.Fatalf("续期后仍被回收 %d 条 —— 会误杀正常长任务", n)
	}
}
