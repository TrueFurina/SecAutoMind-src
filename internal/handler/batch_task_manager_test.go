package handler

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

func TestNormalizeBatchQueueConcurrency(t *testing.T) {
	if got := normalizeBatchQueueConcurrency(0); got != DefaultBatchQueueConcurrency {
		t.Fatalf("expected default %d, got %d", DefaultBatchQueueConcurrency, got)
	}
	if got := normalizeBatchQueueConcurrency(99); got != MaxBatchQueueConcurrency {
		t.Fatalf("expected max %d, got %d", MaxBatchQueueConcurrency, got)
	}
}

func TestClaimNextPendingTaskParallel(t *testing.T) {
	m := NewBatchTaskManager(zap.NewNop())
	queue, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 3, []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("CreateBatchQueue: %v", err)
	}
	m.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)

	t1, ok1 := m.ClaimNextPendingTask(queue.ID)
	t2, ok2 := m.ClaimNextPendingTask(queue.ID)
	if !ok1 || !ok2 || t1.ID == t2.ID {
		t.Fatalf("expected two distinct claims, got ok1=%v ok2=%v t1=%v t2=%v", ok1, ok2, t1, t2)
	}
	if t1.Status != BatchTaskStatusRunning || t2.Status != BatchTaskStatusRunning {
		t.Fatalf("claimed tasks should be running")
	}
	t3, ok3 := m.ClaimNextPendingTask(queue.ID)
	if !ok3 {
		t.Fatal("expected third claim")
	}
	_, ok4 := m.ClaimNextPendingTask(queue.ID)
	if ok4 {
		t.Fatal("expected no fourth pending task")
	}
	_ = t3
}

func TestBatchQueueExecutionShouldStop(t *testing.T) {
	t.Parallel()
	if !batchQueueExecutionShouldStop(nil, false) {
		t.Fatal("expected stop when queue missing")
	}
	if !batchQueueExecutionShouldStop(nil, true) {
		t.Fatal("expected stop when queue is nil but exists=true")
	}
	q := &BatchTaskQueue{Status: BatchQueueStatusRunning}
	if batchQueueExecutionShouldStop(q, true) {
		t.Fatal("expected continue when running")
	}
	q.Status = BatchQueueStatusCancelled
	if !batchQueueExecutionShouldStop(q, true) {
		t.Fatal("expected stop when cancelled")
	}
}

func TestBatchSubTaskConversationMetaKeepsQueueRole(t *testing.T) {
	t.Parallel()

	meta := batchSubTaskConversationMeta(nil, &BatchTaskQueue{Role: " 渗透测试 "})
	if meta.Source != "batch_task" {
		t.Fatalf("expected batch_task source, got %q", meta.Source)
	}
	if meta.RoleName != "渗透测试" {
		t.Fatalf("expected queue role to be stored on child conversation, got %q", meta.RoleName)
	}
}

func TestDeleteQueueBlockedWhileExecutorActive(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())
	queue, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 1, []string{"hello"})
	if err != nil {
		t.Fatalf("CreateBatchQueue: %v", err)
	}
	marked, _ := m.TryMarkQueueExecutor(queue.ID)
	if !marked {
		t.Fatal("expected to mark executor")
	}
	m.UpdateQueueStatus(queue.ID, BatchQueueStatusCancelled)

	err = m.DeleteQueue(queue.ID)
	if !errors.Is(err, ErrBatchQueueExecutorActive) {
		t.Fatalf("expected ErrBatchQueueExecutorActive, got %v", err)
	}
	if _, ok := m.GetBatchQueue(queue.ID); !ok {
		t.Fatal("queue should still exist while executor active")
	}

	_, gen := m.TryMarkQueueExecutor(queue.ID) // 已占用：返回当前代次
	m.UnmarkQueueExecutor(queue.ID, gen)
	if err := m.DeleteQueue(queue.ID); err != nil {
		t.Fatalf("expected delete after executor unmarked, got %v", err)
	}
	if _, ok := m.GetBatchQueue(queue.ID); ok {
		t.Fatal("queue should be deleted")
	}
}

func TestDeleteQueueBlockedWhileRunning(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())
	queue, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 1, []string{"hello"})
	if err != nil {
		t.Fatalf("CreateBatchQueue: %v", err)
	}
	m.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)

	err = m.DeleteQueue(queue.ID)
	if !errors.Is(err, ErrBatchQueueStillRunning) {
		t.Fatalf("expected ErrBatchQueueStillRunning, got %v", err)
	}
}

func TestTryMarkQueueExecutorDedupes(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())
	marked, gen1 := m.TryMarkQueueExecutor("q-1")
	if !marked {
		t.Fatal("first mark should succeed")
	}
	if marked2, _ := m.TryMarkQueueExecutor("q-1"); marked2 {
		t.Fatal("second mark should fail")
	}
	m.UnmarkQueueExecutor("q-1", gen1)
	marked, gen2 := m.TryMarkQueueExecutor("q-1")
	if !marked {
		t.Fatal("mark after unmark should succeed")
	}
	if gen1 == gen2 {
		t.Fatalf("代次必须单调递增（gen1=%d gen2=%d）", gen1, gen2)
	}
}

// TestStaleGenerationCannotReleaseNewSlot 复现「暂停态单条重跑」的跨代误释放窗口：
// 旧执行器（gen1）未退出时，单条重跑 ForceUnmark 槽位并立即起新执行器（gen2）。
// 旧行为：旧执行器退出时的 defer 无条件 Unmark → 删掉 gen2 的槽位 → 第三次启动双跑。
// 新行为：代次不吻合不释放，gen2 的槽位存活到自身退出为止。
func TestStaleGenerationCannotReleaseNewSlot(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())

	marked, gen1 := m.TryMarkQueueExecutor("q-1")
	if !marked || gen1 == 0 {
		t.Fatalf("first mark should succeed with nonzero gen, got marked=%v gen=%d", marked, gen1)
	}

	// 单条重跑场景：强清旧槽位（旧协程仍在途，尚未执行 defer）
	m.ForceUnmarkQueueExecutor("q-1")
	if m.IsQueueExecutorActive("q-1") {
		t.Fatal("force unmark should release the slot")
	}

	// 新执行器占位
	marked, gen2 := m.TryMarkQueueExecutor("q-1")
	if !marked {
		t.Fatal("re-mark after force unmark should succeed")
	}
	if gen2 <= gen1 {
		t.Fatalf("new generation must be greater: gen1=%d gen2=%d", gen1, gen2)
	}
	if !m.IsQueueExecutorCurrent("q-1", gen2) {
		t.Fatal("gen2 should be the current executor")
	}
	if m.IsQueueExecutorCurrent("q-1", gen1) {
		t.Fatal("stale gen1 must not be current (worker loop should exit)")
	}

	// 旧执行器此时才退出：凭 gen1 释放必须被拒（核心断言）
	m.UnmarkQueueExecutor("q-1", gen1)
	if !m.IsQueueExecutorActive("q-1") {
		t.Fatal("stale generation released the NEW executor's slot — cross-generation leak")
	}
	if marked3, _ := m.TryMarkQueueExecutor("q-1"); marked3 {
		t.Fatal("slot must still be held by gen2 after stale release attempt")
	}

	// 新执行器正常退出：凭 gen2 释放成功，槽位回到可用
	m.UnmarkQueueExecutor("q-1", gen2)
	if m.IsQueueExecutorActive("q-1") {
		t.Fatal("gen2 release should free the slot")
	}
	if marked, _ := m.TryMarkQueueExecutor("q-1"); !marked {
		t.Fatal("slot should be markable again after proper release")
	}
}
