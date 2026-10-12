package handler

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"secautomind-ai/internal/database"

	_ "github.com/glebarez/go-sqlite"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// HITL「审批落库 fail-closed」回归测试
//
// 背景（为什么必须有这个测试）：
//   修复前 hitl.go 与 c2_hitl_bridge.go 用 `_, _ = m.db.Exec(...)` 静默丢弃
//   审批落库错误，UI 仍返回「已批准/已驳回」，形成「界面说拦过、审计表无记录」
//   的假成功。对主打「人机可控」的安全产品，这等于无法自证拦截。
//
// 本测试锁死三条铁律：
//   1. 落库失败 → 必须返回 error，且不得返回可用决策（fail-closed，不是假成功）
//   2. 落库成功 → 必须正常放行（fail-closed 不等于「永远拒绝」，别修成瘫痪）
//   3. 三个分支（人工决策 / 超时 / 取消）都要满足 1，不能有遗漏分支
// ---------------------------------------------------------------------------

// newClosedDB 返回一个**已关闭**的 DB，任何 Exec/Query 都会返回错误。
// 这是构造「落库失败」最小成本的方式：database.DB 内嵌 *sql.DB（字段名 DB 可导出），
// 因此无需真实 schema 即可注入失败态。
func newClosedDB(t *testing.T) *database.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("打开内存 sqlite 失败: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭内存 sqlite 失败: %v", err)
	}
	return &database.DB{DB: raw}
}

// newOKDB 建一张**最小** hitl_interrupts 表并插入一条 pending 记录，
// 仅包含 UPDATE 语句触及的字段 —— 不依赖 EnsureSchema 的完整 schema，
// 避免 schema 变更把测试拖挂（测试要测的是 fail-closed 逻辑，不是 schema）。
func newOKDB(t *testing.T, interruptID string) *database.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("打开内存 sqlite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Exec(`CREATE TABLE hitl_interrupts (
		id TEXT PRIMARY KEY,
		status TEXT,
		decision TEXT,
		decision_comment TEXT,
		decided_at DATETIME,
		decided_by TEXT
	)`); err != nil {
		t.Fatalf("建最小 hitl_interrupts 表失败: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO hitl_interrupts (id, status) VALUES (?, 'pending')`, interruptID); err != nil {
		t.Fatalf("插入 pending 记录失败: %v", err)
	}
	return &database.DB{DB: raw}
}

func newPending(id string, mode string) *pendingInterrupt {
	return &pendingInterrupt{
		ConversationID: "conv-test",
		InterruptID:    id,
		Mode:           mode,
		ToolName:       "dangerous_tool",
		ToolCallID:     "call-test",
		decideCh:       make(chan hitlDecision, 1),
	}
}

// TestHITLWaitDecisionFailsClosedOnPersistError_Decided
// 分支一：人工已决策，但落库失败 → 必须拒绝放行。
func TestHITLWaitDecisionFailsClosedOnPersistError_Decided(t *testing.T) {
	m := NewHITLManager(newClosedDB(t), zap.NewNop())
	p := newPending("itm-decided", "review")
	p.decideCh <- hitlDecision{Decision: "approve", Comment: "human approved"}

	d, err := m.waitDecision(context.Background(), p, 0)
	if err == nil {
		t.Fatalf("落库失败必须返回错误（fail-closed），实际返回成功，decision=%+v", d)
	}
	if d.Decision != "" {
		t.Errorf("fail-closed 时不得返回可用决策，实际 decision=%q（应为拒绝而非放行）", d.Decision)
	}
	if !strings.Contains(err.Error(), "落库失败") {
		t.Errorf("错误信息应标明落库失败以便排障，实际: %v", err)
	}
}

// TestHITLWaitDecisionFailsClosedOnPersistError_Timeout
// 分支二：审批超时自动拒绝，但落库失败 → 必须报告错误（不能假装已拒绝）。
func TestHITLWaitDecisionFailsClosedOnPersistError_Timeout(t *testing.T) {
	m := NewHITLManager(newClosedDB(t), zap.NewNop())
	p := newPending("itm-timeout", "review") // decideCh 无发送者，必然走超时

	d, err := m.waitDecision(context.Background(), p, 5*time.Millisecond)
	if err == nil {
		t.Fatalf("超时分支落库失败必须返回错误，实际返回成功，decision=%+v", d)
	}
	if d.Decision != "" {
		t.Errorf("fail-closed 时不得返回可用决策，实际 decision=%q", d.Decision)
	}
}

// TestHITLWaitDecisionFailsClosedOnPersistError_Cancelled
// 分支三：任务取消，但落库失败 → 必须报告错误。
func TestHITLWaitDecisionFailsClosedOnPersistError_Cancelled(t *testing.T) {
	m := NewHITLManager(newClosedDB(t), zap.NewNop())
	p := newPending("itm-cancel", "review")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d, err := m.waitDecision(ctx, p, 0)
	if err == nil {
		t.Fatalf("取消分支落库失败必须返回错误，实际返回成功，decision=%+v", d)
	}
	if d.Decision != "" {
		t.Errorf("fail-closed 时不得返回可用决策，实际 decision=%q", d.Decision)
	}
}

// TestHITLWaitDecisionPassesWhenPersisted
// 反向对照：落库成功时必须正常放行。
// 没有这条测试，「fail-closed」可能被后来者误改成「一律拒绝」而测试仍全绿 ——
// 那会让 HITL 从「假成功」变成「永远不可用」，是另一种事故。
func TestHITLWaitDecisionPassesWhenPersisted(t *testing.T) {
	const id = "itm-ok"
	m := NewHITLManager(newOKDB(t, id), zap.NewNop())
	p := newPending(id, "review")
	p.decideCh <- hitlDecision{Decision: "approve", Comment: "human approved"}

	d, err := m.waitDecision(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("落库成功时应正常放行，实际返回错误: %v（fail-closed 被误伤成一律拒绝）", err)
	}
	if d.Decision != "approve" {
		t.Errorf("落库成功时应返回人工决策 approve，实际 %q", d.Decision)
	}
}
