package app

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secautomind-ai/internal/c2"
	"secautomind-ai/internal/database"

	_ "github.com/glebarez/go-sqlite"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// C2 危险任务 HITL 桥的失效边界（补 docs/hitl_failure_boundary.md §5 自曝的覆盖缺口）
//
// 主路径（internal/handler 的 waitDecision / ResolveInterrupt）已有回归测试；
// 本文件锁 C2 桥（c2_hitl_bridge.go RequestApproval）在同两个模式上的语义：
//   ① 落库失败 → fail-closed 拒绝执行（不得返回 nil 放行）
//   ② 审批超时 → 自动拒绝（fail-safe，并留 status='timeout'/decision='reject' 审计痕迹）
// C2 桥用于「危险任务」审批，静默放行的后果比普通工具更重，故单独加锁。
// ---------------------------------------------------------------------------

// closedDB 返回已关闭的 DB，任何 Exec 都会失败（复用「落库失败」最小构造）。
func closedDB(t *testing.T) *database.DB {
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

// c2HITLTestDB 建一张**最小** hitl_interrupts 表（仅含 C2 桥 INSERT/UPDATE 触及的字段），
// 依赖 EnsureSchema 的完整 schema 只会让测试被 schema 变更拖挂。
func c2HITLTestDB(t *testing.T) *database.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "c2-hitl.db"))
	if err != nil {
		t.Fatalf("打开 sqlite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Exec(`CREATE TABLE hitl_interrupts (
		id TEXT PRIMARY KEY,
		conversation_id TEXT,
		message_id TEXT,
		mode TEXT,
		tool_name TEXT,
		tool_call_id TEXT,
		payload TEXT,
		status TEXT,
		decision TEXT,
		decision_comment TEXT,
		created_at DATETIME,
		decided_at DATETIME
	)`); err != nil {
		t.Fatalf("建最小 hitl_interrupts 表失败: %v", err)
	}
	return &database.DB{DB: raw}
}

// ① 落库失败 → fail-closed 拒绝执行。
func TestC2HITLBridge_FailsClosedWhenPersistFails(t *testing.T) {
	b := NewC2HITLBridge(closedDB(t), zap.NewNop())

	err := b.RequestApproval(context.Background(), c2.HITLApprovalRequest{
		TaskID: "t-1", SessionID: "s-1", TaskType: "exec",
	})
	if err == nil {
		t.Fatal("审批记录落库失败必须 fail-closed 拒绝执行，实际返回 nil —— 危险任务被静默放行")
	}
	if !strings.Contains(err.Error(), "拒绝执行") {
		t.Fatalf("错误信息应标明已拒绝执行以便排障，实际: %v", err)
	}
}

// ② 审批超时 → 自动拒绝（fail-safe），审计留痕 status='timeout'/decision='reject'。
func TestC2HITLBridge_TimeoutAutoRejects(t *testing.T) {
	db := c2HITLTestDB(t)
	b := NewC2HITLBridge(db, zap.NewNop())
	b.SetTimeout(10 * time.Millisecond) // 无人工介入 → 必走超时分支

	err := b.RequestApproval(context.Background(), c2.HITLApprovalRequest{
		TaskID: "t-2", SessionID: "s-2", TaskType: "persist",
	})
	if err == nil {
		t.Fatal("审批超时必须自动拒绝，实际返回 nil —— 无人审批即放行（挂死即提权）")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Fatalf("错误信息应标明超时，实际: %v", err)
	}
	var status, decision string
	if qerr := db.QueryRow(
		`SELECT status, COALESCE(decision, '') FROM hitl_interrupts LIMIT 1`).Scan(&status, &decision); qerr != nil {
		t.Fatalf("查询审批记录失败: %v", qerr)
	}
	if status != "timeout" || decision != "reject" {
		t.Fatalf("超时后审计记录应为 status=timeout / decision=reject，实际 %s/%s", status, decision)
	}
}
