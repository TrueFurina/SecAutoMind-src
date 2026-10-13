package handler

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// HITL 失效边界（规划 §4.2）—— 确定性失效模式回归测试
//
// 背景：HITL 是「决策逻辑与可解释性」评分维的直接回应，也是 9-12 标记的
// 「唯一真正可随机化的子研究」。§4.2 的失效模式矩阵含 5 类，其中
// false-approve / false-block 依赖外部导师 randomized 评测（本测试无法覆盖，
// 见 docs/hitl_failure_boundary.md 中标为 OPEN 的两项），但其余**确定性**模式
// 必须由代码侧锁死 —— 否则「人机可控」只是措辞，无法自证拦截。
//
// 本文件覆盖 3 个确定性模式（超时挂死 / 落库失败已由 hitl_failclosed_test.go 覆盖，不重复）：
//   A. 覆盖冲突：重复裁决 / 双击 / 多人并发 → **first-writer-wins**，
//      第二个决策必须被拒，首个决策不得被后到者翻盘。
//   B. 越界裁决：不存在的中断 / 非法决策值 → 必须明确报错，不得静默接受。
//   C. 参数篡改：非 review_edit 模式下的 editedArguments → 必须剥离，
//      否则「审批」会被偷换成「改参后直接放行」（对高危工具即提权）。
// ---------------------------------------------------------------------------

// A1. 覆盖冲突：同一中断的第二个裁决必须被拒绝，且首个决策不被覆盖。
func TestHITLResolveInterrupt_RejectsSecondDecision(t *testing.T) {
	m := NewHITLManager(nil, zap.NewNop())
	p := newPending("itm-race", "approval")
	m.pending[p.InterruptID] = p

	if err := m.ResolveInterrupt(p.InterruptID, "approve", "first", nil); err != nil {
		t.Fatalf("首个裁决应被接受，实际错误: %v", err)
	}
	// 第二个裁决（相反结论）：必须是错误，绝不能覆盖首个已受理的决策。
	if err := m.ResolveInterrupt(p.InterruptID, "reject", "second", nil); err == nil {
		t.Fatal("第二个裁决必须被拒绝（first-writer-wins），实际却成功覆盖 —— 人工拦截可被后到者翻盘")
	}
	select {
	case d := <-p.decideCh:
		if d.Decision != "approve" {
			t.Fatalf("通道内应保留首个决策 approve，实际 %q（首决策被覆盖）", d.Decision)
		}
	default:
		t.Fatal("通道内应存在首个决策")
	}
}

// A2. 覆盖冲突反向对照：首个决策已被消费、中断已从 pending 移除后，
// 迟到裁决必须报「not found」，而不是被再次放行 —— 中断不得复活。
func TestHITLResolveInterrupt_RejectsAfterResolved(t *testing.T) {
	m := NewHITLManager(nil, zap.NewNop())
	p := newPending("itm-resolved", "approval")
	m.pending[p.InterruptID] = p

	if err := m.ResolveInterrupt(p.InterruptID, "reject", "first", nil); err != nil {
		t.Fatalf("首个裁决应被接受，实际错误: %v", err)
	}
	// 模拟 waitDecision 的正常收尾：消费决策并从 pending 移除。
	<-p.decideCh
	m.mu.Lock()
	delete(m.pending, p.InterruptID)
	m.mu.Unlock()

	if err := m.ResolveInterrupt(p.InterruptID, "approve", "late", nil); err == nil {
		t.Fatal("中断已解除后，迟到裁决必须被拒绝（不得复活已定案的中断）")
	}
}

// B1. 越界裁决：不存在的中断 ID 必须报错（不接受幽灵裁决）。
func TestHITLResolveInterrupt_RejectsUnknownInterrupt(t *testing.T) {
	m := NewHITLManager(nil, zap.NewNop())
	if err := m.ResolveInterrupt("itm-ghost", "approve", "", nil); err == nil {
		t.Fatal("不存在的中断必须报错，不得静默接受")
	}
}

// B2. 越界裁决：非法决策值必须报错（只有 approve/reject 合法）。
func TestHITLResolveInterrupt_RejectsInvalidDecision(t *testing.T) {
	m := NewHITLManager(nil, zap.NewNop())
	p := newPending("itm-invalid", "approval")
	m.pending[p.InterruptID] = p
	// 注意：这些值经 ToLower/TrimSpace 归一化后仍非法，故必须被拒。
	// （"APPROVE" 会被归一化为合法值，故意不列入。）
	for _, bad := range []string{"", "maybe", "approve now", "pass", "1", "yes"} {
		if err := m.ResolveInterrupt(p.InterruptID, bad, "", nil); err == nil {
			t.Fatalf("非法决策值 %q 必须被拒绝，实际被接受", bad)
		}
	}
	// 反向对照：合法值必须被接受，否则「防越界」会被修成「永远拒绝」。
	if err := m.ResolveInterrupt(p.InterruptID, "Approve", "", nil); err != nil {
		t.Fatalf("合法决策值 Approve（归一化为 approve）应被接受，实际错误: %v", err)
	}
}

// C. 参数篡改：非 review_edit 模式必须剥离 editedArguments。
//
//	没有这条防线，审批者可以在 approve 的同时改写工具参数 —— 等于绕过审批。
func TestHITLWaitDecision_StripsEditedArgsOutsideReviewEdit(t *testing.T) {
	const id = "itm-strip"
	m := NewHITLManager(newOKDB(t, id), zap.NewNop())
	p := newPending(id, "approval") // approval ≠ review_edit
	p.decideCh <- hitlDecision{
		Decision:        "approve",
		Comment:         "ok",
		EditedArguments: map[string]interface{}{"cmd": "rm -rf /"},
	}
	d, err := m.waitDecision(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("waitDecision 出错: %v", err)
	}
	if len(d.EditedArguments) != 0 {
		t.Fatalf("非 review_edit 模式下 editedArguments 必须被剥离，实际残留 %v", d.EditedArguments)
	}
}

// C 反向对照：review_edit 模式必须保留 editedArguments（否则该模式形同虚设）。
func TestHITLWaitDecision_KeepsEditedArgsInReviewEdit(t *testing.T) {
	const id = "itm-keep"
	m := NewHITLManager(newOKDB(t, id), zap.NewNop())
	p := newPending(id, "review_edit")
	p.decideCh <- hitlDecision{
		Decision:        "approve",
		Comment:         "ok",
		EditedArguments: map[string]interface{}{"cmd": "ls -la"},
	}
	d, err := m.waitDecision(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("waitDecision 出错: %v", err)
	}
	if len(d.EditedArguments) == 0 {
		t.Fatal("review_edit 模式下 editedArguments 必须保留，实际被剥离（该模式形同虚设）")
	}
}

// D. 超时挂死：审批未在超时窗口内到达 → **自动拒绝**（fail-safe）。
//
//	这是「挂死」模式的核心语义：无人在场时，高危操作绝不能因"没人否决"而被放行。
//	注意与 hitl_failclosed_test.go 的 Timeout 用例区分：那条测的是「超时 + 落库失败」，
//	本条测的是「超时 + 落库正常」——必须真的返回 reject 决策，而非仅报错。
func TestHITLWaitDecision_TimeoutAutoRejects(t *testing.T) {
	const id = "itm-timeout-reject"
	m := NewHITLManager(newOKDB(t, id), zap.NewNop())
	p := newPending(id, "approval") // decideCh 无发送者 → 必走超时分支

	d, err := m.waitDecision(context.Background(), p, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("落库正常的超时分支应返回 reject 决策而非错误，实际: %v", err)
	}
	if d.Decision != "reject" {
		t.Fatalf("审批超时必须自动拒绝（fail-safe），实际 decision=%q（超时被放行=挂死即提权）", d.Decision)
	}
}
