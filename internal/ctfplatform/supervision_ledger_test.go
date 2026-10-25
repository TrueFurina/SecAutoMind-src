// supervision_ledger_test.go —— 监督消费率账本回归（听风 2026-10-25）。
//
// 对应 agent_roles_20261025.md 角色 #3 验收项：
// 「监督机制消费率（被采纳的 ABANDON/SWITCH 次数 / 总反思次数）有统计落盘」。
// 门禁三铁律之回归：账本坏（路径不可写/文件半行/文件丢失）必须 fail-open，
// 求解决策绝不能因遥测而变。
package ctfplatform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func intPtr(v int) *int       { return &v }
func floatPtr(v float64) *float64 { return &v }

// abandonState 构造能触发规则⑥的最小状态：零候选+消耗>=60%+步数>=5+token 也>=60%。
func abandonState(challenge string) SupervisionState {
	return SupervisionState{
		BudgetTotal: 10, BudgetUsed: 6,
		Candidates: intPtr(0), TokenRatio: floatPtr(0.7),
		Challenge: challenge,
	}
}

// continueState 构造规则③状态：预算充足+信心中性。
func continueState(challenge string) SupervisionState {
	return SupervisionState{
		BudgetTotal: 12, BudgetUsed: 1,
		Candidates: intPtr(0),
		Challenge:  challenge,
	}
}

func readRecords(t *testing.T, path string) []SupervisionRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读账本失败: %v", err)
	}
	var recs []SupervisionRecord
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			if i > start {
				var rec SupervisionRecord
				if err := json.Unmarshal(data[start:i], &rec); err != nil {
					t.Fatalf("第 %d 条记录解析失败: %v", len(recs)+1, err)
				}
				recs = append(recs, rec)
			}
			start = i + 1
		}
	}
	return recs
}

func TestLedgerDisabledByDefault(t *testing.T) {
	DisableSupervisionLedger() // 确保前序测试没留下全局账本
	dec := ReflectSupervision(continueState("无账本题"), nil, nil)
	if dec.Decision != DecisionContinue {
		t.Fatalf("无账本时决策必须与核心逻辑一致，got %s", dec.Decision)
	}
	// 不 panic / 不产生任何文件副作用即为本测试的隐含断言
}

func TestLedgerRecordsEveryReflection(t *testing.T) {
	DisableSupervisionLedger()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := EnableSupervisionLedger(path); err != nil {
		t.Fatalf("启用账本失败: %v", err)
	}
	t.Cleanup(DisableSupervisionLedger)

	// 1×CONTINUE（规则③）+ 1×ABANDON（规则⑥）
	if dec := ReflectSupervision(continueState("题A"), nil, nil); dec.Decision != DecisionContinue {
		t.Fatalf("题A 应 CONTINUE，got %s", dec.Decision)
	}
	if dec := ReflectSupervision(abandonState("题B"), nil, nil); dec.Decision != DecisionAbandon {
		t.Fatalf("题B 应 ABANDON，got %s", dec.Decision)
	}

	recs := readRecords(t, path)
	if len(recs) != 2 {
		t.Fatalf("应落盘 2 条，got %d", len(recs))
	}
	if recs[0].Challenge != "题A" || recs[0].Decision != DecisionContinue {
		t.Fatalf("记录0 内容不符: %+v", recs[0])
	}
	if recs[1].Challenge != "题B" || recs[1].Decision != DecisionAbandon {
		t.Fatalf("记录1 内容不符: %+v", recs[1])
	}
	// 遥测快照必须带判定依据（消费率审计时能回答「为什么 ABANDON」）
	if recs[1].TokenRatio == nil || *recs[1].TokenRatio < 0.6 {
		t.Fatalf("ABANDON 记录必须带 token_ratio 快照: %+v", recs[1])
	}
	if recs[1].Candidates == nil || *recs[1].Candidates != 0 {
		t.Fatalf("ABANDON 记录必须带候选快照: %+v", recs[1])
	}
	if recs[0].TS == "" {
		t.Fatalf("记录必须带时间戳")
	}
}

func TestConsumptionRateMath(t *testing.T) {
	DisableSupervisionLedger()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := EnableSupervisionLedger(path); err != nil {
		t.Fatalf("启用账本失败: %v", err)
	}
	t.Cleanup(DisableSupervisionLedger)

	// 2 CONTINUE + 1 ABANDON → 消费率 1/3
	_ = ReflectSupervision(continueState("c1"), nil, nil)
	_ = ReflectSupervision(continueState("c2"), nil, nil)
	_ = ReflectSupervision(abandonState("a1"), nil, nil)

	stats, err := SummarizeSupervisionLedger(path)
	if err != nil {
		t.Fatalf("汇总失败: %v", err)
	}
	if stats.Total != 3 {
		t.Fatalf("total 应为 3，got %d", stats.Total)
	}
	if stats.ByDecision[DecisionContinue] != 2 || stats.ByDecision[DecisionAbandon] != 1 {
		t.Fatalf("by_decision 不符: %+v", stats.ByDecision)
	}
	want := 1.0 / 3.0
	if diff := stats.ConsumptionRate - want; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("消费率应为 %.4f，got %.4f", want, stats.ConsumptionRate)
	}
}

func TestSummarizeMissingFileIsEmptyNotError(t *testing.T) {
	stats, err := SummarizeSupervisionLedger(filepath.Join(t.TempDir(), "不存在.jsonl"))
	if err != nil {
		t.Fatalf("文件不存在必须是空统计而非错误: %v", err)
	}
	if stats.Total != 0 || stats.ConsumptionRate != 0 {
		t.Fatalf("空统计应为零值: %+v", stats)
	}
}

func TestLedgerFailOpenOnUnwritablePath(t *testing.T) {
	DisableSupervisionLedger()
	// 路径父级是一个「文件」→ MkdirAll 必失败 → Enable 返回错误
	fileAsDir := filepath.Join(t.TempDir(), "iam-a-file")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnableSupervisionLedger(filepath.Join(fileAsDir, "ledger.jsonl")); err == nil {
		t.Fatalf("指向文件下层的账本必须启用失败（fail-closed on enable）")
	}
	// 启用失败后决策完全不受影响
	if dec := ReflectSupervision(abandonState("fail-open-题"), nil, nil); dec.Decision != DecisionAbandon {
		t.Fatalf("账本启用失败不得影响决策，got %s", dec.Decision)
	}
	DisableSupervisionLedger()
}

func TestLedgerFailOpenOnWriteFailure(t *testing.T) {
	DisableSupervisionLedger()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := EnableSupervisionLedger(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(DisableSupervisionLedger)
	// 模拟写入失败：关闭底层句柄（Windows 不允许替换已打开的文件，
	// 故直接走 Close→ErrClosed 分支，与磁盘写失败同属 Append 报错路径）
	supLedgerMu.RLock()
	l := supLedger
	supLedgerMu.RUnlock()
	if l == nil {
		t.Fatal("账本应已启用")
	}
	_ = l.Close() //nolint:errcheck
	if dec := ReflectSupervision(abandonState("写失败题"), nil, nil); dec.Decision != DecisionAbandon {
		t.Fatalf("落盘失败不得影响决策（fail-open），got %s", dec.Decision)
	}
	if dec := ReflectSupervision(continueState("写失败题2"), nil, nil); dec.Decision != DecisionContinue {
		t.Fatalf("落盘失败不得影响决策（fail-open），got %s", dec.Decision)
	}
}

func TestSummarizeSkipsCorruptLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	valid := `{"ts":"2026-10-25T02:00:00Z","challenge":"ok","decision":"ABANDON","reason":"r","budget_ratio":0.6,"confidence":0.5,"progress_in_window":0,"trailing_no_progress":3}`
	content := "这不是JSON\n" + valid + "\n{\"decision\":\n" + valid + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	stats, err := SummarizeSupervisionLedger(path)
	if err != nil {
		t.Fatalf("坏行不应使汇总报错: %v", err)
	}
	if stats.Total != 2 {
		t.Fatalf("坏行应被跳过，只计有效 2 条，got %d", stats.Total)
	}
	if stats.ConsumptionRate != 1.0 {
		t.Fatalf("2×ABANDON 消费率应为 1.0，got %.4f", stats.ConsumptionRate)
	}
}

func TestLedgerConcurrentAppends(t *testing.T) {
	DisableSupervisionLedger()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := EnableSupervisionLedger(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(DisableSupervisionLedger)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = ReflectSupervision(continueState("并发题"), nil, nil) //nolint:errcheck // 并发下决策恒 CONTINUE
		}(i)
	}
	wg.Wait()
	stats, err := SummarizeSupervisionLedger(path)
	if err != nil {
		t.Fatalf("汇总失败: %v", err)
	}
	if stats.Total != n {
		t.Fatalf("并发 %d 次应落盘 %d 条不丢不重，got %d", n, n, stats.Total)
	}
}
