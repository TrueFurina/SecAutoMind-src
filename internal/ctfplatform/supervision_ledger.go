// supervision_ledger.go —— 监督消费率统计落盘（听风 2026-10-25 第一刀）。
//
// 验收口径（docs/specs/agent_roles_20261025.md 角色 #3）：
// 「监督机制消费率（被采纳的 ABANDON/SWITCH 次数 / 总反思次数）有统计落盘」。
//
// 设计原则：
//   - 遥测 fail-open：落盘失败绝不影响求解决策本身（门禁才 fail-closed；
//     仪表坏了不能让车熄火——错误分类散落导致单题 111K token 零烧的教训
//     属于决策路径，与本账本无关）。
//   - 库级 opt-in：包级账本默认 nil，测试/库调用方零文件副作用；
//     runner 启动时 EnableSupervisionLedger(path) 打开。
//   - JSONL 每行一条；默认路径 logs/supervision_ledger.jsonl（已 gitignore）。
package ctfplatform

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SupervisionRecord 一次反思的落盘条目。
type SupervisionRecord struct {
	TS                 string   `json:"ts"`
	Challenge          string   `json:"challenge"`
	Decision           string   `json:"decision"`
	Reason             string   `json:"reason"`
	BudgetRatio        float64  `json:"budget_ratio"`
	Confidence         float64  `json:"confidence"`
	Candidates         *int     `json:"candidates"`
	TokenRatio         *float64 `json:"token_ratio"`
	ProgressInWindow   int      `json:"progress_in_window"`
	TrailingNoProgress int      `json:"trailing_no_progress"`
}

// DefaultSupervisionLedgerPath runner 默认账本路径（相对 runner 工作目录）。
const DefaultSupervisionLedgerPath = "logs" + string(filepath.Separator) + "supervision_ledger.jsonl"

// SupervisionLedger JSONL 追加式账本（goroutine-safe）。
type SupervisionLedger struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// NewSupervisionLedger 打开（追加）账本文件；目录不存在则尝试创建。
func NewSupervisionLedger(path string) (*SupervisionLedger, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &SupervisionLedger{path: path, f: f}, nil
}

// Path 返回账本文件路径。
func (l *SupervisionLedger) Path() string { return l.path }

// Append 追加一条记录。写失败返回错误，由调用方吞掉（遥测 fail-open）。
func (l *SupervisionLedger) Append(rec SupervisionRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return os.ErrClosed
	}
	_, err = l.f.Write(b)
	return err
}

// Close 关闭账本文件（幂等）。
func (l *SupervisionLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// SupervisionStats 消费率汇总。
type SupervisionStats struct {
	Total      int            `json:"total"`
	ByDecision map[string]int `json:"by_decision"`
	// ConsumptionRate 消费率 = (ABANDON+SWITCH) / Total。
	// 操作性定义：本实现中产出的 ABANDON/SWITCH 由 runner 直接执行
	// （短路收口/标记换策略），产出即采纳；CONTINUE 无动作故不计。
	ConsumptionRate float64 `json:"consumption_rate"`
}

// SummarizeSupervisionLedger 读取账本文件汇总消费率。
// 文件不存在返回空统计（非错误）——没跑过 ≠ 跑过且全 CONTINUE，两者都诚实呈现为 0。
func SummarizeSupervisionLedger(path string) (SupervisionStats, error) {
	stats := SupervisionStats{ByDecision: map[string]int{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return stats, nil
		}
		return stats, err
	}
	defer f.Close() //nolint:errcheck
	sc := bufio.NewScanner(f)
	// 防超长行打爆内存：单行 1MB 上限足够（单条记录 <1KB）
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec SupervisionRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // 坏行跳过（半写崩溃行），不让一条脏数据毁掉全部统计
		}
		stats.Total++
		stats.ByDecision[rec.Decision]++
	}
	if err := sc.Err(); err != nil {
		return stats, err
	}
	stats.ConsumptionRate = consumptionRate(stats.ByDecision, stats.Total)
	return stats, nil
}

func consumptionRate(byDecision map[string]int, total int) float64 {
	if total <= 0 {
		return 0
	}
	acted := byDecision[DecisionAbandon] + byDecision[DecisionSwitch]
	return float64(acted) / float64(total)
}

// ── 包级默认账本（opt-in，ReflectSupervision 自动落盘） ─────────────

var (
	supLedgerMu sync.RWMutex
	supLedger   *SupervisionLedger
)

// EnableSupervisionLedger 打开包级账本；此后每次 ReflectSupervision 落盘一条。
// 打开失败返回错误且不改变既有状态（调用方决定降级方式）。
func EnableSupervisionLedger(path string) error {
	l, err := NewSupervisionLedger(path)
	if err != nil {
		return err
	}
	supLedgerMu.Lock()
	defer supLedgerMu.Unlock()
	if supLedger != nil {
		_ = supLedger.Close() //nolint:errcheck // 换路径时旧句柄尽力关闭
	}
	supLedger = l
	return nil
}

// DisableSupervisionLedger 关闭并摘除包级账本（测试收尾用）。
func DisableSupervisionLedger() {
	supLedgerMu.Lock()
	defer supLedgerMu.Unlock()
	if supLedger != nil {
		_ = supLedger.Close() //nolint:errcheck
	}
	supLedger = nil
}

// recordSupervision ReflectSupervision 的遥测钩子：best-effort，永不影响决策。
func recordSupervision(state SupervisionState, dec SupervisionDecision) {
	supLedgerMu.RLock()
	l := supLedger
	supLedgerMu.RUnlock()
	if l == nil {
		return
	}
	rec := SupervisionRecord{
		TS:        time.Now().UTC().Format(time.RFC3339),
		Challenge: state.Challenge,
		Decision:  dec.Decision,
		Reason:    dec.Reason,
	}
	// 从 metrics 安全取数（键缺失/类型不符 → 零值，遥测不撒谎也不崩）
	if v, ok := dec.Metrics["budget_ratio"].(float64); ok {
		rec.BudgetRatio = v
	}
	if v, ok := dec.Metrics["confidence"].(float64); ok {
		rec.Confidence = v
	}
	if v, ok := dec.Metrics["candidates_found"].(*int); ok {
		rec.Candidates = v
	}
	if v, ok := dec.Metrics["token_ratio"].(*float64); ok {
		rec.TokenRatio = v
	}
	if v, ok := dec.Metrics["progress_in_window"].(int); ok {
		rec.ProgressInWindow = v
	}
	if v, ok := dec.Metrics["trailing_no_progress"].(int); ok {
		rec.TrailingNoProgress = v
	}
	_ = l.Append(rec) //nolint:errcheck // fail-open：遥测失败不影响求解
}
