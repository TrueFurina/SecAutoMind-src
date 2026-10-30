package ctfplatform

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// 排行榜快照接线回归（2026-10-28，评估见 docs/evidence/平台接口接线审计与评估_20261028.md）。
//
// 覆盖四条：
//  T1 终报快照：ScoreboardSnapshot=true 时停轮恰好打 1 次（脱离已取消 ctx）；
//  T2 反向对照：默认关 = GetOverview 零调用（第八条「新接线默认关」纪律的机验）；
//  T3 语义倒挂：周期间隔 < PollInterval → 告警 + 间隔清零，但终报快照不连带关；
//  T4 周期快照：间隔到期后按轮打快照（终报额外 +1）。

func newScoreboardTestPoller(fp *fakePlatform, cfg PollerConfig) *Poller {
	solver := func(ctx context.Context, ch *Challenge) ([]string, error) { return nil, nil }
	return NewPoller(fp, solver, cfg, zap.NewNop())
}

func TestScoreboardFinalSnapshotOnStop(t *testing.T) {
	fp := &fakePlatform{}
	cfg := DefaultPollerConfig()
	cfg.ScoreboardSnapshot = true
	p := newScoreboardTestPoller(fp, cfg)

	// 预取消 ctx：RunForever 启动后立刻走 ctx.Done 退出，终报快照必须仍打得出
	// （用脱离的独立超时上下文，而非复用已取消的父 ctx —— 那会瞬间失败）。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.RunForever(ctx); err != context.Canceled {
		t.Fatalf("期望返回 context.Canceled，实际 %v", err)
	}
	if fp.overviewCalls != 1 {
		t.Fatalf("终报快照应恰好打 1 次，实际 %d", fp.overviewCalls)
	}
}

// TestScoreboardSnapshotWritesLedger 接线断言（2026-10-31）：
// 上面几条只数 GetOverview 调用次数，**删掉 poller 里那行 AppendScoreboard 它们照样绿**。
// 本用例直接断言「快照真的落盘了」，把 wiring 钉死。
func TestScoreboardSnapshotWritesLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.jsonl")
	EnableScoreboardLedger(path)
	defer EnableScoreboardLedger("") // 防污染其它用例

	fp := &fakePlatform{}
	cfg := DefaultPollerConfig()
	cfg.ScoreboardSnapshot = true
	p := newScoreboardTestPoller(fp, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立刻停轮 → 只打终报
	if err := p.RunForever(ctx); err != context.Canceled {
		t.Fatalf("期望 context.Canceled，实际 %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("账本未生成：%v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("终报应恰好 1 行，实际 %d：%q", len(lines), string(raw))
	}
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("账本行不是合法 JSON：%v", err)
	}
	if rec["kind"] != "final" {
		t.Fatalf("kind 应为 final，实际 %v", rec["kind"])
	}
	ov, ok := rec["overview"].(map[string]interface{})
	if !ok || ov["total"] != float64(3) {
		t.Fatalf("overview 未原样落盘：%v", rec["overview"])
	}
}

func TestScoreboardDisabledByDefault(t *testing.T) {
	fp := &fakePlatform{}
	cfg := DefaultPollerConfig() // ScoreboardSnapshot 默认 false
	p := newScoreboardTestPoller(fp, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.RunForever(ctx); err != context.Canceled {
		t.Fatalf("期望返回 context.Canceled，实际 %v", err)
	}
	if fp.overviewCalls != 0 {
		t.Fatalf("默认关闭时 GetOverview 必须零调用（反向对照），实际 %d", fp.overviewCalls)
	}
}

func TestScoreboardIntervalInversionFixedWithWarn(t *testing.T) {
	cfg := DefaultPollerConfig() // PollInterval = 30s
	cfg.ScoreboardSnapshot = true
	cfg.ScoreboardInterval = 5 * time.Second // < PollInterval：语义倒挂

	fixed, warns, err := ValidatePollerConfig(cfg)
	if err != nil {
		t.Fatalf("倒挂不应致命：%v", err)
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "排行榜周期快照间隔非法") {
			found = true
		}
	}
	if !found {
		t.Fatalf("倒挂未告警：%v", warns)
	}
	if fixed.ScoreboardInterval != 0 {
		t.Fatalf("倒挂间隔应清零，实际 %v", fixed.ScoreboardInterval)
	}
	if !fixed.ScoreboardSnapshot {
		t.Fatal("周期快照倒挂不应连带关闭终报快照（收尾只打一次，无平台压力）")
	}
}

func TestScoreboardPeriodicSnapshot(t *testing.T) {
	fp := &fakePlatform{}
	cfg := DefaultPollerConfig()
	cfg.PollInterval = 40 * time.Millisecond
	cfg.ScoreboardSnapshot = true
	cfg.ScoreboardInterval = 50 * time.Millisecond // ≥ PollInterval：合法
	p := newScoreboardTestPoller(fp, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = p.RunForever(ctx) // 超时退出（DeadlineExceeded），终报快照走 defer

	// 300ms / 50ms ≈ 5 次周期 + 1 次终报；留容差防时序抖动，只要求"周期确实在打"。
	if fp.overviewCalls < 3 {
		t.Fatalf("周期快照未按间隔触发（300ms 内应 ≥3 次，实际 %d）", fp.overviewCalls)
	}
}
