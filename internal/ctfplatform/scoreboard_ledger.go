// scoreboard_ledger.go —— 排行榜快照落盘（2026-10-31，羊城杯 0 分复盘的最后一环）。
//
// 为什么需要：
// 2026-10-24 那场**全程没有分数信号**——`ScoreboardSnapshot` 到 10-28 才接线、
// 且默认 false。更关键的是它只 `logger.Info` 打日志，**没有落盘**：
// 赛中看不见（心跳已补），**赛后也查不到**（本文件补）。
// 没有落盘 ⇒ 下一次复盘同样只能靠回忆，等于同样的失败会再来一次。
//
// 设计原则（照抄 supervision_ledger.go）：
//   - **遥测 fail-open**：落盘失败绝不影响解题主路径（仪表坏了不能让车熄火）。
//   - **库级 opt-in**：包级路径默认空 = 不写文件；runner 启动时
//     EnableScoreboardLedger(path) 打开，测试/库调用方零文件副作用。
//   - JSONL 每行一条；默认 logs/scoreboard.jsonl（logs/ 已 gitignore）。
//   - **原样存**：`GetOverview` 返回 `map[string]interface{}`，字段名随平台变化，
//     这里不猜、不重命名、不丢字段——事后怎么解析是读方的事。
package ctfplatform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultScoreboardLedgerPath runner 默认排行榜账本路径（相对工作目录）。
const DefaultScoreboardLedgerPath = "logs" + string(filepath.Separator) + "scoreboard.jsonl"

var (
	scoreboardMu   sync.Mutex
	scoreboardPath string
)

// EnableScoreboardLedger 打开排行榜落盘；传空串即关闭。
// 只设置路径、不预先建文件——第一次真正写入时才落盘（避免空跑也留空文件）。
func EnableScoreboardLedger(path string) {
	scoreboardMu.Lock()
	scoreboardPath = path
	scoreboardMu.Unlock()
}

// ScoreboardPath 返回当前生效路径（测试与自检用）。
func ScoreboardPath() string {
	scoreboardMu.Lock()
	defer scoreboardMu.Unlock()
	return scoreboardPath
}

// AppendScoreboard 追加一条排行榜快照。**fail-open**：任何失败静默返回，
// 绝不向上抛错——排行榜是观测项，不许影响解题主路径。
//
// kind 语义与 poller 一致："periodic"（周期）/ "final"（停轮终报）。
func AppendScoreboard(kind string, overview map[string]interface{}) {
	scoreboardMu.Lock()
	path := scoreboardPath
	scoreboardMu.Unlock()
	if path == "" || overview == nil {
		return
	}

	rec := map[string]interface{}{
		"ts":       time.Now().Format(time.RFC3339),
		"kind":     kind,
		"overview": overview,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return // fail-open
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.Write(append(line, '\n'))
}
