package ctfplatform

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestScoreboardLedgerDisabledByDefault 库级 opt-in：未启用时不得产生任何文件副作用。
func TestScoreboardLedgerDisabledByDefault(t *testing.T) {
	EnableScoreboardLedger("") // 显式关（防止其它用例污染）
	dir := t.TempDir()
	path := filepath.Join(dir, "scoreboard.jsonl")

	AppendScoreboard("periodic", map[string]interface{}{"score": 1})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("未启用却产生了文件：%s", path)
	}
	if got := ScoreboardPath(); got != "" {
		t.Fatalf("ScoreboardPath 应为空，得到 %q", got)
	}
}

// TestScoreboardLedgerAppendsJSONL 启用后每行一条合法 JSON，且原样保留 overview。
func TestScoreboardLedgerAppendsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "scoreboard.jsonl")
	EnableScoreboardLedger(path)
	defer EnableScoreboardLedger("")

	AppendScoreboard("periodic", map[string]interface{}{"score": 370.5, "rank": 12})
	AppendScoreboard("final", map[string]interface{}{"score": 500.0})

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("账本未创建：%v", err)
	}
	defer func() { _ = f.Close() }()

	var recs []map[string]interface{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON：%v", len(recs)+1, err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 2 {
		t.Fatalf("应有 2 条记录，实际 %d", len(recs))
	}
	if recs[0]["kind"] != "periodic" || recs[1]["kind"] != "final" {
		t.Fatalf("kind 未保留：%v / %v", recs[0]["kind"], recs[1]["kind"])
	}
	if _, ok := recs[0]["ts"].(string); !ok {
		t.Fatalf("缺 ts 字段：%v", recs[0])
	}
	ov, ok := recs[0]["overview"].(map[string]interface{})
	if !ok || ov["score"] != 370.5 {
		t.Fatalf("overview 未原样保留：%v", recs[0]["overview"])
	}
}

// TestScoreboardLedgerNilOverviewNoop nil 快照不写行（避免灌空记录）。
func TestScoreboardLedgerNilOverviewNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	EnableScoreboardLedger(path)
	defer EnableScoreboardLedger("")

	AppendScoreboard("periodic", nil)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("nil overview 却写了文件")
	}
}

// TestScoreboardLedgerFailOpen 落盘失败必须静默（仪表坏了不能让车熄火）。
func TestScoreboardLedgerFailOpen(t *testing.T) {
	// 把一个普通文件当目录用 → MkdirAll 必失败
	base := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(base, []byte("x"), 0o644); err != nil {
		t.Fatalf("准备失败：%v", err)
	}
	EnableScoreboardLedger(filepath.Join(base, "sub", "scoreboard.jsonl"))
	defer EnableScoreboardLedger("")

	done := make(chan struct{})
	go func() {
		defer close(done)
		AppendScoreboard("periodic", map[string]interface{}{"score": 1}) // 不许 panic
	}()
	<-done
}
