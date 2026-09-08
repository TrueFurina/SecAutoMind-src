package ctfplatform

// SQLi 深度机验：反注水注册门禁 + 靶场实战 + 生产入口（SHA-256 逐题校验）。

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func startSQLiRange(t *testing.T, port int) (cleanup func()) {
	t.Helper()
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python 不在 PATH，跳过靶场实战")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	rang := filepath.Join(root, "data", "ctf_benchmark", "live_target", "sqli_range.py")
	cmd := exec.Command(py, rang, strconv.Itoa(port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动靶场失败: %v", err)
	}
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	ready := false
	for i := 0; i < 100; i++ {
		cl := webClient(1 * time.Second)
		if code, _ := httpQuickGet(context.Background(), cl, base+"/"); code == 200 {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		t.Fatalf("靶场未就绪: %s", base)
	}
	return func() { _ = cmd.Process.Kill() }
}

// TestSQLiSolverRegistered 反注水门禁：sqli_extract 必须已注册。
func TestSQLiSolverRegistered(t *testing.T) {
	for _, e := range GetSolvers() {
		if e.Name == "sqli_extract" {
			return
		}
	}
	t.Fatal("sqli_extract 求解器未注册")
}

// TestSQLiAttackAgainstRange 靶场实战：三族注入真提取。
func TestSQLiAttackAgainstRange(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "sqli_benchmark.json"))
	if err != nil {
		t.Skipf("基准集缺失: %v", err)
	}
	var bench struct {
		Problems map[string]struct {
			FlagSHA256  string `json:"flag_sha256"`
			Description string `json:"description"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(doc, &bench); err != nil {
		t.Fatal(err)
	}
	port := 18222
	cleanup := startSQLiRange(t, port)
	defer cleanup()
	base := "http://127.0.0.1:" + strconv.Itoa(port)

	hit := 0
	for scene := range bench.Problems {
		hints := ParseWebHints(bench.Problems[scene].Description)
		found := AttackSQLi(context.Background(), base, hints)
		if shaIn(found, bench.Problems[scene].FlagSHA256) {
			hit++
			t.Logf("✅ %s：SQL 注入命中（%d 候选）", scene, len(found))
		} else {
			t.Errorf("❌ %s：未命中，got=%v", scene, found)
		}
	}
	if hit != 3 {
		t.Errorf("SQLi 实战命中率 %d/3", hit)
	}
}

// TestSQLiAttackViaProductionText 生产入口：题目文本 → 注册表求解器。
func TestSQLiAttackViaProductionText(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "sqli_benchmark.json"))
	if err != nil {
		t.Skipf("基准集缺失: %v", err)
	}
	var bench struct {
		Problems map[string]struct {
			FlagSHA256  string `json:"flag_sha256"`
			Description string `json:"description"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(doc, &bench); err != nil {
		t.Fatal(err)
	}
	port := 18223
	cleanup := startSQLiRange(t, port)
	defer cleanup()
	base := "http://127.0.0.1:" + strconv.Itoa(port)

	hit := 0
	for scene := range bench.Problems {
		found := sqliAttackFromText(context.Background(),
			bench.Problems[scene].Description+" 靶机: "+base)
		if shaIn(found, bench.Problems[scene].FlagSHA256) {
			hit++
			t.Logf("✅ 生产入口 %s 命中", scene)
		} else {
			t.Errorf("❌ 生产入口 %s 未命中，got=%v", scene, found)
		}
	}
	if hit != 3 {
		t.Errorf("生产入口命中率 %d/3", hit)
	}
}
