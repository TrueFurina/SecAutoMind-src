package ctfplatform

// SSTI 深度机验：反注水注册门禁 + 靶场实战 + 生产入口（SHA-256 逐题校验）。

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

func startSSTIRange(t *testing.T, port int) (cleanup func()) {
	t.Helper()
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python 不在 PATH，跳过靶场实战")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	rang := filepath.Join(root, "data", "ctf_benchmark", "live_target", "ssti_range.py")
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

// TestSSTISolverRegistered 反注水门禁：ssti_eval_escape 必须已注册。
func TestSSTISolverRegistered(t *testing.T) {
	for _, e := range GetSolvers() {
		if e.Name == "ssti_eval_escape" {
			return
		}
	}
	t.Fatal("ssti_eval_escape 求解器未注册")
}

// TestSSTIAttackAgainstRange 靶场实战：三类模板注入真逃逸。
func TestSSTIAttackAgainstRange(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "ssti_benchmark.json"))
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
	port := 18224
	cleanup := startSSTIRange(t, port)
	defer cleanup()
	base := "http://127.0.0.1:" + strconv.Itoa(port)

	hit := 0
	for scene := range bench.Problems {
		hints := ParseWebHints(bench.Problems[scene].Description)
		found := AttackSSTI(context.Background(), base, hints, bench.Problems[scene].Description)
		if shaIn(found, bench.Problems[scene].FlagSHA256) {
			hit++
			t.Logf("✅ %s：SSTI 逃逸命中（%d 候选）", scene, len(found))
		} else {
			t.Errorf("❌ %s：未命中，got=%v", scene, found)
		}
	}
	if hit != 3 {
		t.Errorf("SSTI 实战命中率 %d/3", hit)
	}
}

// TestSSTIAttackViaProductionText 生产入口：题目文本 → 注册表求解器。
func TestSSTIAttackViaProductionText(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "ssti_benchmark.json"))
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
	port := 18225
	cleanup := startSSTIRange(t, port)
	defer cleanup()
	base := "http://127.0.0.1:" + strconv.Itoa(port)

	hit := 0
	for scene := range bench.Problems {
		found := sstiAttackFromText(context.Background(),
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
