package ctfplatform

// SSRF 机验：反注水注册门禁 + 靶场实战 + 生产入口（SHA-256 逐题校验）。

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

func startSSRFRange(t *testing.T, port int) (cleanup func()) {
	t.Helper()
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python 不在 PATH，跳过靶场实战")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	rang := filepath.Join(root, "data", "ctf_benchmark", "live_target", "ssrf_range.py")
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

// TestSSRFSolverRegistered 反注水门禁：ssrf_redis_rce 必须已注册。
func TestSSRFSolverRegistered(t *testing.T) {
	for _, e := range GetSolvers() {
		if e.Name == "ssrf_redis_rce" {
			return
		}
	}
	t.Fatal("ssrf_redis_rce 求解器未注册")
}

// TestSSRFAttackAgainstRange 靶场实战：三场景真利用。
func TestSSRFAttackAgainstRange(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "ssrf_benchmark.json"))
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
	port := 18220
	cleanup := startSSRFRange(t, port)
	defer cleanup()
	base := "http://127.0.0.1:" + strconv.Itoa(port)

	hit := 0
	for scene := range bench.Problems {
		hints := ParseWebHints(bench.Problems[scene].Description)
		found := AttackSSRF(context.Background(), base, hints)
		for _, f := range found {
			if uploadFlagSHA(f) == bench.Problems[scene].FlagSHA256 {
				hit++
				t.Logf("✅ %s：SSRF 链命中（%d 候选）", scene, len(found))
				break
			}
		}
		if hit == 0 || !shaIn(found, bench.Problems[scene].FlagSHA256) {
			// 单场景失败记录（最终 hit 汇总判定）
			if !shaIn(found, bench.Problems[scene].FlagSHA256) {
				t.Errorf("❌ %s：未命中，got=%v", scene, found)
			}
		}
	}
	if hit != 3 {
		t.Errorf("SSRF 实战命中率 %d/3", hit)
	}
}

// TestSSRFAttackViaProductionText 生产入口：题目文本 → 注册表求解器。
func TestSSRFAttackViaProductionText(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "ssrf_benchmark.json"))
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
	port := 18221
	cleanup := startSSRFRange(t, port)
	defer cleanup()
	base := "http://127.0.0.1:" + strconv.Itoa(port)

	hit := 0
	for scene := range bench.Problems {
		found := ssrfAttackFromText(context.Background(),
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

// shaIn 判断候选里是否有目标 SHA。
func shaIn(found []string, want string) bool {
	for _, f := range found {
		if uploadFlagSHA(f) == want {
			return true
		}
	}
	return false
}
