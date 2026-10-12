package ctfplatform

// GraphQL 机验：反注水注册门禁 + 靶场实战 + 生产入口（SHA-256 逐题校验）。

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

func startGQLRange(t *testing.T, port int, scene string) (cleanup func()) {
	t.Helper()
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python 不在 PATH，跳过靶场实战")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	rang := filepath.Join(root, "data", "ctf_benchmark", "live_target", "gql_range.py")
	cmd := exec.Command(py, rang, strconv.Itoa(port), scene)
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动靶场失败: %v", err)
	}
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	ready := false
	for i := 0; i < 100; i++ {
		cl := webClient(1 * time.Second)
		if code, _ := httpQuickGet(context.Background(), cl, base+"/"); code == 404 || code == 405 || code == 200 {
			// 靶场 GET /graphql 会回 405/404，均说明服务已监听
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

// TestGraphQLSolverRegistered 反注水门禁：graphql_probe 必须已注册。
func TestGraphQLSolverRegistered(t *testing.T) {
	for _, e := range GetSolvers() {
		if e.Name == "graphql_probe" {
			return
		}
	}
	t.Fatal("graphql_probe 求解器未注册")
}

// TestGraphQLAttackAgainstRange 靶场实战：三场景真利用。
func TestGraphQLAttackAgainstRange(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "graphql_benchmark.json"))
	if err != nil {
		t.Skipf("基准集缺失: %v", err)
	}
	var bench struct {
		Problems map[string]struct {
			FlagSHA256 string `json:"flag_sha256"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(doc, &bench); err != nil {
		t.Fatal(err)
	}
	ports := map[string]int{"gql_introspection": 18211, "gql_idor": 18212, "gql_mutation": 18213}
	hit := 0
	for scene, port := range ports {
		cleanup := startGQLRange(t, port, scene)
		func() {
			defer cleanup()
			cl := webClient(8 * time.Second)
			base := "http://127.0.0.1:" + strconv.Itoa(port)
			found := ExploitGraphQLTarget(context.Background(), cl, base, WebHints{})
			for _, f := range found {
				if uploadFlagSHA(f) == bench.Problems[scene].FlagSHA256 {
					hit++
					t.Logf("✅ %s：GraphQL 利用成功（%d 命中）", scene, len(found))
					return
				}
			}
			t.Errorf("❌ %s：未命中，got=%v want_sha=%s", scene, found, bench.Problems[scene].FlagSHA256[:12])
		}()
	}
	if hit != 3 {
		t.Errorf("GraphQL 实战命中率 %d/3", hit)
	}
}

// TestGraphQLAttackViaProductionText 生产入口：题目文本 → 注册表求解器。
func TestGraphQLAttackViaProductionText(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "graphql_benchmark.json"))
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
	ports := map[string]int{"gql_introspection": 18214, "gql_idor": 18215, "gql_mutation": 18216}
	hit := 0
	for scene, port := range ports {
		cleanup := startGQLRange(t, port, scene)
		func() {
			defer cleanup()
			text := bench.Problems[scene].Description + " 靶机: http://127.0.0.1:" + strconv.Itoa(port)
			found := gqlAttackFromText(context.Background(), text)
			for _, f := range found {
				if uploadFlagSHA(f) == bench.Problems[scene].FlagSHA256 {
					hit++
					t.Logf("✅ 生产入口 %s 命中", scene)
					return
				}
			}
			t.Errorf("❌ 生产入口 %s 未命中，got=%v", scene, found)
		}()
	}
	if hit != 3 {
		t.Errorf("生产入口命中率 %d/3", hit)
	}
}
