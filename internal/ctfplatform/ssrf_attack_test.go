package ctfplatform

// SSRF 机验：反注水注册门禁 + 靶场实战 + 生产入口（SHA-256 逐题校验）。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// ssrfRuntimePorts 靶场落盘的实际端口（靶场遇端口占用自动避让时非默认值）。
type ssrfRuntimePorts struct {
	BasePort     int `json:"base_port"`
	RedisPort    int `json:"redis_port"`
	InternalPort int `json:"internal_port"`
}

// loadSSRFRuntime 读靶场运行时端口；文件缺失/损坏时回退默认端口。
func loadSSRFRuntime(t *testing.T, basePort int) ssrfRuntimePorts {
	t.Helper()
	def := ssrfRuntimePorts{BasePort: basePort, RedisPort: 6399, InternalPort: 6401}
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark",
		fmt.Sprintf("ssrf_runtime_%d.json", basePort)))
	if err != nil {
		return def
	}
	var rt ssrfRuntimePorts
	if err := json.Unmarshal(doc, &rt); err != nil {
		return def
	}
	if rt.RedisPort == 0 {
		rt.RedisPort = def.RedisPort
	}
	if rt.InternalPort == 0 {
		rt.InternalPort = def.InternalPort
	}
	return rt
}

// applyTo 把运行时端口注入 hints（使 Redis / 回环候选覆盖实际端口）。
func (rt ssrfRuntimePorts) applyTo(hints *WebHints) {
	hints.Types = append(hints.Types,
		fmt.Sprintf("%d 端口", rt.RedisPort),
		fmt.Sprintf("%d 端口", rt.InternalPort))
}

// hintText 运行时端口线索文本（供生产入口测试拼接）。
func (rt ssrfRuntimePorts) hintText() string {
	return fmt.Sprintf("内网 %d 端口 内网 %d 端口", rt.RedisPort, rt.InternalPort)
}

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
	// 清掉上一次的运行时端口文件，避免读到过期端口
	_ = os.Remove(filepath.Join(root, "data", "ctf_benchmark",
		fmt.Sprintf("ssrf_runtime_%d.json", port)))
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
	rt := loadSSRFRuntime(t, port)

	hit := 0
	for scene := range bench.Problems {
		hints := ParseWebHints(bench.Problems[scene].Description)
		ssrfInjectPorts(&hints, bench.Problems[scene].Description)
		rt.applyTo(&hints)
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
	rt := loadSSRFRuntime(t, port)

	hit := 0
	for scene := range bench.Problems {
		found := ssrfAttackFromText(context.Background(),
			bench.Problems[scene].Description+" 靶机: "+base+" "+rt.hintText())
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
