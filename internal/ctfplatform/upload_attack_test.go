package ctfplatform

// 文件上传 RCE 机验：离线 multipart 构造 + 靶场实战 + 生产入口 + 反注水注册门禁。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func uploadFlagSHA(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestUploadSolverRegistered 反注水门禁：upload_rce 必须已注册。
func TestUploadSolverRegistered(t *testing.T) {
	for _, e := range GetSolvers() {
		if e.Name == "upload_rce" {
			return
		}
	}
	t.Fatal("upload_rce 求解器未注册")
}

// TestUploadMultipartBuilder 离线校验：对不可达端点上传必须失败（不假成功）。
func TestUploadMultipartBuilder(t *testing.T) {
	if _, _, ok := uploadMultipart(context.Background(),
		nil, "http://127.0.0.1:1/none", "a.py", "print(1)", ""); ok {
		t.Fatal("对不可达端点上传不应成功")
	}
}

// startUploadRange 启动指定场景的靶场进程并等待就绪。
func startUploadRange(t *testing.T, port int, scene string) (cleanup func()) {
	t.Helper()
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python 不在 PATH，跳过靶场实战")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	rang := filepath.Join(root, "data", "ctf_benchmark", "live_target", "upload_range.py")
	cmd := exec.Command(py, rang, strconv.Itoa(port), scene)
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

// TestUploadAttackAgainstRange 靶场实战：三场景逐一真利用（SHA-256 校验）。
func TestUploadAttackAgainstRange(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "upload_benchmark.json"))
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

	ports := map[string]int{"upload_unrestricted": 18181, "upload_blacklist": 18182, "upload_traversal": 18183}
	hit := 0
	for scene, port := range ports {
		cleanup := startUploadRange(t, port, scene)
		func() {
			defer cleanup()
			cl := webClient(8 * time.Second)
			base := "http://127.0.0.1:" + strconv.Itoa(port)
			found := ExploitUploadTarget(context.Background(), cl, base, WebHints{})
			for _, f := range found {
				if uploadFlagSHA(f) == bench.Problems[scene].FlagSHA256 {
					hit++
					t.Logf("✅ %s：上传 RCE 成功（%d 命中）", scene, len(found))
					return
				}
			}
			t.Errorf("❌ %s：未取回正确 flag，got=%v want_sha=%s", scene, found, bench.Problems[scene].FlagSHA256[:12])
		}()
	}
	if hit != 3 {
		t.Errorf("上传实战命中率 %d/3", hit)
	}
}

// TestUploadAttackViaProductionText 生产入口：题目文本 → 注册表求解器。
func TestUploadAttackViaProductionText(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "upload_benchmark.json"))
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
	ports := map[string]int{"upload_unrestricted": 18184, "upload_blacklist": 18185, "upload_traversal": 18186}
	hit := 0
	for scene, port := range ports {
		cleanup := startUploadRange(t, port, scene)
		func() {
			defer cleanup()
			text := bench.Problems[scene].Description + " 靶机: http://127.0.0.1:" + strconv.Itoa(port)
			found := uploadAttackFromText(context.Background(), text)
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
