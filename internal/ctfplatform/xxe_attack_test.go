package ctfplatform

// xxe_attack_test.go —— XXE 利用能力机验。
//
// 三组：离线 payload 结构校验 / 真实靶场实战 / 生产入口 + 反注水门禁。
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type xxeBenchProblem struct {
	FlagSHA256  string `json:"flag_sha256"`
	Description string `json:"description"`
}

func loadXXEBenchmark(t *testing.T) map[string]xxeBenchProblem {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "xxe_benchmark.json"))
	if err != nil {
		t.Skip("xxe_benchmark.json 缺失（先跑 xxe_range.py --dump-json），跳过")
	}
	var doc struct {
		Problems map[string]xxeBenchProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 XXE 基准集失败: %v", err)
	}
	return doc.Problems
}

func xxeWaitReady(t *testing.T, port string) bool {
	t.Helper()
	for i := 0; i < 100; i++ {
		resp, err := http.Get("http://127.0.0.1:" + port + "/")
		if err == nil {
			resp.Body.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// TestXXEPayloadsOffline 离线校验：payload 必须是合法 XML 骨架且带目标文件。
func TestXXEPayloadsOffline(t *testing.T) {
	reEntity := regexp.MustCompile(`<!ENTITY xxe SYSTEM "([^"]+)">`)
	reInclude := regexp.MustCompile(`<xi:include href="([^"]+)" parse="text"/>`)
	for _, f := range []string{"flag.txt", "/flag", "secret.txt"} {
		ref := string(xxeReflectedPayload(f))
		if !strings.Contains(ref, `<!DOCTYPE r [`) || !strings.Contains(ref, "&xxe;") {
			t.Fatalf("回显型 payload 缺少 DOCTYPE/实体引用: %q", ref)
		}
		m := reEntity.FindStringSubmatch(ref)
		if m == nil || m[1] != f {
			t.Fatalf("回显型 payload 实体声明错误: %q", ref)
		}
		inc := string(xxeXIncludePayload(f))
		mi := reInclude.FindStringSubmatch(inc)
		if mi == nil || mi[1] != f {
			t.Fatalf("XInclude payload 错误: %q", inc)
		}
		oob := string(xxeOOBPayload("http://127.0.0.1:9", f))
		if !strings.Contains(oob, `<!ENTITY % file SYSTEM "`+f+`">`) ||
			!strings.Contains(oob, "http://127.0.0.1:9/oob?d=%file;") {
			t.Fatalf("OOB payload 错误: %q", oob)
		}
	}
	t.Log("✅ XXE 三型 payload 结构自校验通过")
}

// TestXXEAttackAgainstRange 真实靶场实战：逐场景起靶机，验证真能读到/带出 flag。
func TestXXEAttackAgainstRange(t *testing.T) {
	root := filepath.Join("..", "..")
	rangePy := filepath.Join(root, "data", "ctf_benchmark", "live_target", "xxe_range.py")
	if _, err := os.Stat(rangePy); err != nil {
		t.Skip("XXE 靶场脚本缺失，跳过")
	}
	probs := loadXXEBenchmark(t)
	ids := make([]string, 0, len(probs))
	for k := range probs {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	portBase := 18171
	hit := 0
	for i, id := range ids {
		port := strconv.Itoa(portBase + i)
		cmd := exec.Command("python", rangePy, port, id)
		if err := cmd.Start(); err != nil {
			t.Fatalf("启动靶场失败: %v", err)
		}
		func() {
			defer func() {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			}()
			if !xxeWaitReady(t, port) {
				t.Fatalf("靶场端口 %s 未就绪", port)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			got := AttackXXE(ctx, "http://127.0.0.1:"+port, ParseWebHints(probs[id].Description))
			want := probs[id].FlagSHA256
			ok := false
			for _, f := range got {
				if sha256Hex(f) == want {
					ok = true
					break
				}
			}
			if ok {
				hit++
				t.Logf("✅ %-14s XXE 利用命中 (SHA-256 校验通过)", id)
			} else {
				t.Logf("❌ %-14s 未命中 (返回 %d 个候选: %v)", id, len(got), got)
			}
		}()
	}
	t.Logf("XXE 靶场实战：%d/%d", hit, len(ids))
	if hit != len(ids) {
		t.Errorf("XXE 基准集未全中：%d/%d", hit, len(ids))
	}
}

// TestXXEAttackViaProductionText 生产入口：题目文本带 URL 时自动触发 XXE 利用。
func TestXXEAttackViaProductionText(t *testing.T) {
	root := filepath.Join("..", "..")
	rangePy := filepath.Join(root, "data", "ctf_benchmark", "live_target", "xxe_range.py")
	if _, err := os.Stat(rangePy); err != nil {
		t.Skip("XXE 靶场脚本缺失，跳过")
	}
	probs := loadXXEBenchmark(t)
	ids := make([]string, 0, len(probs))
	for k := range probs {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	portBase := 18181
	hit := 0
	for i, id := range ids {
		port := strconv.Itoa(portBase + i)
		cmd := exec.Command("python", rangePy, port, id)
		if err := cmd.Start(); err != nil {
			t.Fatalf("启动靶场失败: %v", err)
		}
		func() {
			defer func() {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			}()
			if !xxeWaitReady(t, port) {
				t.Fatalf("靶场端口 %s 未就绪", port)
			}
			text := fmt.Sprintf("%s\n目标地址 http://127.0.0.1:%s/", probs[id].Description, port)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			got := xxeAttackFromText(ctx, text)
			ok := false
			for _, f := range got {
				if sha256Hex(f) == probs[id].FlagSHA256 {
					ok = true
					break
				}
			}
			if ok {
				hit++
				t.Logf("✅ %-14s 生产入口命中 (SHA-256 校验通过)", id)
			} else {
				t.Logf("❌ %-14s 生产入口未命中", id)
			}
		}()
	}
	t.Logf("生产入口：%d/%d", hit, len(ids))
	if hit != len(ids) {
		t.Errorf("生产入口未全中：%d/%d", hit, len(ids))
	}
}

// TestXXESolverRegistered 反注水门禁：求解器必须真实注册进生产注册表。
func TestXXESolverRegistered(t *testing.T) {
	found := false
	all := GetSolvers()
	for _, s := range all {
		if s.Name == "xxe_file_read" {
			found = true
			if !s.Enabled {
				t.Fatal("xxe_file_read 注册了但被禁用——等于没接入生产")
			}
		}
	}
	if !found {
		t.Fatal("xxe_file_read 未注册到注册表（宣称能力但未接线）")
	}
	t.Logf("✅ xxe_file_read 已注册并启用（注册表共 %d 个求解器）", len(all))
}
