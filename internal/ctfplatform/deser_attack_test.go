package ctfplatform

// deser_attack_test.go —— 反序列化利用能力机验。
//
// 三组：
//   1. TestDeserPayloadsOffline   —— payload 构造正确性（PHP 长度字段自校验）
//   2. TestDeserAttackAgainstRange —— 真实靶场实战（真 pickle.loads / 真对象注入）
//   3. TestDeserAttackViaProductionText / TestDeserSolverRegistered —— 生产入口 + 反注水门禁
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

type deserBenchProblem struct {
	FlagSHA256  string `json:"flag_sha256"`
	Description string `json:"description"`
}

func loadDeserBenchmark(t *testing.T) map[string]deserBenchProblem {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "deser_benchmark.json"))
	if err != nil {
		t.Skip("deser_benchmark.json 缺失（先跑 deser_range.py --dump-json），跳过")
	}
	var doc struct {
		Problems map[string]deserBenchProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析反序列化基准集失败: %v", err)
	}
	return doc.Problems
}

// deserWaitReady 等靶场端口可服务。
func deserWaitReady(t *testing.T, port string) bool {
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

// TestDeserPayloadsOffline 离线校验：PHP 序列化串的每处长度字段必须与实际一致，
// 否则服务端解析直接失败（这是手写 payload 最常见的低级错误）。
func TestDeserPayloadsOffline(t *testing.T) {
	rePHP := regexp.MustCompile(`^O:(\d+):"([A-Za-z]+)":(\d+):\{s:(\d+):"([^"]*)";s:(\d+):"([^"]*)";\}$`)
	for _, f := range []string{"flag.txt", "/flag", "secret.txt"} {
		for _, s := range deserPHPPayloads(f) {
			m := rePHP.FindStringSubmatch(s)
			if m == nil {
				t.Fatalf("payload 形态不合法: %q", s)
			}
			if m[1] != strconv.Itoa(len(m[2])) {
				t.Fatalf("类名长度字段错误: %q", s)
			}
			if m[4] != strconv.Itoa(len(m[5])) {
				t.Fatalf("属性名长度字段错误: %q", s)
			}
			if m[6] != strconv.Itoa(len(m[7])) {
				t.Fatalf("属性值长度字段错误: %q", s)
			}
			if m[7] != f {
				t.Fatalf("属性值与期望文件不一致: %q != %q", m[7], f)
			}
		}
		// pickle payload 必须携带目标文件且以 STOP 指令结尾
		for _, p := range deserPicklePayloads(f) {
			ps := string(p)
			if !strings.Contains(ps, f) || !strings.HasSuffix(ps, ".") {
				t.Fatalf("pickle payload 不完整: %q", ps)
			}
			// 结构校验：必须以 MARK→TUPLE→REDUCE→STOP 收尾，否则服务端 loads 会失败
			if !strings.HasSuffix(ps, "\ntR.") {
				t.Fatalf("pickle 指令序列不完整（应 tR. 收尾）: %q", ps)
			}
			if strings.Count(ps, "\n(") != 1 {
				t.Fatalf("pickle MARK 指令异常: %q", ps)
			}
		}
	}
	t.Log("✅ PHP 长度字段与 pickle 结构自校验通过")
}

// TestDeserAttackAgainstRange 真实靶场实战：逐场景起靶机，验证真能读到 flag。
func TestDeserAttackAgainstRange(t *testing.T) {
	root := filepath.Join("..", "..")
	rangePy := filepath.Join(root, "data", "ctf_benchmark", "live_target", "deser_range.py")
	if _, err := os.Stat(rangePy); err != nil {
		t.Skip("反序列化靶场脚本缺失，跳过")
	}
	probs := loadDeserBenchmark(t)
	ids := make([]string, 0, len(probs))
	for k := range probs {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	portBase := 18121
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
			if !deserWaitReady(t, port) {
				t.Fatalf("靶场端口 %s 未就绪", port)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			got := AttackDeserialization(ctx, "http://127.0.0.1:"+port, ParseWebHints(probs[id].Description))
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
				t.Logf("✅ %-18s 反序列化利用命中 (SHA-256 校验通过)", id)
			} else {
				t.Logf("❌ %-18s 未命中 (返回 %d 个候选: %v)", id, len(got), got)
			}
		}()
	}
	t.Logf("反序列化靶场实战：%d/%d", hit, len(ids))
	if hit != len(ids) {
		t.Errorf("反序列化基准集未全中：%d/%d", hit, len(ids))
	}
}

// TestDeserAttackViaProductionText 生产入口：题目文本带 URL 时自动触发反序列化利用。
func TestDeserAttackViaProductionText(t *testing.T) {
	root := filepath.Join("..", "..")
	rangePy := filepath.Join(root, "data", "ctf_benchmark", "live_target", "deser_range.py")
	if _, err := os.Stat(rangePy); err != nil {
		t.Skip("反序列化靶场脚本缺失，跳过")
	}
	probs := loadDeserBenchmark(t)
	ids := make([]string, 0, len(probs))
	for k := range probs {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	portBase := 18131
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
			if !deserWaitReady(t, port) {
				t.Fatalf("靶场端口 %s 未就绪", port)
			}
			text := fmt.Sprintf("%s\n目标地址 http://127.0.0.1:%s/", probs[id].Description, port)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			got := deserAttackFromText(ctx, text)
			ok := false
			for _, f := range got {
				if sha256Hex(f) == probs[id].FlagSHA256 {
					ok = true
					break
				}
			}
			if ok {
				hit++
				t.Logf("✅ %-18s 生产入口命中 (SHA-256 校验通过)", id)
			} else {
				t.Logf("❌ %-18s 生产入口未命中", id)
			}
		}()
	}
	t.Logf("生产入口：%d/%d", hit, len(ids))
	if hit != len(ids) {
		t.Errorf("生产入口未全中：%d/%d", hit, len(ids))
	}
}

// TestDeserSolverRegistered 反注水门禁：求解器必须真实注册进生产注册表。
func TestDeserSolverRegistered(t *testing.T) {
	found := false
	all := GetSolvers()
	for _, s := range all {
		if s.Name == "deser_rce" {
			found = true
			if !s.Enabled {
				t.Fatal("deser_rce 注册了但被禁用——等于没接入生产")
			}
		}
	}
	if !found {
		t.Fatal("deser_rce 未注册到注册表（宣称能力但未接线）")
	}
	t.Logf("✅ deser_rce 已注册并启用（注册表共 %d 个求解器）", len(all))
}
