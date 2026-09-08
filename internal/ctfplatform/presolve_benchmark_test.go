package ctfplatform

// presolve_benchmark_test.go —— 权威「真题确定性覆盖」机验。
//
// 与 data/ctf_benchmark/judge.py(judge_exec.py) 互为独立校验：Go 侧直接调用
// 实际 shipping 代码路径，报告 SHA-256 校验通过的确定性命中数。
//
// 两个路径对照：
//   1. TestRealBenchmark_ShippedPresolve  —— 调用 integrator 实际使用的硬编码
//      Presolve（即生产路径），测「当前 exe 真实覆盖」。
//   2. TestRealBenchmark_RegistryPresolve —— 调用注册表驱动的 PresolveWithRegistry
//      （含全部 130+ 注册求解器，含本会话新增的 exec_* 与 rsa_small_e），
//      测「若切到注册表路径能多覆盖多少」。
//
// 两者差异即暴露：注册表里的求解器是否被生产路径真正调用（诚实化纪律要求）。
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type realBenchProblem struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Sub           string `json:"sub"`
	Description   string `json:"description"`
	FlagSHA256    string `json:"flag_sha256"`
	PresolveSkill string `json:"presolve_skill"`
}

func loadRealBenchmark(t *testing.T) map[string]realBenchProblem {
	benchPath := filepath.Join("..", "..", "data", "ctf_benchmark", "real_benchmark.json")
	raw, err := os.ReadFile(benchPath)
	if err != nil {
		t.Skipf("real_benchmark.json 缺失，跳过: %v", err)
	}
	var doc struct {
		Problems map[string]realBenchProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 real_benchmark.json 失败: %v", err)
	}
	return doc.Problems
}

// runRealBenchmark 对全部真题跑指定 presolve 函数，返回 (命中数, 总数, 详情)。
func runRealBenchmark(t *testing.T, fn func(*Challenge) *PresolveResult) (hits int, total int, detail []string) {
	probs := loadRealBenchmark(t)
	total = len(probs)
	ids := make([]string, 0, total)
	for id := range probs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := probs[id]
		res := fn(&Challenge{ID: id, Category: p.Category, Description: p.Description})
		if res != nil && res.Solved && len(res.Flags) > 0 {
			sum := sha256.Sum256([]byte(res.Flags[0]))
			if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
				hits++
				detail = append(detail, "✅ "+id+" engine="+res.Engine)
				continue
			}
		}
		detail = append(detail, "❌ MISS "+id)
	}
	return
}

func TestRealBenchmark_ShippedPresolve(t *testing.T) {
	pr := NewPresolver(nil)
	hits, total, detail := runRealBenchmark(t, func(ch *Challenge) *PresolveResult {
		return pr.Presolve(context.Background(), ch, nil)
	})
	for _, d := range detail {
		if strings.HasPrefix(d, "✅") {
			t.Logf("%s", d)
		}
	}
	t.Logf("=== 生产路径 Presolve 真题覆盖率: %d/%d = %.1f%% ===", hits, total, 100*float64(hits)/float64(total))
	// 机验门禁：生产路径确定性覆盖不得低于 14（历史基线 10/55≈18.2%，
	// 因新增 base64_multilayer/endian/rsa_common_factor 等已落地，基线抬升至 ≥14）。
	if hits < 14 {
		t.Errorf("生产路径确定性覆盖 %d/%d 低于门禁 14", hits, total)
	}
}

func TestRealBenchmark_RegistryPresolve(t *testing.T) {
	pr := NewPresolver(nil)
	hits, total, detail := runRealBenchmark(t, func(ch *Challenge) *PresolveResult {
		return pr.PresolveWithRegistry(context.Background(), ch, nil)
	})
	missed := 0
	for _, d := range detail {
		if strings.HasPrefix(d, "✅") {
			t.Logf("%s", d)
		} else {
			missed++
			t.Logf("%s", d)
		}
	}
	t.Logf("=== 注册表路径 PresolveWithRegistry 真题覆盖率: %d/%d = %.1f%% (MISS %d) ===", hits, total, 100*float64(hits)/float64(total), missed)
}
