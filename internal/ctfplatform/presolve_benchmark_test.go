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
//      （含全部注册求解器），测「若切到注册表路径能多覆盖多少」，并机验
//      **shipped ⊆ registry** 不变量（用不变量而非硬编码命中数，能力提升后无需改测试）。
//
// 两者差异即暴露：注册表里的求解器是否被生产路径真正调用（诚实化纪律要求）。
// Go 两路径 + Python judge.py 镜像的**三路逐题**一致性不在此处重复实现，
// 由 CI job benchmark-parity-gate 跑 scripts/check_benchmark_parity.py 判定。
// （为什么必须分工：跨语言 parity 需要同时起 go 与 python 子进程，
//   放在 Go 测试里会依赖测试环境是否装了 python —— 那是另一个环境假设坑。）
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
	// 🔴 关掉西湖论剑 Python 兜底：本 helper 的所有用例都在测「Go 预解路径的覆盖率」，
	// 而兜底是**另一条机制**（起 runner.py 子进程，光加载 79 个 skill 模块就 9.7s/次）。
	// 2026-10-23 实测：不关的话 55 题 × 2 条路径 × 10s ≫ 600s，两个基准用例双双超时；
	// 而且兜底若解出题会污染「Go 路径覆盖率」这个口径（数字不再对应它声称的东西）。
	// 兜底通道自身有独立用例：presolve_python_test.go 6 例（含 Vigenère 端到端）。
	t.Setenv(envPythonFallback, "0")

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

// benchHitSet 跑指定 presolve 路径，返回「SHA-256 校验通过的题目 id 集合」与总题数。
// 只机验不打印 —— 供不变量比较用（需要逐题留痕的调用方自行遍历 detail）。
func benchHitSet(t *testing.T, fn func(*Challenge) *PresolveResult) (map[string]bool, int) {
	hits, total, detail := runRealBenchmark(t, fn)
	set := make(map[string]bool, hits)
	for _, d := range detail {
		if strings.HasPrefix(d, "✅") {
			if f := strings.Fields(d); len(f) >= 2 {
				set[f[1]] = true
			}
		}
	}
	// 计数 vs 读回自洽：命中计数与解析出的 id 数必须互相印证，否则判据本身有洞。
	if len(set) != hits {
		t.Fatalf("机验自洽失败：命中计数 %d 与解析出的 id 数 %d 不一致", hits, len(set))
	}
	return set, total
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

// benchParityGap 比较生产路径与注册表路径的命中集合，返回 (注册表缺失的题, 注册表多出的题)。
// 判据抽成独立函数，便于 TestBenchParityGapDetection 做负向（变异）验证 ——
// 证明「缺口确实会被检出」，而不是一条永不放行的死判据。
func benchParityGap(shipped, registry map[string]bool) (gap, extra []string) {
	for id := range shipped {
		if !registry[id] {
			gap = append(gap, id)
		}
	}
	for id := range registry {
		if !shipped[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(gap)
	sort.Strings(extra)
	return
}

// TestBenchParityGapDetection 变异验证 benchParityGap：两向都要能检出，且相等时不得误报。
// 只证逻辑会响；「真跑时缺口会让 TestRealBenchmark_RegistryPresolve 变红」由该测试
// 那句 `if len(gap) > 0 { t.Errorf }` 直接保证（无额外分支）。
func TestBenchParityGapDetection(t *testing.T) {
	shipped := map[string]bool{"a": true, "b": true, "c": true}

	gap, extra := benchParityGap(shipped, map[string]bool{"a": true, "c": true})
	if len(gap) != 1 || gap[0] != "b" || len(extra) != 0 {
		t.Errorf("注册表缺题未被检出：gap=%v extra=%v（期望 gap=[b] extra=[]）", gap, extra)
	}

	gap, extra = benchParityGap(shipped, map[string]bool{"a": true, "b": true, "c": true, "z": true})
	if len(gap) != 0 || len(extra) != 1 || extra[0] != "z" {
		t.Errorf("注册表多题未被检出：gap=%v extra=%v（期望 gap=[] extra=[z]）", gap, extra)
	}

	gap, extra = benchParityGap(shipped, map[string]bool{"a": true, "b": true, "c": true})
	if len(gap) != 0 || len(extra) != 0 {
		t.Errorf("集合相等时不得误报：gap=%v extra=%v（期望两者都空）", gap, extra)
	}
}

// TestRealBenchmark_RegistryPresolve 注册表路径（PresolveWithRegistry）真题覆盖率。
//
// ⚠️ 历史缺陷（2026-10-16 修）：本测试此前**只 t.Logf、不含任何断言** ——
//   一个永远 PASS 的测试会给出假的安全感，正是 AGENTS.md 第四条禁止的「装饰品门禁」。
//   现补机验（且**不含硬编码命中数**，避免能力提升后门禁反而挡路）：
//     ① 计数 vs 读回自洽（见 benchHitSet）；
//     ② **shipped ⊆ registry** 不变量 —— 生产路径能解的题，注册表路径必须也能解。
//        违反即注册表 sweep 存在缺口（曾实测发生过：verbatim 密文把真解挤出候选）。
//   注册表**多**解出的题只留痕不判红：它属「求解器注册了却没被生产路径调用」的
//   接线缺口，需人工裁决；三路（Go×2 + Python 镜像）完整 parity 见
//   scripts/check_benchmark_parity.py。
func TestRealBenchmark_RegistryPresolve(t *testing.T) {
	// 注：Python 兜底由 runRealBenchmark 统一关闭（理由见那里的注释）——本用例测的是
	// **注册表口径**，兜底通道不得混入，也不该让 55 题各付 10s 子进程成本。
	pr := NewPresolver(nil)
	hits, total, detail := runRealBenchmark(t, func(ch *Challenge) *PresolveResult {
		return pr.PresolveWithRegistry(context.Background(), ch, nil)
	})
	registry := make(map[string]bool, hits)
	for _, d := range detail {
		if strings.HasPrefix(d, "✅") {
			if f := strings.Fields(d); len(f) >= 2 {
				registry[f[1]] = true
			}
		}
		t.Logf("%s", d)
	}
	if len(registry) != hits {
		t.Fatalf("机验自洽失败：命中计数 %d 与解析出的 id 数 %d 不一致", hits, len(registry))
	}
	t.Logf("=== 注册表路径 PresolveWithRegistry 真题覆盖率: %d/%d = %.1f%% (MISS %d) ===",
		hits, total, 100*float64(hits)/float64(total), total-hits)

	shipped, _ := benchHitSet(t, func(ch *Challenge) *PresolveResult {
		return pr.Presolve(context.Background(), ch, nil)
	})
	gap, extra := benchParityGap(shipped, registry)
	t.Logf("=== 与生产路径对比：生产 %d 题 | 注册表缺 %d | 注册表多 %d ===",
		len(shipped), len(gap), len(extra))
	if len(extra) > 0 {
		t.Logf("⚠️ 注册表多解出（注册了却没被生产路径调用，需人工裁决）: %v", extra)
	}
	if len(gap) > 0 {
		t.Errorf("注册表路径漏掉生产路径能解的题（shipped ⊄ registry，注册表 sweep 有缺口）: %v", gap)
	}
}
