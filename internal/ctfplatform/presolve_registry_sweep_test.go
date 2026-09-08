package ctfplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"
	"time"
)

// TestAllRegisteredSolversActuallyExecute 反注水门禁：
// 对外宣称「N 个注册求解器」，就必须证明这 N 个在生产链路真的被执行到。
// 历史上生产 Presolve 只硬编码调用约 25 个，其余 120 个注册了却永不被调用
// ——本测试即为该断层的机验：跑一次注册表全量扫描，断言每个 Enabled
// 求解器都至少执行 1 次。
func TestAllRegisteredSolversActuallyExecute(t *testing.T) {
	solvers := GetSolvers()
	if len(solvers) == 0 {
		t.Fatal("注册表为空")
	}
	enabled := 0
	seen := make(map[string]int, len(solvers))
	for _, s := range solvers {
		if s.Enabled {
			enabled++
		}
		seen[s.Name]++
	}
	// 诚实披露：重名重复注册会让「N 个求解器」的口径虚高，必须单独报出来。
	var dup []string
	for name, n := range seen {
		if n > 1 {
			dup = append(dup, fmt.Sprintf("%s×%d", name, n))
		}
	}
	sort.Strings(dup)
	t.Logf("注册表条目总数=%d，唯一名称=%d，Enabled=%d", len(solvers), len(seen), enabled)
	if len(dup) > 0 {
		t.Logf("⚠️ 重名重复注册（口径虚高，需去重）: %v", dup)
	}

	pr := NewPresolver(nil)
	ch := &Challenge{
		ID:          "sweep-probe",
		Title:       "registry sweep probe",
		Category:    "misc",
		Description: "Find the flag. Try base64, caesar, rot13, morse, xor, rsa, hex, and look at the HTML source.",
	}
	_ = pr.PresolveWithRegistry(context.Background(), ch, nil)

	counts := SolverRunCounts()
	ran := 0
	var notRun []string
	for _, s := range solvers {
		if !s.Enabled {
			continue
		}
		if counts[s.Name] > 0 {
			ran++
		} else {
			notRun = append(notRun, s.Name)
		}
	}
	sort.Strings(notRun)
	t.Logf("全量扫描实际执行到的求解器: %d/%d", ran, enabled)
	if ran != enabled {
		t.Logf("未执行: %v", notRun)
		t.Errorf("宣称 %d 个启用求解器，实际只执行了 %d 个——存在注水", enabled, ran)
	}
}

// TestProductionPresolveInvokesRegistrySweep 证明生产 Presolve（integrator 实际
// 调用的路径）也会触发注册表全量扫描，而不只是硬编码快速路径那 25 个。
// 注意：快速路径若已拿到 flag 外形结果会提前返回、不等待扫描收尾，
// 因此此处只断言「扫描被启动且执行了显著多于硬编码数量的求解器」。
func TestProductionPresolveInvokesRegistrySweep(t *testing.T) {
	solvers := GetSolvers()
	total := len(solvers)
	if total == 0 {
		t.Fatal("注册表为空")
	}
	pr := NewPresolver(nil)
	// 用一道快速路径必然解不出的题，确保生产路径会等待全量扫描。
	ch := &Challenge{
		ID:          "prod-sweep-probe",
		Category:    "misc",
		Description: "We captured some traffic. Analyze the pcap and the git history to recover the secret.",
	}
	_ = pr.Presolve(context.Background(), ch, nil)

	counts := SolverRunCounts()
	ran := 0
	for _, s := range solvers {
		if s.Enabled && counts[s.Name] > 0 {
			ran++
		}
	}
	t.Logf("生产 Presolve 触发后，已执行的注册求解器: %d/%d", ran, total)
	if ran < total/2 {
		t.Errorf("生产 Presolve 疑似未接入注册表全量扫描：仅 %d/%d 个求解器被执行", ran, total)
	}
}

// TestRegistrySweepNoDiagnosticFalsePositive 反例门禁：
// 扫描器不得把诊断提示（如 "AES ECB 检测：发现 N 个重复块"）当作命中返回。
func TestRegistrySweepNoDiagnosticFalsePositive(t *testing.T) {
	if got := flagLikeness([]string{"AES ECB 检测：发现 3 个重复的 16 字节块（ECB 模式特征）"}); got != 1 {
		t.Fatalf("诊断文本应判为 likeness=1（非 flag 外形），实际 %d", got)
	}
	if got := flagLikeness([]string{"flag{real_flag_here}"}); got != 3 {
		t.Fatalf("flag 外形应判为 likeness=3，实际 %d", got)
	}
	if got := flagLikeness([]string{"picoCTF{n3v3r_g0nn4}"}); got != 3 {
		t.Fatalf("picoCTF 外形应判为 likeness=3，实际 %d", got)
	}
	if got := flagLikeness([]string{"BZHCTF{sur3m3nt}"}); got != 3 {
		t.Fatalf("大写前缀外形应判为 likeness=3，实际 %d", got)
	}

	// 诊断文本与真 flag 同场竞技时，必须选真 flag（修复首命中缺陷的核心）
	diag := sweepCandidate{name: "aes_ecb", prio: 0, flags: []string{"AES ECB 检测：发现 3 个重复块"}, like: 1}
	real := sweepCandidate{name: "b64", prio: 5, flags: []string{"flag{real}"}, like: 3}
	if !betterSweep(real, diag) {
		t.Fatal("真 flag 必须压过诊断提示")
	}
	if betterSweep(diag, real) {
		t.Fatal("诊断提示不得压过真 flag")
	}
}

// TestRegistrySweepDiagnosticOnRealBenchmark 诊断用：对整套真题跑注册表全量扫描，
// 报告「有输出」与「经 SHA-256 校验为真命中」各多少，用于判断扫描器是否真在
// 工作、以及还有多少潜在能力可挖。
func TestRegistrySweepDiagnosticOnRealBenchmark(t *testing.T) {
	probs := loadRealBenchmark(t)
	pr := NewPresolver(nil)
	start := time.Now()
	sweepHits, realHits := 0, 0
	ids := make([]string, 0, len(probs))
	for id := range probs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := probs[id]
		ch := &Challenge{ID: id, Category: p.Category, Description: p.Description}
		r := pr.PresolveWithRegistry(context.Background(), ch, nil)
		if !r.Solved || len(r.Flags) == 0 {
			continue
		}
		sweepHits++
		for _, f := range r.Flags {
			sum := sha256.Sum256([]byte(f))
			if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
				realHits++
				t.Logf("✅ 扫描真命中 %s engine=%s", id, r.Engine)
				break
			}
		}
	}
	t.Logf("=== 注册表全量扫描：%d/%d 有输出，其中 %d 道 SHA-256 校验真命中，耗时 %v ===",
		sweepHits, len(probs), realHits, time.Since(start).Round(time.Millisecond))
}
