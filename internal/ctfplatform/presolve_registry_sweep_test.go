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
// ——本测试即为该断层的机验：跑注册表全量扫描，断言每个 Enabled
// 求解器都至少执行 1 次。
//
// ⚠️ 2026-10-15 起必须两路探针：WebExploitChain 九件套（web_exploit/ssrf/
// ssti/sqli/jwt/gql/xxe/upload/deser）仅对 web 类或未声明类别的题目启用
// （webExploitApplies，presolve_registry.go；非 web 题文本里的 URL 多为
// writeup 引用，对无关主机发起真实渗透链会干等满超时）。因此反注水证明
// 拆为两路，**两路并集的执行覆盖必须等于 Enabled 全集**：
//   - misc 探针：证明其余求解器在非 web 题上真的被调度；
//   - web 探针：证明九件套同样接进了生产扫描（而非注册了永不执行）。
// 只用单路 misc 探针会把「按设计门控」误报成注水——那反而是门禁缺陷。
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
	probes := []*Challenge{
		{ID: "sweep-probe-misc", Title: "registry sweep probe (non-web)", Category: "misc",
			Description: "Find the flag. Try base64, caesar, rot13, morse, xor, rsa, hex, and look at the HTML source."},
		{ID: "sweep-probe-web", Title: "registry sweep probe (web)", Category: "web",
			Description: "Find the flag on the web target. Try base64, caesar, rot13, morse, xor, rsa, hex, and inspect the HTML source."},
	}
	for _, ch := range probes {
		_ = pr.PresolveWithRegistry(context.Background(), ch, nil)
	}

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
	t.Logf("两路探针（misc+web）实际执行到的求解器: %d/%d", ran, enabled)
	if ran != enabled {
		t.Logf("未执行: %v", notRun)
		t.Errorf("宣称 %d 个启用求解器，两路探针下只执行了 %d 个——存在注水", enabled, ran)
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

// TestRegistrySweepVerbatimTieBreak verbatim 同分裁决门禁：
// 「密文本身具 flag 外形」会把变换产出的真解挤出局——同一 likeness 下，
// 原文刮中（verbatim）必须让位于变换产出。
//
// 真实案例 ehaxctf2025_morse：题面「维吉尼亚解密(密钥kagi): OHGF{w0ry3_...}」
// 中 OHGF{...} 是密文（外形像 flag，flagLikeness=3，与真解打平），
// 而 flag_scan 以 priority 10 先命中并胜出，真解 EHAX{m0rs3_...} 被挤掉。
// 生产 huntPresolve 用固定调用顺序规避（tryVigenereKnownKey 先于 scanFlags），
// 注册表裁决必须等价表达该语义，否则同一道题在两条路径上结论不一致。
func TestRegistrySweepVerbatimTieBreak(t *testing.T) {
	// 真解：由变换（维吉尼亚/base64）产出，不原样出现在文本中。
	transformed := sweepCandidate{name: "vigenere", prio: 20, flags: []string{"EHAX{m0rs3_v1g3n3r3_0p3r4t10n}"}, like: 3}
	// 假解：密文原文刮中，likeness 同为 3，优先级更高（10 < 20）。
	verbatim := sweepCandidate{name: "flag_scan", prio: 10, flags: []string{"OHGF{w0ry3_d1q3n3x3_0x3b4t10t}"}, like: 3, verbatim: true}

	if !betterSweep(transformed, verbatim) {
		t.Fatal("同 likeness 下变换产出必须压过原文刮中（verbatim 挤真解缺陷未修复）")
	}
	if betterSweep(verbatim, transformed) {
		t.Fatal("原文刮中不得压过变换产出")
	}

	// 反向对照：likeness 不同则 verbatim 不参与裁决（高 likeness 仍优先），
	// 防止本修复退化成「verbatim 永远垫底」而压掉真正的原文命中。
	strongVerbatim := sweepCandidate{name: "flag_scan", prio: 0, flags: []string{"flag{plain_text_flag}"}, like: 3, verbatim: true}
	weakTransformed := sweepCandidate{name: "rot13", prio: 30, flags: []string{"flag{low_likeness}"}, like: 2}
	if !betterSweep(strongVerbatim, weakTransformed) {
		t.Fatal("likeness 更高者必须胜出，verbatim 不得凌驾 likeness")
	}

	// 端到端：该题在注册表路径必须返回真解而非密文。
	pr := NewPresolver(nil)
	ch := &Challenge{
		ID:          "ehaxctf2025_morse",
		Category:    "crypto",
		Description: "维吉尼亚解密(密钥kagi): OHGF{w0ry3_d1q3n3x3_0x3b4t10t}",
	}
	res := pr.PresolveWithRegistry(context.Background(), ch, nil)
	if !res.Solved {
		t.Fatal("维吉尼亚题应被解出")
	}
	if len(res.Flags) == 0 || res.Flags[0] != "EHAX{m0rs3_v1g3n3r3_0p3r4t10n}" {
		t.Fatalf("应返回变换产出的真解，实际 %v", res.Flags)
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
