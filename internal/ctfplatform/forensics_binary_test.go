package ctfplatform

// forensics_binary_test.go —— 真实二进制取证能力机验。
//
// 与静态文本基准（real_benchmark.json）互补：静态集的 36 道 MISS 里，绝大多数
// 是「描述里根本不含任何数据」的结构性无解题（flag 只在靶机/附件里）。本文件
// 测的正是那一层能力——给真实附件（PNG/pcap/zip/二进制），能否真正解析出 flag。
//
// 两条硬纪律：
//  1. 命中判定走 SHA-256（与 Go/Python 双语言基准一致的机验口径），不认肉眼。
//  2. 反注水断言：朴素 flag 正则（scanFlags）在附件原始字节上必须扫不到，
//     否则说明题目出得太水、能力贡献为零。
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

type attachProblem struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Description   string `json:"description"`
	Attachment    string `json:"attachment"`
	FlagSHA256    string `json:"flag_sha256"`
	PresolveSkill string `json:"presolve_skill"`
}

func loadAttachmentBenchmark(t *testing.T) map[string]attachProblem {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "attachment_benchmark.json"))
	if err != nil {
		t.Fatalf("读取附件基准失败（先跑 scripts/gen_forensics_artifacts.py）: %v", err)
	}
	var doc struct {
		Problems map[string]attachProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析附件基准失败: %v", err)
	}
	if len(doc.Problems) == 0 {
		t.Fatal("附件基准为空")
	}
	return doc.Problems
}

func flagSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestAttachmentForensicsBenchmark 走生产路径 Presolve（与线上同一入口），
// 以附件 map 形式喂入真实取证产物，校验 SHA-256 命中。
func TestAttachmentForensicsBenchmark(t *testing.T) {
	probs := loadAttachmentBenchmark(t)
	ids := make([]string, 0, len(probs))
	for id := range probs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	p := NewPresolver(nil)
	// 诊断（用 fmt.Printf 而非 t.Logf：t.Logf 只在测试失败时才出现在 CI 日志里，
	// 导致偶发失败时拿不到上下文。2026-09-28 该测试在 CI 上偶发 9/10，
	// 就是因为在"成功的那几次"里没有任何留痕，无法比对。）
	fmt.Printf("[att-diag] 注册表求解器数=%d 基准题数=%d\n", len(GetSolvers()), len(ids))
	hit := 0
	for _, id := range ids {
		prob := probs[id]
		data, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", prob.Attachment))
		if err != nil {
			t.Errorf("%s: 读取附件失败: %v", id, err)
			continue
		}
		t0 := time.Now()
		res := p.Presolve(context.Background(),
			&Challenge{Description: prob.Description, Category: prob.Category},
			map[string]string{filepath.Base(prob.Attachment): string(data)})
		fmt.Printf("[att-diag] %-24s engine=%-18s flags=%-2d 附件=%-6dB 耗时=%v\n",
			id, res.Engine, len(res.Flags), len(data), time.Since(t0).Round(time.Millisecond))
		ok := false
		for _, f := range res.Flags {
			if flagSHA(f) == prob.FlagSHA256 {
				ok = true
				break
			}
		}
		if ok {
			hit++
			t.Logf("✅ %-24s engine=%s", id, res.Engine)
		} else {
			t.Errorf("❌ %-24s 未命中（engine=%s flags=%v）", id, res.Engine, res.Flags)
		}
	}
	t.Logf("=== 附件取证基准（生产 Presolve 路径）: %d/%d = %.1f%% ===",
		hit, len(probs), float64(hit)*100/float64(len(probs)))
}

// TestAttachmentForensicsPerSolver 逐求解器机验：每道题必须由「设计上该命中」
// 的那个解析器（presolve_skill）真正产出 flag，避免聚合路径掩盖某个解析器空转。
func TestAttachmentForensicsPerSolver(t *testing.T) {
	probs := loadAttachmentBenchmark(t)
	dispatch := map[string]func([]byte) []string{
		"bin_strings":   bfxScanVariants,
		"bin_png_lsb":   bfxPNGLsb,
		"bin_png_meta":  bfxPNGMeta,
		"bin_jpeg_meta": bfxJPEGMeta,
		"bin_pcap_http": bfxPcapHTTP,
		"bin_zip_inner": func(d []byte) []string { return bfxZipInner(d, 0) },
		"bin_carve":     bfxCarve,
		"bin_xor_crib":  bfxXorCrib,
	}
	ids := make([]string, 0, len(probs))
	for id := range probs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	hit := 0
	for _, id := range ids {
		prob := probs[id]
		fn, ok := dispatch[prob.PresolveSkill]
		if !ok {
			t.Fatalf("%s: 未知求解器 %s", id, prob.PresolveSkill)
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", prob.Attachment))
		if err != nil {
			t.Fatalf("%s: 读取附件失败: %v", id, err)
		}
		matched := false
		for _, f := range fn(data) {
			if flagSHA(f) == prob.FlagSHA256 {
				matched = true
				break
			}
		}
		if matched {
			hit++
		} else {
			t.Errorf("❌ %-24s %s 未解析出 flag（原始输出 %q）", id, prob.PresolveSkill, fn(data))
		}
	}
	t.Logf("=== 取证解析器逐项机验: %d/%d ===", hit, len(ids))
}

// TestAttachmentBenchmarkNotSolvableByNaiveRegex 反注水门禁：
// 若朴素正则就能在原始字节上扫到 flag，说明产物没有真实隐藏、能力贡献为零。
func TestAttachmentBenchmarkNotSolvableByNaiveRegex(t *testing.T) {
	probs := loadAttachmentBenchmark(t)
	for id, prob := range probs {
		data, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", prob.Attachment))
		if err != nil {
			t.Fatalf("%s: 读取附件失败: %v", id, err)
		}
		for _, f := range scanFlags(string(data)) {
			if flagSHA(f) == prob.FlagSHA256 {
				t.Errorf("%s: 朴素正则即可命中，产物未做真实隐藏（注水）", id)
			}
		}
	}
}

// TestBinaryForensicsSolversReturnFlagShapedOnly 取证层只准返回 flag 形状的结果，
// 不准返回诊断文本（旧 forensics 壳子的老毛病）。
func TestBinaryForensicsSolversReturnFlagShapedOnly(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "artifacts", "stego_lsb.png"))
	if err != nil {
		t.Skip("缺少取证产物")
	}
	attachments := map[string]string{"stego_lsb.png": string(data)}
	cases := []struct {
		name string
		fn   func([]byte) []string
	}{
		{"bin_strings", func(d []byte) []string { return bfxScanVariants(d) }},
		{"bin_png_lsb", bfxPNGLsb},
		{"bin_png_meta", bfxPNGMeta},
		{"bin_carve", bfxCarve},
		{"bin_xor_crib", bfxXorCrib},
	}
	for _, c := range cases {
		for _, got := range c.fn(data) {
			if len(scanFlags(got)) == 0 {
				t.Errorf("%s 返回非 flag 形状结果: %q", c.name, got)
			}
		}
	}
	_ = attachments
}

// TestPresolveSweepResultNotLost 锁死「注册表扫描结果不得被 select 竞态丢弃」。
//
// 背景（2026-09-30 定位到 CI 偶发 9/10 的根因）：
// Presolve 的收集端同时 select chSweep 与 sweepDone，而 sweep goroutine 是
// 「先 chSweep <-（缓冲 1，不阻塞）→ 再 defer close(sweepDone)」，两个 channel
// 可能同时就绪 —— Go 的 select 在多 case 就绪时**随机**选取，于是约一半概率
// 走 sweepDone 分支而把扫描结果丢掉。
//
// artifact_utf16_binary 是唯一「快速路径没有任何 solver 能解、只能靠注册表扫描
// 命中」的基准题（bin_strings 只注册在 forensics_binary.go:732；另一道
// presolve_skill=bin_strings 的 artifact_b64_binary 在快速路径就被
// base64_multilayer 解掉了，likeness=3 时根本不进那个 select），所以它单独
// 表现为偶发失败。
//
// 本用例对这道题反复走**生产路径** Presolve：修复前在 CI（-race、负载高）上有
// 可观概率变红，修复后必须稳定全中。
func TestPresolveSweepResultNotLost(t *testing.T) {
	const id = "artifact_utf16_binary"
	const rounds = 30

	probs := loadAttachmentBenchmark(t)
	prob, ok := probs[id]
	if !ok {
		t.Fatalf("基准集缺少 %s", id)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", prob.Attachment))
	if err != nil {
		t.Fatalf("%s: 读取附件失败: %v", id, err)
	}

	miss := 0
	for i := 1; i <= rounds; i++ {
		p := NewPresolver(nil)
		res := p.Presolve(context.Background(),
			&Challenge{Description: prob.Description, Category: prob.Category},
			map[string]string{filepath.Base(prob.Attachment): string(data)})
		hit := false
		for _, f := range res.Flags {
			if flagSHA(f) == prob.FlagSHA256 {
				hit = true
				break
			}
		}
		if !hit {
			miss++
			if miss <= 3 {
				t.Errorf("第 %d 轮未命中（engine=%q flags=%v）—— 扫描结果疑似被 select 竞态丢弃",
					i, res.Engine, res.Flags)
			}
		}
	}
	if miss > 0 {
		t.Errorf("%s 在 %d 轮中漏解 %d 次（应为 0）：生产 Presolve 对扫描结果有丢失路径",
			id, rounds, miss)
	}
}

// TestSweepDoneImpliesSweepResultBuffered 用**确定性**方式验证上面那处修复。
//
// 为什么需要它：Presolve 的竞态依赖「主 goroutine 恰好晚于 sweep 完成才执行 select」
// 这一时序，本地跑几十轮都未必触发（本地 sweep 通常慢于快速路径，主 goroutine 会先
// 阻塞在 select 上），所以 TestPresolveSweepResultNotLost 只能算压力用例、不能算证明。
// 本用例直接构造与生产**完全一致的 channel 形状**并强制进入「两个 case 同时就绪」
// 状态（先 <−sweepDone 等 sweep 彻底结束，此时 chSweep 已满且 sweepDone 已关闭），
// 于是不依赖调度运气即可复现。
//
// 两个断言互为自检：
//   - 修复写法（sweepDone 分支补一次非阻塞读）必须零丢失；
//   - 原始写法（该分支什么都不做）必须**确有丢失**，否则说明用例没造出同时就绪、
//     整条用例失效（杀不死变异体的测试是摆设）。
func TestSweepDoneImpliesSweepResultBuffered(t *testing.T) {
	const rounds = 2000

	runOnce := func(withDrain bool) bool {
		chSweep := make(chan int, 1) // 与生产一致：缓冲 1，发送不阻塞
		sweepDone := make(chan struct{})
		go func() {
			defer close(sweepDone) // 与生产一致：先发送，后由 defer 关闭
			chSweep <- 42
		}()
		<-sweepDone // 强制「同时就绪」：此刻 chSweep 有值 且 sweepDone 已关闭

		got := 0
		select {
		case v := <-chSweep:
			got = v
		case <-sweepDone:
			if withDrain {
				select { // ← 修复：把可能已躺在缓冲里的结果捞回来
				case v := <-chSweep:
					got = v
				default:
				}
			}
		}
		return got == 42
	}

	lostOld, lostNew := 0, 0
	for i := 0; i < rounds; i++ {
		if !runOnce(false) {
			lostOld++
		}
	}
	for i := 0; i < rounds; i++ {
		if !runOnce(true) {
			lostNew++
		}
	}
	fmt.Printf("[att-diag] 同时就绪 %d 次：原写法丢失 %d 次（%.1f%%），修复写法丢失 %d 次\n",
		rounds, lostOld, float64(lostOld)*100/float64(rounds), lostNew)

	if lostNew != 0 {
		t.Errorf("修复写法仍丢失 %d/%d —— 补读无效", lostNew, rounds)
	}
	if lostOld == 0 {
		t.Errorf("原写法在 %d 次下竟一次未丢 —— 用例没造出「同时就绪」，证明力为零", rounds)
	}
}
