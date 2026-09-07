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
	"os"
	"path/filepath"
	"sort"
	"testing"
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
	hit := 0
	for _, id := range ids {
		prob := probs[id]
		data, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", prob.Attachment))
		if err != nil {
			t.Errorf("%s: 读取附件失败: %v", id, err)
			continue
		}
		res := p.Presolve(context.Background(),
			&Challenge{Description: prob.Description, Category: prob.Category},
			map[string]string{filepath.Base(prob.Attachment): string(data)})
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
