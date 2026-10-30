package runnerl3

// flag 提取「跨语言单一真值源」契约（cross-language golden test 的 Go 半边）。
//
// 真值来源：Python 侧 scripts/experiments/flag_util.py::FLAG_RE —— 判分链路唯一
// 认可的口径（MEMORY.md 明确「flag 提取只认 flag_util.py」）。由
// scripts/check_flag_extract_contract.py --generate 依据真值源生成
// testdata/flag_extract_golden.json（单一真值源，禁止手改）。
//
// 为什么需要它（2026-10-30 建立，防 10-29 冤案复发）：
//   本包 flagCandRe 与 Python FLAG_RE 目前字面量相同，但却是两份各自硬编码的拷贝。
//   10-29 服务器真机事故的根因就是两侧口径各活各的：Go 旧实现用
//   strings.Index(lower, "flag{") 只认一种前缀，模型已输出 picoCTF{...} 正解
//   却判「没找到 flag 格式」→ 候选 0 → 记 MISS。另有既有差异：Python findall
//   不去重，本包 extractFlagCandidates 带 seen map 去重 + TrimSpace。今天判分
//   都只认 flag_sha256、无影响，但没有任何机器契约锁住「哪些 token 算候选」。
//   ⇒ 任一侧单独改动都会让下面两个测试红，必须两侧 + golden 一起改才放行。
//
// 归一化口径（与 Python extract_normalized 对称，别各自演化）：
//   抽取全部匹配 → 每个 strip → 按首次出现顺序去重。下游判分只看 sha256、
//   与顺序无关，这里逐项相等是更强约束（两侧都是确定性左到右扫描）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type flagExtractGolden struct {
	SourceRegex string `json:"source_regex"`
	Cases       []struct {
		Name     string   `json:"name"`
		Input    string   `json:"input"`
		Expected []string `json:"expected"`
	} `json:"cases"`
}

func loadFlagExtractGolden(t *testing.T) flagExtractGolden {
	t.Helper()
	// Linux 部署铁律：路径必须 filepath.Join，禁硬编码 "\\"。
	raw, err := os.ReadFile(filepath.Join("testdata", "flag_extract_golden.json"))
	if err != nil {
		t.Fatalf("读取 golden 失败（先跑 python scripts/check_flag_extract_contract.py --generate）: %v", err)
	}
	var g flagExtractGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}
	if len(g.Cases) == 0 {
		t.Fatalf("golden 用例为空，契约形同虚设")
	}
	return g
}

// normalizeFlagCandidates 与 Python 侧 _ordered_unique 对称：trim + 按首次出现去重。
// 独立实现（不复用 extractFlagCandidates 内部的 seen），这样即使后者将来改了
// 去重逻辑，契约仍按冻结口径独立校验，不会被"自己验自己"掩盖。
func normalizeFlagCandidates(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool)
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFlagExtractContractRegexLiteral 锁死正则字面量本身 —— 连 pattern 字符串
// 都不许单侧漂移。比逐例行为比对更早、更明确地报警。
func TestFlagExtractContractRegexLiteral(t *testing.T) {
	g := loadFlagExtractGolden(t)
	if flagCandRe.String() != g.SourceRegex {
		t.Fatalf("Go flagCandRe 与 Python 真值源正则字面量不一致:\n  Go     = %q\n  golden = %q\n两侧必须同步修改（改 Python FLAG_RE 后 --generate，再改 Go）",
			flagCandRe.String(), g.SourceRegex)
	}
}

// TestFlagExtractContractCases 逐例比对：一次跑完全部用例并汇总所有差异，
// 避免"修一条报一条"的低效循环。真值是 Python 侧 flag_util.FLAG_RE。
func TestFlagExtractContractCases(t *testing.T) {
	g := loadFlagExtractGolden(t)
	var diffCount int
	for _, c := range g.Cases {
		got := normalizeFlagCandidates(extractFlagCandidates(c.Input))
		if !equalStringSlices(got, c.Expected) {
			t.Errorf("[%s] extractFlagCandidates(%q) 归一化后 = %v, golden(Python 真值源) = %v",
				c.Name, c.Input, got, c.Expected)
			diffCount++
		}
	}
	if diffCount > 0 {
		t.Errorf("共 %d 处与 Python 真值源不一致（真值是 Python 侧 flag_util.FLAG_RE）", diffCount)
	}
}

// TestFlagExtractContractMutation 变异验证：证明本契约不是"两边恒绿"的摆设。
// 把正则退回 10-29 事故前的旧口径（strings.Index(lower,"flag{") 的等价正则：只认
// flag{} 字面前缀），picoCTF 事故原题必须立刻与 golden 分叉。用内联局部正则，
// 不修改包级 flagCandRe、不污染其他测试，故可与上面两个测试并行运行。
func TestFlagExtractContractMutation(t *testing.T) {
	g := loadFlagExtractGolden(t)

	// 找到事故原题用例（golden 里 name 含 picoCTF）
	var pico struct {
		Name     string
		Input    string
		Expected []string
	}
	found := false
	for _, c := range g.Cases {
		if strings.Contains(c.Name, "picoCTF") {
			pico.Name, pico.Input, pico.Expected = c.Name, c.Input, c.Expected
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("golden 里找不到 picoCTF 事故原题用例，变异验证无法进行")
	}

	// 现口径：必须与 golden 一致（正向护栏）
	gotNow := normalizeFlagCandidates(extractFlagCandidates(pico.Input))
	if !equalStringSlices(gotNow, pico.Expected) {
		t.Fatalf("现口径对 [%s] 已与 golden 分叉：got=%v want=%v", pico.Name, gotNow, pico.Expected)
	}

	// 旧口径：只认 flag{...} 字面前缀（大小写不敏感）—— 这正是 10-29 判 MISS 的根因
	legacy := regexp.MustCompile(`(?i)flag\{[^{}\n]{1,200}\}`)
	gotLegacy := normalizeFlagCandidates(legacy.FindAllString(pico.Input, -1))
	if equalStringSlices(gotLegacy, pico.Expected) {
		t.Fatalf("变异未生效：旧口径对 [%s] 竟与现口径一致 (got=%v)。"+
			"说明该用例无法区分新旧正则，契约对 10-29 退化不敏感，需换更强的用例",
			pico.Name, gotLegacy)
	}
	// 旧口径对 picoCTF{} 应抽不到任何候选 → 抽出为空即证明分叉
	if len(gotLegacy) != 0 {
		t.Fatalf("旧口径对 [%s] 抽出了 %v，与「只认 flag{} 前缀」预期不符，变异用例设计有误",
			pico.Name, gotLegacy)
	}
}
