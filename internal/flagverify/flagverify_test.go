package flagverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTruth 三态仲裁的表驱动测试。
// 纪律：必须覆盖「无真值」——bool 语义会把"无法判定"误判成"错"，是幻觉误报根源。
func TestTruth(t *testing.T) {
	// 真值一律实算，禁止在测试里手写哈希（本项目铁律：数字只能来自脚本/函数实跑）
	truthFull := SHA256Hex("flag{Demo}")

	cases := []struct {
		name      string
		candidate string
		truth     string
		want      Verdict
	}{
		{"全串匹配", "flag{Demo}", truthFull, Match},
		{"大小写不同的全串也算不符（严格逐字）", "FLAG{Demo}", truthFull, Mismatch},
		{"错答案", "flag{other}", truthFull, Mismatch},
		{"无真值→Unknown（不得判错）", "flag{Demo}", "", Unknown},
		{"真值格式非法→Unknown（不得因格式怪判错）", "flag{Demo}", "not-a-sha", Unknown},
		{"空候选→Unknown", "", truthFull, Unknown},
		{"仅空白候选→Unknown", "   ", truthFull, Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truth(tc.candidate, tc.truth); got != tc.want {
				t.Fatalf("Truth(%q, %q) = %v, want %v", tc.candidate, tc.truth, got, tc.want)
			}
		})
	}
}

// TestTruthInnerForm 验证"只吐内文"的求解器输出也能被判为 Match。
// 这是真实痛点：很多求解器返回 flag 内文，若只比全串会把正确解误判成错。
func TestTruthInnerForm(t *testing.T) {
	innerTruth := SHA256Hex("Demo")
	if got := Truth("flag{Demo}", innerTruth); got != Match {
		t.Fatalf("内文口径应判 Match，实际 %v", got)
	}
	if got := Truth("flag{Demo}", SHA256Hex("flag{Demo}")); got != Match {
		t.Fatalf("全串口径应判 Match，实际 %v", got)
	}
}

// TestTruthNotDegradeToBool 明确锁死"三态不是 bool"这条设计约束。
func TestTruthNotDegradeToBool(t *testing.T) {
	truth := SHA256Hex("flag{X}")
	if Truth("flag{X}", truth) != Match {
		t.Fatal("应为 Match")
	}
	if Truth("flag{Y}", truth) != Mismatch {
		t.Fatal("应为 Mismatch")
	}
	if Truth("flag{Y}", "") != Unknown {
		t.Fatal("无真值必须是 Unknown，不能是 Mismatch")
	}
}

func TestCoherence(t *testing.T) {
	t.Run("全部合规→无发现", func(t *testing.T) {
		problems := map[string]Problem{
			"a": {ID: "a", File: "b1.json", FlagSHA256: SHA256Hex("flag{A}")},
			"b": {ID: "b", File: "b1.json", FlagSHA256: SHA256Hex("flag{B}")},
		}
		if f := Coherence(problems); len(f) != 0 {
			t.Fatalf("期望无发现，实际 %v", f)
		}
	})

	t.Run("缺真值→红线", func(t *testing.T) {
		f := Coherence(map[string]Problem{"a": {ID: "a", File: "b.json"}})
		if len(f) != 1 || f[0].Kind != FindingMissingTruth {
			t.Fatalf("期望 missing_truth，实际 %v", f)
		}
	})

	t.Run("真值格式非法→红线", func(t *testing.T) {
		f := Coherence(map[string]Problem{"a": {ID: "a", File: "b.json", FlagSHA256: "zz"}})
		if len(f) != 1 || f[0].Kind != FindingInvalidTruth {
			t.Fatalf("期望 invalid_truth，实际 %v", f)
		}
	})

	t.Run("同 id 不同真值→红线（注水温床）", func(t *testing.T) {
		// 同一 id 被两个题集收录但答案不同：静态审查几乎发现不了，必须机器对账。
		occ := []Problem{
			{ID: "dup", File: "x.json", FlagSHA256: SHA256Hex("flag{ONE}")},
			{ID: "dup", File: "y.json", FlagSHA256: SHA256Hex("flag{TWO}")},
		}
		f := CoherenceAcross(occ)
		if len(f) != 1 || f[0].Kind != FindingTruthDivergence {
			t.Fatalf("期望 truth_divergence 一条，实际 %v", f)
		}
		if !strings.Contains(f[0].Detail, "x.json") || !strings.Contains(f[0].Detail, "y.json") {
			t.Fatalf("发现应指出两个来源文件，实际: %s", f[0].Detail)
		}
	})

	t.Run("同 id 同真值跨文件→不算红线（跨集复用正常）", func(t *testing.T) {
		occ := []Problem{
			{ID: "same", File: "x.json", FlagSHA256: SHA256Hex("flag{SAME}")},
			{ID: "same", File: "y.json", FlagSHA256: SHA256Hex("flag{SAME}")},
		}
		if f := CoherenceAcross(occ); HasRedLine(f) {
			t.Fatalf("跨集复用同一真值不应判红线，实际 %v", f)
		}
	})

	t.Run("报告稳定可复现", func(t *testing.T) {
		problems := map[string]Problem{
			"z": {ID: "z", File: "b.json"},
			"a": {ID: "a", File: "b.json"},
			"m": {ID: "m", File: "b.json", FlagSHA256: "bad"},
		}
		first := Coherence(problems)
		second := Coherence(problems)
		// z 与 a 缺真值、m 真值格式非法 → 共 3 条
		if len(first) != 3 {
			t.Fatalf("期望 3 条发现，实际 %d（%v）", len(first), first)
		}
		for i := range first {
			if first[i].ID != second[i].ID {
				t.Fatalf("两次报告顺序不一致：%s vs %s", first[i].ID, second[i].ID)
			}
		}
	})
}

// benchmarkProblem 对齐 data/ctf_benchmark/*.json 的最小结构。
type benchmarkProblem struct {
	ID         string `json:"id"`
	FlagSHA256 string `json:"flag_sha256"`
	Flag       string `json:"flag"`
	Source     string `json:"source"`
}

type benchmarkDoc struct {
	Problems map[string]benchmarkProblem `json:"problems"`
}

func loadBenchmark(t *testing.T, rel string) benchmarkDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", rel, err)
	}
	var doc benchmarkDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 %s 失败: %v", rel, err)
	}
	return doc
}

// TestRealBenchmarkTruthCoherence 对仓库内**真实公开真题**题集做真值源一致性对账。
// 这是一条常驻回归：任何人把答案表换成另一个来源（本题库的 P0 事故形态），
// 本测试立刻变红，而不是等到跑批时才发现 3 道真解被冤成 0。
func TestRealBenchmarkTruthCoherence(t *testing.T) {
	doc := loadBenchmark(t, filepath.Join("data", "ctf_benchmark", "real_benchmark.json"))
	if len(doc.Problems) == 0 {
		t.Fatal("real_benchmark.json 解析出 0 题，题库结构可能变了，需同步本测试")
	}
	problems := make(map[string]Problem, len(doc.Problems))
	for id, p := range doc.Problems {
		problems[id] = Problem{ID: id, File: "real_benchmark.json", FlagSHA256: p.FlagSHA256}
	}
	if f := Coherence(problems); HasRedLine(f) {
		t.Fatalf("真实真题题集出现真值源问题：\n%s", joinFindings(f))
	}
}

// TestExternalWestlakeNoPlaintext 校验外送基准（西湖论剑 CTF-Agent 出品）不含明文答案。
// 外送集一旦混入明文 flag，会让"外部真题口径"被答案污染，必须变红。
func TestExternalWestlakeNoPlaintext(t *testing.T) {
	path := filepath.Join("..", "..", "data", "ctf_benchmark", "external_westlake", "benchmark.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		// 按本项目 0-skip 纪律：对象缺失时硬失败并给出可执行修复，不静默跳过
		t.Fatalf("外送基准缺失：%v；修复方式=重新执行导出 ctf_agent/scripts/_export_external_benchmark.py", err)
	}
	var doc benchmarkDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 external_westlake/benchmark.json 失败: %v", err)
	}
	if len(doc.Problems) == 0 {
		t.Fatal("外送基准解析出 0 题，需检查导出产物")
	}
	plainRe := regexp.MustCompile(`flag\{[^}]{2,}\}`)
	leaks := 0
	for id, p := range doc.Problems {
		if plainRe.MatchString(p.Flag) {
			t.Errorf("外送基准 %s 含明文 flag（字段 flag）", id)
			leaks++
		}
		if p.FlagSHA256 == "" {
			t.Errorf("外送基准 %s 缺 flag_sha256", id)
			leaks++
		}
	}
	if leaks > 0 {
		t.Fatalf("外送基准存在 %d 处答案污染", leaks)
	}
}

// TestRealBenchmarkPlaintextIsRedundant 记录一个**已知现状**：
// real_benchmark.json 中部分题同时保存明文 flag 与其 SHA-256，且两者一致，
// 即明文对判分零作用（纯冗余）。该测试锁住"两者一致"这一事实——
// 若哪天有人改了明文却没同步哈希，本测试立刻变红。
func TestRealBenchmarkPlaintextIsRedundant(t *testing.T) {
	doc := loadBenchmark(t, filepath.Join("data", "ctf_benchmark", "real_benchmark.json"))
	plainRe := regexp.MustCompile(`flag\{[^}]{2,}\}`)
	checked := 0
	for id, p := range doc.Problems {
		if !plainRe.MatchString(p.Flag) {
			continue
		}
		if p.FlagSHA256 == "" {
			t.Fatalf("%s 有明文 flag 但无 flag_sha256：明文无法被哈希校验，等于答案键外泄", id)
		}
		if got := SHA256Hex(p.Flag); !strings.EqualFold(got, p.FlagSHA256) {
			t.Fatalf("%s 明文 flag 与 flag_sha256 不一致——判分与题面已分裂", id)
		}
		checked++
	}
	if checked == 0 {
		// 不 skip：若真已整改（无明文），本测试无对象但不代表失败——此时仅确认事实
		t.Log("real_benchmark.json 当前无明文 flag 题（可能已整改）")
	}
	t.Logf("real_benchmark.json 中明文 flag 与哈希一致（冗余但自洽）的题目数: %d", checked)
}

func joinFindings(f []Finding) string {
	var sb strings.Builder
	for _, x := range f {
		sb.WriteString("  - " + x.String() + "\n")
	}
	return sb.String()
}
