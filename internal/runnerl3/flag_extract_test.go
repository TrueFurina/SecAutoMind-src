package runnerl3

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestFlagRegexMatchesPythonCounterpart 防止 Go / Python 两侧的 flag 正则**各活各的**。
//
// 存在理由：2026-10-29 发现的性质事故 —— Python 测量侧早就放宽到通用前缀
// （scripts/experiments/flag_util.py::FLAG_RE），Go 生产侧却还是 `strings.Index("flag{")`，
// 两侧口径漂移无人察觉，导致模型已解出的 `picoCTF{...}` 在生产路径被判「无候选」。
// **同一套口径写在两个语言里而没有互锁，迟早再漂一次**。本测试就是那把锁。
//
// fail-closed：对方文件找不到或抓不到正则 → 直接 Fatal，不许静默跳过
// （"跳过"会被当成绿，这正是本项目门禁失效的通用形态）。
func TestFlagRegexMatchesPythonCounterpart(t *testing.T) {
	const rel = "scripts/experiments/flag_util.py"
	raw, err := os.ReadFile(rel)
	if err != nil {
		// 测试 cwd 在包目录内，往上两级才是仓库根。
		alt, aerr := os.ReadFile(filepath.Join("..", "..", rel))
		if aerr != nil {
			t.Fatalf("读不到 Python 侧 %s：%v（若该文件已移动，请在本测试里同步路径，不要改成 skip）", rel, err)
		}
		raw = alt
	}
	m := regexp.MustCompile(`(?m)^FLAG_RE\s*=\s*re\.compile\(r"(.+)"\)`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("在 %s 里抓不到 FLAG_RE 的正则字面量 —— 要么被改写了，要么本测试的抓取正则过期", rel)
	}
	pyPat := string(m[1])
	if pyPat != flagCandRe.String() {
		t.Fatalf("两侧 flag 正则已漂移：\n  Python %s: %s\n  Go 内部   : %s\n"+
			"请二选一并同步另一侧，然后在两侧各自补测试用例", rel, pyPat, flagCandRe.String())
	}
}

// TestDefaultWholeSolveTimeoutNotRegressed 锁死「整题预算默认 300s」这条口径。
//
// 存在理由（2026-10-29 服务器真机事故）：
// RUNNER_LLM_TIMEOUT_SEC 的 ctx 建在 round 循环**之外**，是**整题**预算。
// 旧默认 60s 实测把 YCB 两题、real_benchmark 的 buuctf_upload_basic 精确掐死在
// 超时点上（round 3/4 起 context deadline exceeded）→ 直接 return nil,nil 记 MISS。
// 放开到 600s 后 12 题全部自然结束（7~63s）⇒ 60s 是纯人为截断。
// 本测试防止有人"顺手把数字改回去"而没人发现。
func TestDefaultWholeSolveTimeoutNotRegressed(t *testing.T) {
	if defaultWholeSolveTimeoutSec < 300 {
		t.Fatalf("整题预算默认值 %ds 过小：实测会把正在解题的题掐成 MISS，"+
			"必须 >= 300（证据见 internal/runnerl3/llm_solver.go Solve 内注释）",
			defaultWholeSolveTimeoutSec)
	}
}

// TestExtractFlagCandidatesPrefixAllowlist 锁死「前缀白名单」这条口径。
//
// 存在理由（2026-10-29 真机事故，非理论推演）：
// 旧实现用 strings.Index(lower, "flag{") 找候选，而真值前缀并不统一。
// 服务器冒烟实锤：pico2024_interencdec 题模型已输出正确解
// `picoCTF{contract_fixture_9f2a}`（原题真值已脱敏，见 benchmark.json 的
// `flag_sha256`；本用例只需复现「带非 flag 前缀」这一形态），旧实现判「没找到 flag 格式」
// → 候选 0 → 不提交 → 记 MISS。真实题库里非 flag{} 前缀普遍存在，
// 旧实现对它们逐道系统性判死。本测试就是防止这个 bug 再长回来。
func TestExtractFlagCandidatesPrefixAllowlist(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"flag 标准前缀", "答案是 flag{abc_123}", []string{"flag{abc_123}"}},
		{"picoCTF 前缀（事故原题）", "picoCTF{contract_fixture_9f2a}\n\nCONFIDENCE: 1.0",
			[]string{"picoCTF{contract_fixture_9f2a}"}},
		{"sdctf 前缀", "sdctf{Case64_ar!}", []string{"sdctf{Case64_ar!}"}},
		{"大写 FLAG", "FLAG{UPPER}", []string{"FLAG{UPPER}"}},
		{"带 flag: 引导词", "flag: flag{led}", []string{"flag{led}"}},
		{"多候选去重", "flag{a}\nflag{a}\nflag{b}", []string{"flag{a}", "flag{b}"}},
		{"无花括号文本不是候选", "CONFIDENCE: 1.0 没有 flag", nil},
		{"未闭合不算候选", "flag{unclosed", nil},
		{"空内容不算候选", "flag{}", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractFlagCandidates(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("extractFlagCandidates(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("extractFlagCandidates(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}
