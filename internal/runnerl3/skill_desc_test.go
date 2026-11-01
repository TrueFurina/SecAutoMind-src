package runnerl3

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

// catalogFake 实现 SkillRunner + SkillCatalogProvider，只用于检查 Desc 渲染。
type catalogFake struct {
	cat       map[string][]string
	contracts map[string]string // 可选：参数契约（实现 SkillContractProvider）
}

func (c *catalogFake) RunSkill(context.Context, string, *ctfplatform.Challenge) ([]string, bool) {
	return nil, false
}
func (c *catalogFake) SkillCatalog() map[string][]string { return c.cat }

// SkillContracts 只在 contracts 非 nil 时被调用（nil 时本方法仍存在，
// 因此需要 contractlessFake 才能模拟"未升级的 bridge"）。
func (c *catalogFake) SkillContracts() map[string]string { return c.contracts }

// contractlessFake 有 catalog 但没有契约（模拟只实现了 SkillCatalogProvider 的 bridge）。
type contractlessFake struct{ cat map[string][]string }

func (contractlessFake) RunSkill(context.Context, string, *ctfplatform.Challenge) ([]string, bool) {
	return nil, false
}
func (c contractlessFake) SkillCatalog() map[string][]string { return c.cat }

// plainFake 只实现 SkillRunner，不提供清单（模拟未升级的 bridge）。
type plainFake struct{}

func (plainFake) RunSkill(context.Context, string, *ctfplatform.Challenge) ([]string, bool) {
	return nil, false
}

func descOfExecutePython(t *testing.T, f *LLMFallback) string {
	t.Helper()
	for _, ti := range f.buildToolDefs() {
		if ti.Name == "execute_python" {
			return ti.Desc
		}
	}
	t.Fatal("execute_python 工具缺失（pyBridge 非 nil 时必须存在）")
	return ""
}

// 回归锁（2026-11-01 P0）：execute_python 的 Desc 里列出的 skill 名必须全部真实存在。
//
// 事故：Desc 曾手写 16 个 skill 名，其中 15 个在 catalog 里根本不存在
// （factor_integer / rsa_wiener_attack / rsa_hastad_attack / xor_bruteforce /
// angr_decompile / angr_symbolic / ghidra_analyze / objdump_disasm /
// pwn_checksec / pwn_ret2libc / pwn_ret2win / pwn_canary_bruteforce /
// zip_crack / image_steg / pcap_analyze），只有 pwn_ret2dlresolve 是真的。
// 真机后果：crypto 6 题 A/B 对比，模型唯一一次 execute_python 调的就是
// 幻觉名 factor_integer，79 个真 skill 全程零使用，skill 通路形同虚设。
func TestExecutePythonDescOnlyListsRealSkills(t *testing.T) {
	cat := map[string][]string{
		"crypto":  {"crypto_cycling", "rsa_fermat_factor"},
		"reverse": {"reverse_angr_solver"},
		"misc":    {"misc_traffic_analysis"},
	}
	f := &LLMFallback{pyBridge: &catalogFake{cat: cat}, logger: zap.NewNop()}
	desc := descOfExecutePython(t, f)

	// 1) catalog 里的名字必须出现（否则模型仍然看不见可用 skill）。
	for c, names := range cat {
		for _, n := range names {
			if !strings.Contains(desc, n) {
				t.Errorf("Desc 未列出真实 skill %q（category=%s）——模型将无法使用它", n, c)
			}
		}
	}

	// 2) 反向不变量：Desc 中每条 "- <category>: a, b, c" 里的名字必须在该 category 的清单内。
	lineRe := regexp.MustCompile(`(?m)^- ([a-z]+): (.+)$`)
	matched := 0
	for _, m := range lineRe.FindAllStringSubmatch(desc, -1) {
		category, list := m[1], m[2]
		known, isCategory := cat[category]
		if !isCategory {
			continue // 例如 "- crypto 数学模板（..." 这种说明行不匹配本正则
		}
		matched++
		// 渲染形态是 name 或 name(a,b,c)：括号内是参数契约，不是 skill 名的一部分。
		list = regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(list, "")
		for _, n := range strings.Split(list, ",") {
			n = strings.TrimSpace(n)
			if n == "" || n == "…" {
				continue
			}
			found := false
			for _, k := range known {
				if k == n {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Desc 在 category=%s 下列出了不存在的 skill %q —— 模型照调必失败", category, n)
			}
		}
	}
	if matched == 0 {
		t.Fatal("Desc 里没有任何 \"- <category>: ...\" 形式的清单行，清单渲染逻辑坏了")
	}

	// 3) 历史幻觉名一个都不许再出现。
	for _, ghost := range []string{
		"factor_integer", "rsa_wiener_attack", "rsa_hastad_attack", "xor_bruteforce",
		"angr_decompile", "angr_symbolic", "ghidra_analyze", "objdump_disasm",
		"pwn_checksec", "pwn_ret2libc", "pwn_ret2win", "pwn_canary_bruteforce",
		"zip_crack", "image_steg", "pcap_analyze",
	} {
		if strings.Contains(desc, ghost) {
			t.Errorf("Desc 又出现了幻觉 skill 名 %q（该名在 catalog 中不存在）", ghost)
		}
	}
}

// bridge 未实现 SkillCatalogProvider 时，Desc 必须明确警告"不要编造"，
// 而不是退回一张可能存在的手写清单。
func TestExecutePythonDescWarnsWhenNoCatalog(t *testing.T) {
	f := &LLMFallback{pyBridge: plainFake{}, logger: zap.NewNop()}
	desc := descOfExecutePython(t, f)
	if !strings.Contains(desc, "不要编造") {
		t.Errorf("未提供 catalog 时 Desc 应警告不要编造 skill 名，实际：%q", desc)
	}
}

// 清单为空时给出可执行的替代指令（改用 python_session），而不是空列表。
func TestExecutePythonDescEmptyCatalog(t *testing.T) {
	f := &LLMFallback{pyBridge: &catalogFake{cat: map[string][]string{}}, logger: zap.NewNop()}
	desc := descOfExecutePython(t, f)
	if !strings.Contains(desc, "python_session") {
		t.Errorf("空 catalog 时应引导模型用 python_session，实际：%q", desc)
	}
}

// 第二层缺口回归锁（2026-11-01 真机实测）：光给名字不够，参数契约必须可见。
//
// 事故：Desc 换成真名之后，模型确实改用 crypto_knapsack_mhk（真名）了，
// 但它传的是 {"a1": [], "a2": [], "b": [], "c": []} —— 全是空数组。
// 名字对了、参数全错，产出依然是零。模型没法从名字猜出要 pk/ct/kind。
func TestExecutePythonDescShowsSkillContracts(t *testing.T) {
	cat := map[string][]string{"crypto": {"crypto_knapsack_mhk", "crypto_cycling"}}
	f := &LLMFallback{
		pyBridge: &catalogFake{cat: cat, contracts: map[string]string{
			"crypto_knapsack_mhk": "ct,kind,path,pk",
		}},
		logger: zap.NewNop(),
	}
	desc := descOfExecutePython(t, f)

	if !strings.Contains(desc, "crypto_knapsack_mhk(ct,kind,path,pk)") {
		t.Errorf("Desc 未渲染 crypto_knapsack_mhk 的参数契约（模型只能盲调），实际：%q", desc)
	}
	// 没有契约的 skill 保持裸名，不能凭空造一个空括号。
	if strings.Contains(desc, "crypto_cycling(") {
		t.Errorf("无契约的 skill 不应出现括号：%q", desc)
	}
	// 必须解释括号含义，否则模型会把括号当成函数调用语法。
	if !strings.Contains(desc, "params") {
		t.Errorf("Desc 应说明括号内是 params 的键名，实际：%q", desc)
	}
}

// 未提供契约时（旧 bridge / 探测失败）Desc 必须保持纯名字，不得回归成手写清单。
func TestExecutePythonDescWithoutContracts(t *testing.T) {
	cat := map[string][]string{"crypto": {"crypto_cycling"}}
	f := &LLMFallback{pyBridge: contractlessFake{cat: cat}, logger: zap.NewNop()}
	desc := descOfExecutePython(t, f)
	if !strings.Contains(desc, "crypto_cycling") {
		t.Fatalf("Desc 丢了真实 skill 名：%q", desc)
	}
	if strings.Contains(desc, "crypto_cycling(") {
		t.Errorf("无契约时不应渲染括号：%q", desc)
	}
}
