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
	cat map[string][]string
}

func (c *catalogFake) RunSkill(context.Context, string, *ctfplatform.Challenge) ([]string, bool) {
	return nil, false
}
func (c *catalogFake) SkillCatalog() map[string][]string { return c.cat }

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
