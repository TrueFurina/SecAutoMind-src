package ctfplatform

// presolve_const_compare_test.go —— 常量比对链 Go 化回归（三真题真实端到端）。
//
// 载荷 = CSAW Quals 真题附件（beleaf/whataxor/tablez，xhlj_legacy questions_ext
// 随迁件，盘上实测在位）；官方锚以题库 JSON 为唯一真值源（test_rev_const_compare.py
// 同口径）。objdump 缺失或载荷缺失 → SKIP（环境缺口不伪造绿）。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const ccPoolDir = "../../CTF-Agent_融合/ctf_agent/data/questions_ext"
const ccAttachDir = "../../CTF-Agent_融合/ctf_agent/data/questions_ext/_attachments/rev"

func ccAttachPath(rel string) string {
	return filepath.Join(ccAttachDir, filepath.FromSlash(rel))
}

func testContext() context.Context { return context.Background() }

type ccRealCase struct {
	binary   string
	anchor   string
	qid      string
	category string
}

func ccRealCases(t *testing.T) []ccRealCase {
	t.Helper()
	if _, err := objdumpPath(); err != nil {
		t.Skipf("objdump 缺失: %v", err)
	}
	cases := []ccRealCase{
		{"2019q-rev-beleaf/beleaf", "", "ext_nyu_ctf_bench_2019q_rev_beleaf", "rev"},
		{"2023q-rev-whataxor/whataxor", "", "ext_nyu_ctf_bench_2023q_rev_whataxor", "rev"},
		{"2017q-rev-tablez/tablez", "", "ext_nyu_ctf_bench_2017q_rev_tablez", "rev"},
	}
	for i := range cases {
		jf := filepath.Join(ccPoolDir, cases[i].category, cases[i].qid+".json")
		raw, err := os.ReadFile(jf)
		if err != nil {
			t.Skipf("题库 JSON 缺失: %v", err)
		}
		var d struct {
			FlagSHA256 string `json:"flag_sha256"`
		}
		if err := json.Unmarshal(raw, &d); err != nil || d.FlagSHA256 == "" {
			t.Skipf("题库 JSON 无 flag_sha256: %s", jf)
		}
		cases[i].anchor = d.FlagSHA256
	}
	return cases
}

func TestXHLJChain_ConstCompareReal(t *testing.T) {
	for _, c := range ccRealCases(t) {
		t.Run(c.qid, func(t *testing.T) {
			data, err := os.ReadFile(ccAttachPath(c.binary))
			if err != nil {
				t.Skipf("真实载荷缺失: %v", err)
			}
			flags := ccSolve(testContext(), data, c.anchor)
			if len(flags) == 0 {
				t.Fatalf("常量比对链未命中（检测器/解析任一环断）")
			}
			// ccSolve 的 sha256 模式已严格选候选——此处再验一次双保险。
			ok := false
			for _, f := range flags {
				if len(f) >= 6 && ccVerify([]byte(f), c.anchor) {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("候选未过官方锚: %v", flags)
			}
		})
	}
}

func TestXHLJChain_ConstCompareNegative(t *testing.T) {
	if _, err := objdumpPath(); err != nil {
		t.Skipf("objdump 缺失: %v", err)
	}
	if flags := ccSolve(testContext(), []byte("plain text, not an ELF at all"), ""); flags != nil {
		t.Fatalf("非 ELF 输入不应命中: %v", flags)
	}
}
