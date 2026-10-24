// crossbench_stage1_test.go —— 吞并验收阶段 1（merge_xhlj_roadmap_20261023 §五 +
// docs/specs/西湖论剑融合移交_20261024.md §一）：
//   阶段 1 阈值 = SecAutoMind **presolve 层**（Go registry + Python 兜底 bridge）
//   解出数 ≥ ctf_agent **presolve 层**终态解出数（同池同口径）。
//
// ctf_agent 终态锚（data/ctf_benchmark/xhlj_legacy/coverage_map.json summary）：
//   12 题有数据子集上 **covered_yes = 6**（10733 / vnctf_flag / ezrsa / simplelegendre /
//   exciting_inverse / filterrandom，全部 sha256 机验）；另有 covered_chain_verified_synthetic=4
//   （合成口径，不与本测试混算）与 covered_no=4。
//
// 🔴 环境守卫：SECAUTOMIND_STAGE1_ACCEPTANCE=1 才运行——python 兜底全开，88 题文本口径
//   + 12 题附件口径最坏 20-60 分钟，绝不进 CI 默认路径（CI 的 cross-bench 双用例保持
//   fallback=0 的 Go-only 口径，两套数字互不冒充）。
// 🔴 只报告不断言命中率（crossbench 家族纪律：输入部分完整，命中率不设 CI 阈值）；
//    但环境/资产缺失必须 SKIP 或显式记账，不伪造绿。
// 🔴 本测试结果即「阶段 1 验收」的正式读数，跑完应回写移交总纲 §一（含日期与两个口径）。
package ctfplatform

import (
	"context"
	"os"
	"sort"
	"testing"

	"go.uber.org/zap"
)

func TestStage1_AcceptanceWithFallback(t *testing.T) {
	if os.Getenv("SECAUTOMIND_STAGE1_ACCEPTANCE") == "" {
		t.Skip("阶段 1 验收为手动跑：设 SECAUTOMIND_STAGE1_ACCEPTANCE=1" +
			"（python 兜底全开，约 20-60 分钟；CI 默认跳过）")
	}
	skipNoPython(t)
	// python 兜底全开：解释器沿 race_preflight 钉死的链（CTF_PYTHON_PATH → workbuddy venv）
	if py := os.Getenv("CTF_PYTHON_PATH"); py != "" {
		t.Setenv(envPythonBin, py)
	} else {
		t.Setenv(envPythonBin, testPyVenv)
	}
	t.Setenv(envPythonFallback, "1")
	t.Setenv(envXHLJLegacyDir, testXHLJLegacy)
	t.Setenv(envPythonFallbackTimout, "45000")

	doc := loadCrossBench(t)
	pr := NewPresolver(zap.NewNop())

	// ── 模式 B（裁决口径）：12 题有数据子集，文本+附件，与 ctf_agent covered_yes=6 同池 ──
	// 剔除答案形态附件 = 真实解题口径（主判据）；含答案口径按赛制另列，互不冒充。
	realHits, realIDs, em, um := runCrossBenchSubset(doc, false, func(ch *Challenge) *PresolveResult {
		return pr.Presolve(context.Background(), ch, nil)
	})
	t.Logf("[模式B·剔除答案文件] 命中 %d/%d（ctf_agent 终态锚 = 6）：命中题 = %v",
		realHits, subsetTotal(t, doc), realIDs)
	t.Logf("[模式B] 附件缺失记账：预期缺失（git 排除答案文件）=%d，异常缺失=%d（异常缺失>0 = 清单与实物脱节）", em, um)
	if um > 0 {
		t.Errorf("附件清单与实物脱节 %d 处——先修数据完整性再谈命中率（fail-closed）", um)
	}

	allHits, allIDs, _, _ := runCrossBenchSubset(doc, true, func(ch *Challenge) *PresolveResult {
		return pr.Presolve(context.Background(), ch, nil)
	})
	t.Logf("[模式B·含答案文件] 命中 %d/%d：命中题 = %v", allHits, subsetTotal(t, doc), allIDs)

	// ── 模式 A（下限口径）：88 题纯文本（Go registry + miss 后兜底）──
	prodHits, prodByCat, totalByCat, prodAtt := runCrossBench(doc, func(ch *Challenge) *PresolveResult {
		return pr.Presolve(context.Background(), ch, nil)
	})
	cats := make([]string, 0, len(totalByCat))
	for c := range totalByCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		t.Logf("[模式A·文本] %-8s %d/%d", c, prodByCat[c], totalByCat[c])
	}
	t.Logf("[模式A·文本] 合计 %d/%d（其中附件可用题命中 %d）——此为下限口径", prodHits, len(doc.Problems), prodAtt)

	// ── 阶段 1 裁决（报告制：达标/未达标都如实回写移交总纲，不粉饰）──
	switch {
	case realHits >= 6:
		t.Logf("✅ 阶段 1 达标：剔除答案口径 %d ≥ ctf_agent 终态 6（同池同口径）", realHits)
	default:
		t.Logf("⛔ 阶段 1 未达标：剔除答案口径 %d < 6——缺口题 = 12 子集 − 命中集，逐题 Go 化后复跑（P1 工作清单来源）", realHits)
	}
}

func subsetTotal(t *testing.T, doc crossBenchDoc) int {
	t.Helper()
	n := 0
	for _, p := range doc.Problems {
		if p.AttachmentAvailable {
			n++
		}
	}
	return n
}
