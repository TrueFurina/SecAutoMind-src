package ctfplatform

// crossbench_test.go —— 与西湖论剑（A 库）真题的同卷对照立尺（规划 §2.2）。
//
// 目的不是刷分，而是回答一个决策问题：**A 的题型要不要往 B 迁？**
// 规划 §2.2 已先定阈值再跑数（防"数字难看 → 恐慌性全量迁移"这条历史复发路径）：
//   - B 命中率 ≥ 13% → 不迁题型；
//   - < 13%        → 仅迁 misc 差集（crypto/web 明确不迁）。
//
// 🔴🔴 本基准的三个诚实边界（不得越过，越过即误导）：
//  1. **输入不完整**：A 侧 88 题中仅 12 题的挑战数据（附件）仍存在，其余 76 题路径已失效。
//     本基准只喂 `description`（文本口径），测得的是 B 的**下限**，不是能力上限。
//  2. **不是 KPI**：产物在 `data/questions_real_bench/`（独立目录），
//     不并入 `data/ctf_benchmark/`，命中数**不得**写进对外材料当战果。
//  3. **不设通过阈值**：正因输入不完整，本测试只报告不断言，
//     绝不把"命中率低"变成 CI 红灯（那会逼出为了转绿而改阈值的退化）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"go.uber.org/zap"
)

type crossBenchProblem struct {
	ID                  string `json:"id"`
	Category            string `json:"category"`
	Sub                 string `json:"sub"`
	Description         string `json:"description"`
	Title               string `json:"title"`
	FlagSHA256          string `json:"flag_sha256"`
	AttachmentAvailable bool   `json:"attachment_available"`
}

type crossBenchDoc struct {
	Version string `json:"version"`
	Honesty struct {
		InputMode           string `json:"input_mode"`
		AttachmentAvailable int    `json:"attachment_available"`
		AttachmentMissing   int    `json:"attachment_missing"`
	} `json:"honesty"`
	Problems map[string]crossBenchProblem `json:"problems"`
}

func loadCrossBench(t *testing.T) crossBenchDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "questions_real_bench", "cross_bench.json"))
	if err != nil {
		t.Skipf("cross_bench.json 缺失，跳过（先跑 scripts/build_cross_bench.py）: %v", err)
	}
	var doc crossBenchDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 cross_bench.json 失败: %v", err)
	}
	return doc
}

// runCrossBench 对全部 A 库真题跑指定 presolve 函数，返回命中集合。
func runCrossBench(doc crossBenchDoc, fn func(*Challenge) *PresolveResult) (hits int, byCat map[string]int, totalByCat map[string]int, hitWithAttach int) {
	ids := make([]string, 0, len(doc.Problems))
	for id := range doc.Problems {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	byCat = map[string]int{}
	totalByCat = map[string]int{}
	for _, id := range ids {
		p := doc.Problems[id]
		totalByCat[p.Category]++
		res := fn(&Challenge{ID: id, Category: p.Category, Description: p.Description})
		if res == nil || !res.Solved || len(res.Flags) == 0 {
			continue
		}
		sum := sha256.Sum256([]byte(res.Flags[0]))
		if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
			hits++
			byCat[p.Category]++
			if p.AttachmentAvailable {
				hitWithAttach++
			}
		}
	}
	return
}

// TestCrossBench_AgainstXihuRealQuestions 输出 A/B 同卷对照的水位与分类差集。
func TestCrossBench_AgainstXihuRealQuestions(t *testing.T) {
	doc := loadCrossBench(t)
	total := len(doc.Problems)

	t.Logf("=== A→B 同卷立尺（文本口径，仅 description）===")
	t.Logf("题数=%d  附件仍存在=%d  附件已缺失=%d",
		total, doc.Honesty.AttachmentAvailable, doc.Honesty.AttachmentMissing)

	pr := NewPresolver(zap.NewNop())
	shipHits, shipByCat, totalByCat, shipAtt := runCrossBench(doc, func(ch *Challenge) *PresolveResult {
		return pr.Presolve(context.Background(), ch, nil)
	})
	regHits, regByCat, _, regAtt := runCrossBench(doc, func(ch *Challenge) *PresolveResult {
		return pr.PresolveWithRegistry(context.Background(), ch, nil)
	})

	cats := make([]string, 0, len(totalByCat))
	for c := range totalByCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		t.Logf("  %-8s 生产 %d/%d   注册表 %d/%d", c, shipByCat[c], totalByCat[c], regByCat[c], totalByCat[c])
	}
	t.Logf("合计：生产路径 %d/%d = %.1f%%；注册表路径 %d/%d = %.1f%%",
		shipHits, total, pct(shipHits, total), regHits, total, pct(regHits, total))
	t.Logf("其中附件仍存在的题：生产命中 %d / 注册表命中 %d", shipAtt, regAtt)

	// 阈值决策（规划 §2.2，先定阈后看数）——只输出结论，不作断言。
	rate := pct(shipHits, total)
	switch {
	case rate >= 13:
		t.Logf("阈值裁决：命中率 %.1f%% ≥ 13%% → **不迁题型**", rate)
	default:
		t.Logf("阈值裁决：命中率 %.1f%% < 13%% → **仅迁 misc 差集**（crypto/web 明确不迁）", rate)
	}
	t.Logf("🔴 提醒：本数字为文本口径下限（76/88 题挑战数据缺失），不得写进对外材料当战果。")
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
