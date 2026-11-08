package ctfplatform

// externalbench_test.go —— 外部真题对照尺（Google CTF 2021–2025，载荷齐全 38/40）。
//
// 🔴 本尺存在的理由（规划 §2.2 的遗留盲区，勿改用途）：
//   B 对外最漂亮的数字是**自产集 70/72 = 97.2%**，但自产集是**按求解器能力造的**（开卷考试）。
//   项目已明令「禁止把自产集当作赛题能力对外表述」，但此前缺一把「外部 + 载荷齐全」的尺
//   来实证该禁令——cross-bench（A 库真题 88 题）只有 12/88 附件仍在，
//   「1/88」可被辩解为「数据缺失，非能力问题」。本尺载荷齐全 38/40，该辩解不成立。
//
// 故本测试的第一用途**不是刷分**：它是「自产集高分 ≠ 解题能力」的对照实测装置。
// 数字好看难看都如实记录，不得为转绿改阈值。
//
// 🔴 三条诚实边界（与 crossbench_test.go 同源，不得越过）：
//  1. **不是 KPI**：产物在 `data/questions_external_bench/`（独立目录），
//     命中数**不得**写进对外材料当战果，也**不得**并入 `data/ctf_benchmark/`。
//  2. **不设通过阈值**：只报告不断言命中率，绝不把"命中率低"变成 CI 红灯。
//  3. **完整性故障必须 fail-closed**：附件清单与实物脱节、或本尺题目混入 KPI 基准，
//     属门禁守护的事实问题，直接红——与"不拿命中率问责"是两件事。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.uber.org/zap"
)

type externalBenchProblem struct {
	ID                 string                 `json:"id"`
	Category           string                 `json:"category"`
	Sub                string                 `json:"sub"`
	Description        string                 `json:"description"`
	Title              string                 `json:"title"`
	FlagSHA256         string                 `json:"flag_sha256"`
	ExternalSource     string                 `json:"external_source"`
	SourceRepo         string                 `json:"source_repo"`
	License            string                 `json:"license"`
	PayloadComplete    bool                   `json:"payload_complete"`
	AttachmentDeclared int                    `json:"attachment_declared"`
	AttachmentPresent  int                    `json:"attachment_present"`
	AttachmentFiles    []crossBenchAttachment `json:"attachment_files,omitempty"`
}

type externalBenchDoc struct {
	Version string `json:"version"`
	Honesty struct {
		PayloadComplete int    `json:"payload_complete"`
		PayloadPartial  int    `json:"payload_partial"`
		NotAKPI         string `json:"not_a_kpi"`
	} `json:"honesty"`
	Problems map[string]externalBenchProblem `json:"problems"`
}

const externalBenchDir = "data/questions_external_bench"
const externalBenchFile = "external_bench.json"
const externalBenchAttachDir = "_attachments"

func loadExternalBench(t *testing.T) externalBenchDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", externalBenchDir, externalBenchFile))
	if err != nil {
		t.Skipf("external_bench.json 缺失，跳过（先跑 scripts/build_external_bench.py）: %v", err)
	}
	var doc externalBenchDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 external_bench.json 失败: %v", err)
	}
	return doc
}

// runExternalBench 对全部外部真题跑指定 presolve 函数，返回命中集合（文本口径）。
func runExternalBench(doc externalBenchDoc, fn func(*Challenge) *PresolveResult) (
	hits int, byCat map[string]int, totalByCat map[string]int, hitIDs []string) {
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
			hitIDs = append(hitIDs, id)
		}
	}
	return
}

// TestExternalBench_TextOnly 文本口径（仅 description）水位——只报告不断言。
func TestExternalBench_TextOnly(t *testing.T) {
	// 🔴 关掉西湖论剑 Python 兜底：本用例量的是「**Go 预解路径**在外部真题尺上的命中率」
	// （对外陈述 0/40 = 0.0%，用来证明"自产集高分 ≠ 解题能力"）。
	// 兜底是另一条机制（起 runner.py，9.7s/次）；不关则 40 题 × 2 条路径 × 10s ≈ 800s，
	// quant 门禁的 external_control 会 600s 超时；且兜底若解出题会污染这个对照口径。
	t.Setenv(envPythonFallback, "0")

	doc := loadExternalBench(t)
	total := len(doc.Problems)
	if total == 0 {
		t.Fatal("external_bench.json 无题目——产物被清空属完整性故障，不得静默通过")
	}

	t.Logf("=== 外部真题对照尺（Google CTF 2021–2025，文本口径仅 description）===")
	t.Logf("题数=%d  载荷齐全=%d  载荷缺失=%d",
		total, doc.Honesty.PayloadComplete, doc.Honesty.PayloadPartial)

	pr := NewPresolver(zap.NewNop())
	shipHits, shipByCat, totalByCat, shipIDs := runExternalBench(doc, func(ch *Challenge) *PresolveResult {
		return pr.Presolve(context.Background(), ch, nil)
	})
	regHits, regByCat, _, regIDs := runExternalBench(doc, func(ch *Challenge) *PresolveResult {
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
	if len(shipIDs) > 0 {
		t.Logf("  生产路径命中题号：%s", strings.Join(shipIDs, ", "))
	}
	if len(regIDs) > 0 {
		t.Logf("  注册表路径命中题号：%s", strings.Join(regIDs, ", "))
	}
	t.Logf("🔴 对照结论用途：与自产集 97.2%% 并置，实证「自产集高分 ≠ 解题能力」。")
	t.Logf("🔴 本数字不得写入对外材料当战果（external-bench 仅作对照尺）。")
}

// loadExternalBenchAttachments 把某题已入仓的附件内容拼进描述（沿用 cross-bench 的
// 截断与二进制跳过口径，保证两把尺的测量管道一致，避免"尺不同"造成的数字不可比）。
func loadExternalBenchAttachments(p externalBenchProblem, includeAnswerKey bool) (string, int, int) {
	var b strings.Builder
	total, expMissing, unexpMissing := 0, 0, 0
	for _, af := range p.AttachmentFiles {
		if af.AnswerKeyShape && !includeAnswerKey {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", externalBenchDir,
			externalBenchAttachDir, p.ID, af.Name))
		if err != nil {
			if af.GitExcluded {
				expMissing++
			} else {
				unexpMissing++
			}
			continue
		}
		if looksBinary(raw) {
			continue
		}
		if len(raw) > crossBenchAttachMaxByte {
			raw = raw[:crossBenchAttachMaxByte]
		}
		if total+len(raw) > crossBenchAttachTotalMax {
			break
		}
		total += len(raw)
		b.WriteString("\n[attachment: " + af.Name + "]\n")
		b.Write(raw)
	}
	return b.String(), expMissing, unexpMissing
}

// TestExternalBench_AttachmentSubset 有数据口径（description + 文本附件）。
//
// 🔴 只报告不断言命中率；但「清单与实物脱节」必须 fail-closed（完整性故障）。
func TestExternalBench_AttachmentSubset(t *testing.T) {
	doc := loadExternalBench(t)
	pr := NewPresolver(zap.NewNop())

	ids := make([]string, 0, len(doc.Problems))
	for id, p := range doc.Problems {
		if len(p.AttachmentFiles) > 0 {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		t.Skip("无附件可用的题（先跑 scripts/build_external_bench.py 复制附件）")
	}

	t.Logf("=== 外部真题对照尺 · 有数据子集（%d 题，description + 文本附件，二进制跳过）===", len(ids))
	for _, m := range []struct {
		label         string
		includeAnsKey bool
	}{
		{"含答案形态附件", true},
		{"剔除答案形态附件", false},
	} {
		hits, hitIDs, expMissing, unexpMissing := 0, []string{}, 0, 0
		for _, id := range ids {
			p := doc.Problems[id]
			att, em, um := loadExternalBenchAttachments(p, m.includeAnsKey)
			expMissing += em
			unexpMissing += um
			res := pr.Presolve(context.Background(),
				&Challenge{ID: id, Category: p.Category, Description: p.Description + att}, nil)
			if res == nil || !res.Solved || len(res.Flags) == 0 {
				continue
			}
			sum := sha256.Sum256([]byte(res.Flags[0]))
			if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
				hits++
				hitIDs = append(hitIDs, id)
			}
		}
		t.Logf("  生产路径｜%s：%d/%d", m.label, hits, len(ids))
		if len(hitIDs) > 0 {
			t.Logf("      命中题号：%s", strings.Join(hitIDs, ", "))
		}
		t.Logf("      附件缺失记账：预期缺失(git 排除答案文件) %d｜异常缺失 %d", expMissing, unexpMissing)
		if unexpMissing > 0 {
			t.Errorf("🔴 %d 个非排除附件文件在磁盘上不存在——external_bench.json 清单与实物脱节，"+
				"请重跑 scripts/build_external_bench.py", unexpMissing)
		}
	}
	t.Logf("🔴 本子集命中数不得写入对外材料当战果。")
}

// TestExternalBench_PayloadLedgerHolds 载荷台账自洽钉子（fail-closed）。
//
// 为什么需要：westlake 80 题的教训是「声明齐全 ≠ 实物存在」——json 里写
// payload_status=verified_on_disk 而磁盘 0 题可解析，门禁照样绿。
// 本尺的价值全在「载荷齐全」这一点上，故必须由代码逐题验，不能靠生成器的自我声明。
func TestExternalBench_PayloadLedgerHolds(t *testing.T) {
	doc := loadExternalBench(t)
	complete := 0
	partial := []string{}
	for id, p := range doc.Problems {
		if p.PayloadComplete {
			complete++
		} else {
			partial = append(partial, id)
		}
		// 声明"齐全"的题，其登记附件数必须等于声明附件数，且每个文件都在磁盘上。
		if p.PayloadComplete {
			if p.AttachmentPresent != p.AttachmentDeclared {
				t.Errorf("🔴 %s 声明载荷齐全，但登记附件 %d ≠ 声明 %d",
					id, p.AttachmentPresent, p.AttachmentDeclared)
			}
			for _, af := range p.AttachmentFiles {
				path := filepath.Join("..", "..", externalBenchDir, externalBenchAttachDir, p.ID, af.Name)
				if _, err := os.Stat(path); err != nil {
					t.Errorf("🔴 %s/%s 声明齐全但磁盘不存在：%v", id, af.Name, err)
				}
			}
		}
	}
	sort.Strings(partial)
	if complete != doc.Honesty.PayloadComplete {
		t.Errorf("🔴 逐题计数 %d 与 honesty.payload_complete %d 不一致——产物与台账脱节",
			complete, doc.Honesty.PayloadComplete)
	}
	if len(partial) != doc.Honesty.PayloadPartial {
		t.Errorf("🔴 载荷不全题数 %d 与 honesty.payload_partial %d 不一致",
			len(partial), doc.Honesty.PayloadPartial)
	}
	t.Logf("载荷齐全 %d 题；载荷不全 %d 题：%s", complete, len(partial), strings.Join(partial, ", "))
}

// TestExternalBench_NotInKpiBenchmarks 反注水钉子：本尺题目**不得**混进自产池/能力分母。
//
// 为什么需要：本尺数字（大概率很低）一旦被算进 `data/ctf_benchmark/` 的分母会成为假分母；
// 反过来，若有人为了"让自产集数字更好看"而把外部题改标成自产题，同样污染 KPI。
//
// 2026-11-08 修（ci run 42473964764）——原判据只做 `strings.Contains(全文, 题号)`，
// 而 `data/ctf_benchmark/purellm_clean_benchmark*.json` 是**分池合并的清洁语料**：
// 外部题以 `pool:"external"` 登记在其中（下游按 pool 过滤，不计能力分母），
// 于是同一份日志里既报「40 题混入」、又在末尾无条件打印「均未混入」（两段自相矛盾）。
// 现在的判据分两点，都是结构化的：
//   ① 外部题若出现在语料里，**必须**带 pool=external；改标/缺标 = 被搬进自产池 → 红；
//   ② 只认可判分条目（带 flag_sha256 的题目对象），台账里的裸题号不算"混入"。
func TestExternalBench_NotInKpiBenchmarks(t *testing.T) {
	ext := loadExternalBench(t)
	if len(ext.Problems) == 0 {
		t.Fatal("external_bench.json 无题目——无法执行反注水钉子")
	}
	externalIDs := map[string]bool{}
	for id := range ext.Problems {
		externalIDs[id] = true
	}
	kpiFiles, _ := filepath.Glob(filepath.Join("..", "..", "data", "ctf_benchmark", "*.json"))
	// 🔴 2026-11-08 又一次自伤（同一个钉子内）：上一版把 `purellm_*` 一律排除，
	// 理由是"那是评测集不是 KPI 基准"。但实测 `data/ctf_benchmark/purellm_clean_benchmark.json`
	// / `purellm_clean_benchmark_v2.json`（都已入仓、denominator=160、按 pool 分池）**正是**
	// 外部题被登记的地方（40 题里 39 题以 pool=external 登记在这两份里）。排除它们之后，
	// 判据看到的语料里一条外部题都没有，于是打印「0 题混入、0 题登记」——把"看不见"当成了
	// "干净"。判据把该看的东西关在门外，比没有判据更危险。
	// 现在只排除**审计台账**（记录"过去暴露过什么"，不是判分语料），其余逐份核对。
	filtered := make([]string, 0, len(kpiFiles))
	auditLedgers := 0
	for _, f := range kpiFiles {
		if filepath.Base(f) == "history_exposure.json" {
			auditLedgers++
			continue
		}
		filtered = append(filtered, f)
	}
	kpiFiles = filtered
	if len(kpiFiles) == 0 {
		t.Fatal("未找到 data/ctf_benchmark/*.json——KPI 基准目录缺失，钉子无法生效（fail-closed）")
	}
	violations := 0
	labelled := map[string]bool{}   // 以外部池正确登记的外部题
	checked := 0
	for _, f := range kpiFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读取 KPI 基准失败 %s: %v", f, err)
		}
		var kpi any
		if err := json.Unmarshal(raw, &kpi); err != nil {
			t.Fatalf("KPI 基准不是合法 JSON %s: %v（判据无法结构化，fail-closed）",
				filepath.Base(f), err)
		}
		entries := map[string]map[string]bool{}   // id -> 该 id 出现过的所有 pool 取值
		collectJudgeableEntries(kpi, entries)
		for id, pools := range entries {
			if !externalIDs[id] {
				continue
			}
			if pools["external"] || pools["ext88"] || pools["cybench"] || pools["heldout"] {
				// 同为外采/对照池，允许保留，但必须显式标注；不算并入自产集。
				labelled[id] = true
				continue
			}
			t.Errorf("🔴 外部尺题目 %s 在 KPI 基准 %s 中**未标注外部池**"+
				"（pool=%v）——外部题被改标/并入自产集会污染能力分母",
				id, filepath.Base(f), sortedKeys(pools))
			violations++
		}
		// 脱钩检测（与 scripts/check_external_bench.py::C4 同口径）：
		// 题号出现在全文里、却没有任何结构化记录（连 {"id": ...} 都没有）→ 判据看不见它，
		// 此时 PASS 只是"我没找见"，不是"没混入"。
		for id := range externalIDs {
			if _, ok := entries[id]; ok {
				continue
			}
			if strings.Contains(string(raw), id) {
				t.Errorf("🔴 外部尺题目 %s 出现在 KPI 基准 %s 中但没有任何结构化记录"+
					"（裸题号即投放形态）——判据与语料形态脱钩，fail-closed",
					id, filepath.Base(f))
				violations++
			}
		}
		checked++
	}
	// fail-closed：语料里一条外部题的登记记录都看不见 ⇒ 判据与语料形态脱钩，
	// 这时 PASS 只证明"我什么都没看见"，不证明"没混入"（AGENTS.md 第零类假绿）。
	if len(labelled) == 0 {
		t.Fatalf("外部尺 %d 题在 %d 个 KPI 语料文件里**一条登记记录都没找到**——"+
			"判据（collectJudgeableEntries 认的 {id, pool} 形态）与语料已经脱钩，"+
			"此时 PASS 只表示看不见，不表示没混入（fail-closed）",
			len(externalIDs), checked)
	}
	if violations == 0 {
		t.Logf("已核对 %d 个 KPI 语料文件（另跳过 %d 份审计台账）：外部尺 %d 题中 %d 题以外部池"+
			"显式登记（不计能力分母），%d 题未出现在语料中（未登记不构成污染），0 题被改标为自产池",
			checked, auditLedgers, len(externalIDs), len(labelled),
			len(externalIDs)-len(labelled))
	}
}

// collectJudgeableEntries 递归收集「结构化题号记录」：id → 该 id 出现过的所有 pool 取值。
//
// 🔴 2026-11-08 改（原判据与语料形态脱钩）：上一版只认同时含 id 与 flag_sha256 的对象，
// 于是构建清单 `*.manifest.json`（actions 里是 id+pool+action，**天然没有 flag_sha256**）
// 被当成"题号出现却无条目"→ fail-closed 红一片，而那份清单其实把 84 条外部题
// 老老实实标成了 external/ext88/cybench/heldout。
// 真正要盯的是 pool（能力分母就定在 pool 上），哈希不是必要条件：
//   · 有 id + 有 pool → 判 pool；
//   · 有 id 但 pool 缺失/写成 real → 违规；
//   · id 只在裸文本里出现、没有任何结构化记录 → 脱钩，fail-closed（由调用方判）。
func collectJudgeableEntries(v any, out map[string]map[string]bool) {
	switch node := v.(type) {
	case map[string]any:
		if id, _ := node["id"].(string); id != "" {
			pool, _ := node["pool"].(string)
			if out[id] == nil {
				out[id] = map[string]bool{}
			}
			out[id][pool] = true
		}
		for _, child := range node {
			collectJudgeableEntries(child, out)
		}
	case []any:
		for _, child := range node {
			collectJudgeableEntries(child, out)
		}
	}
}

// sortedKeys 让报错里的 pool 取值顺序稳定（map 遍历顺序随机会让同一问题两种输出）。
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == "" {
			keys = append(keys, "<缺失>")
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
