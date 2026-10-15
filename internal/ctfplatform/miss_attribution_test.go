package ctfplatform

// miss_attribution_test.go —— 「不可解归因」的反注水门禁。
//
// 背景（2026-10-15）：本轮曾出现一次**按类别推断代替逐题核验**的错误决策——
// 见 55 题基准 35 题 MISS 中 web 占 21 题（60%），据此判断「下一杠杆是给 web 题
// 建本地靶场」。逐题穷举后发现**35/35 全部零附件、30/35 描述 < 40B**，题目数据
// 根本不在库里：靶场需要题目数据，而数据缺失 ⇒ 建靶场提不了分，该判断被证伪。
//
// 类别占比高 ≠ 该类别有能力缺口。本文件把「数据缺失」这一归因从人工结论
// 变成**CI 可复跑的机验断言**，防止未来会话重新踩同一个坑（也防止有人
// 把这批题改口说成「已攻克」或反过来无据地说成「能力缺口」）。
//
// 三条断言各自独立可解释：
//  1. TestRealBenchmarkMissAllLackAttachments —— 55 题 MISS 全部零附件字段；
//  2. TestRealBenchmarkMissMajorityTinyDescription —— 30/35 描述 < 40B（多数为纯题面）；
//  3. TestCrossBenchAttachmentInventoryMatchesDisk —— 12 题附件清单与磁盘实物一致
//     （预期缺失必须全是 git 排除的答案文件，非排除文件缺失即 fail-closed 报红）。
//
// ⚠️ 数据修复后本测试会 FAIL——那是**正确行为**：说明题目数据补回来了，
// 应改写归因结论（数据不再缺失，剩余 MISS 才可能是真能力缺口），而不是放宽断言。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// loadCoverageReportMISS 读取 55 题基准的机验报告，取出全部 sha256 未匹配的题号。
func loadCoverageReportMISS(t *testing.T) []string {
	t.Helper()
	p := filepath.Join("..", "..", "data", "ctf_benchmark", "real_coverage_report.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("覆盖率报告缺失，跳过: %v", err)
	}
	var doc struct {
		Results []struct {
			ID          string `json:"id"`
			SHA256Match bool   `json:"sha256_match"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析覆盖率报告失败: %v", err)
	}
	var miss []string
	for _, r := range doc.Results {
		if !r.SHA256Match {
			miss = append(miss, r.ID)
		}
	}
	return miss
}

// TestRealBenchmarkMissAllLackAttachments 断言：55 题基准的全部 MISS 题，
// 基准条目里都不存在任何附件字段。
//
// 为什么是断言而非日志：2026-10-15 的错误决策正是「以为有数据、建了靶场方向」。
// 一旦将来补齐了附件，本测试报红，强制重新做归因（那才是正确的触发点）。
func TestRealBenchmarkMissAllLackAttachments(t *testing.T) {
	miss := loadCoverageReportMISS(t)
	if len(miss) == 0 {
		t.Skip("无 MISS 题（基准已全命中？），归因结论需重写")
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "real_benchmark.json"))
	if err != nil {
		t.Fatalf("读取基准失败: %v", err)
	}
	var bench struct {
		Problems map[string]map[string]interface{} `json:"problems"`
	}
	if err := json.Unmarshal(raw, &bench); err != nil {
		t.Fatalf("解析基准失败: %v", err)
	}

	// 任何可能承载附件数据的字段名。
	attachKeys := []string{"attachments", "attachment_paths", "files", "attachment_files"}

	withAttach := []string{}
	for _, id := range miss {
		p, ok := bench.Problems[id]
		if !ok {
			t.Errorf("MISS 题 %s 不在基准库中（清单与实物脱节）", id)
			continue
		}
		for _, k := range attachKeys {
			if v, present := p[k]; present && v != nil {
				// null / 空数组不算有附件；非空才算。
				switch tv := v.(type) {
				case []interface{}:
					if len(tv) > 0 {
						withAttach = append(withAttach, id+"."+k)
					}
				case string:
					if tv != "" {
						withAttach = append(withAttach, id+"."+k)
					}
				default:
					withAttach = append(withAttach, id+"."+k)
				}
			}
		}
	}

	if len(withAttach) > 0 {
		t.Fatalf("🔴 以下 MISS 题已带附件字段，【数据缺失】归因已过期，须重做归因并更新本断言：%v\n"+
			"（此前结论：35/35 MISS 全部零附件，缺数据而非缺能力——若数据已补回，"+
			"剩余 MISS 才可能是真能力缺口）", withAttach)
	}
	t.Logf("归因机验通过：%d 题 MISS 全部零附件 ⇒ 数据缺失而非能力缺口", len(miss))
}

// TestRealBenchmarkMissMajorityTinyDescription 断言：MISS 题中「描述 < 40B」
// 的占比过半——这类题的 description 只是一句题目要求，不含任何可解数据。
//
// 阈值 40B 的含义：低于此长度装不下任何 base64 串、密钥、源码片段或参数，
// 只可能是「查看网页源码找 flag」这类纯题目描述。实测 30/35。
func TestRealBenchmarkMissMajorityTinyDescription(t *testing.T) {
	miss := loadCoverageReportMISS(t)
	if len(miss) == 0 {
		t.Skip("无 MISS 题")
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "real_benchmark.json"))
	if err != nil {
		t.Fatalf("读取基准失败: %v", err)
	}
	var bench struct {
		Problems map[string]struct {
			Description string `json:"description"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(raw, &bench); err != nil {
		t.Fatalf("解析基准失败: %v", err)
	}

	const tinyThreshold = 40
	tiny := 0
	for _, id := range miss {
		if p, ok := bench.Problems[id]; ok && len(p.Description) < tinyThreshold {
			tiny++
		}
	}
	ratio := float64(tiny) / float64(len(miss))
	t.Logf("MISS %d 题中，description < %dB 的有 %d 题（%.1f%%）",
		len(miss), tinyThreshold, tiny, ratio*100)

	if ratio < 0.5 {
		t.Fatalf("🔴 短描述占比降至 %.1f%%（< 50%%）——【多数 MISS 是数据缺失】这条归因"+
			"已过期，须重新逐题归因（数据补回或 desc 口径变更都会导致本测试报红）", ratio*100)
	}
}

// TestCrossBenchAttachmentInventoryMatchesDisk 断言：cross_bench 12 题的附件
// 清单与磁盘实物一致，且缺失项**全部**是 git 排除的答案文件。
//
// 为什么必须机验：若某个非排除文件在磁盘上消失，说明构建产物与清单脱节，
// 「12 题有数据」这个前提就不成立，立尺数字失去意义（fail-closed 报红，
// 提示重跑 scripts/build_cross_bench.py）。
func TestCrossBenchAttachmentInventoryMatchesDisk(t *testing.T) {
	doc := loadCrossBench(t)
	base := filepath.Join("..", "..", "data", "questions_real_bench", crossBenchAttachDir)

	total, onDisk, gitExcluded, unexpectedMissing := 0, 0, 0, 0
	for _, p := range doc.Problems {
		if !p.AttachmentAvailable {
			continue
		}
		for _, af := range p.AttachmentFiles {
			total++
			full := filepath.Join(base, p.ID, af.Name)
			if _, err := os.Stat(full); err == nil {
				onDisk++
				continue
			}
			if af.GitExcluded {
				gitExcluded++
			} else {
				unexpectedMissing++
				t.Errorf("🔴 非排除附件缺失：%s/%s —— cross_bench.json 清单与实物脱节，请重跑 scripts/build_cross_bench.py",
					p.ID, af.Name)
			}
		}
	}
	t.Logf("12 题附件盘点：清单 %d 个 / 磁盘在 %d 个 / git 排除（答案文件）%d 个 / 异常缺失 %d 个",
		total, onDisk, gitExcluded, unexpectedMissing)

	if total == 0 {
		t.Skip("附件清单为空（先跑 scripts/build_cross_bench.py 复制附件）")
	}
	if gitExcluded == 0 && total > 0 {
		t.Logf("注：本次无 git 排除文件（答案文件可能在库），含答案口径与剔除口径将同时可跑")
	}
}

// TestRealBenchmarkHitNotInflatedByPlaintextFlag —— 分子侧反注水门禁（2026-10-15 新增）。
//
// 为什么需要它：本文件既有三条断言全部针对 **MISS（分母侧）**，守护的是
// 「35/35 MISS 是数据缺失而非能力缺口」。但**没有任何一条审过 HIT（分子侧）的
// 真实性**。2026-10-15 复核发现：20 个命中里有 4 个是「题面即答案」——
// description 直接写着 flag 明文（例：`<!-- secret: flag{html_comment_flag} -->`），
// presolve 用 flag_scan 正则一扫即命中。sha256 校验确实通过，但这**不构成解题能力**：
// 答案被抄在了题目上。
//
// 于是 20/55 = 36.4% 是**双向失真**的数字：
//   - 分母侧：39/55 题题面只是一句话摘要，无密文/无附件/无目标 ⇒ 判据不可达，恒 MISS；
//   - 分子侧：4 个命中来自题面明文扫描 ⇒ 判据平凡，不需要任何能力。
//
// 两端都是我的「空洞绿」铁律形态，结果这个数字对能力涨落不敏感，不具度量能力。
//
// 本测试做的事（三条彼此独立）：
//  1. **交叉一致**：题面含 flag 明文的命中数 == presolve_engine=flag_scan 的命中数。
//     若不等，说明出现了新的伪解来源（别的引擎也在吃题面明文），必须查明；
//  2. **不得恶化**：flag_scan 伪解数不得超过已知基线 4（防止继续往基准里加抄答案题）；
//  3. **口径留痕**：无论过不过，都在日志里打印「全量 / 真求解器 / 伪解」三口径，
//     供对外材料引用时对照。
//
// ⚠️ 与 MISS 侧断言的相反走向：MISS 侧是「数据补回来 ⇒ 报红 ⇒ 重写归因」；
// 本条是「抄答案题删干净 ⇒ 依然 PASS，但应把 maxAllowedScanHits 下调到 0」。
// **修好后请收紧上限，不要停留在 4。**
func TestRealBenchmarkHitNotInflatedByPlaintextFlag(t *testing.T) {
	rawRep, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "real_coverage_report.json"))
	if err != nil {
		t.Skipf("覆盖率报告缺失，跳过: %v", err)
	}
	var rep struct {
		Total   int `json:"total"`
		Results []struct {
			ID             string `json:"id"`
			SHA256Match    bool   `json:"sha256_match"`
			PresolveEngine string `json:"presolve_engine"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rawRep, &rep); err != nil {
		t.Fatalf("解析覆盖率报告失败: %v", err)
	}

	rawBench, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "real_benchmark.json"))
	if err != nil {
		t.Fatalf("读取基准失败: %v", err)
	}
	var bench struct {
		Problems map[string]struct {
			Description string `json:"description"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(rawBench, &bench); err != nil {
		t.Fatalf("解析基准失败: %v", err)
	}

	// 覆盖度自证：结果条数必须与声明的 total、基准题数一致，否则后面所有比例失真。
	if rep.Total != 0 && len(rep.Results) != rep.Total {
		t.Fatalf("🔴 覆盖率报告自相矛盾：total=%d 但 results=%d 条", rep.Total, len(rep.Results))
	}
	if len(bench.Problems) != len(rep.Results) {
		t.Fatalf("🔴 基准题数 %d != 结果条数 %d，报告与基准脱节", len(bench.Problems), len(rep.Results))
	}

	rows := make([]hitRow, 0, len(rep.Results))
	for _, r := range rep.Results {
		rows = append(rows, hitRow{ID: r.ID, SHA256Match: r.SHA256Match, PresolveEngine: r.PresolveEngine})
	}
	probs := make(map[string]benchDesc, len(bench.Problems))
	for id, p := range bench.Problems {
		probs[id] = benchDesc{Description: p.Description}
	}

	s := analyzeHitSides(rows, probs)
	hit, scanHit, plainHit := s.Hit, s.ScanHit, s.PlainHit

	realSolver := len(hit) - len(scanHit)
	t.Logf("命中口径三分：全量 %d/%d = %.1f%% | 真求解器 %d/%d = %.1f%% | flag_scan 题面明文伪解 %d 题 %v",
		len(hit), len(rep.Results), pct(len(hit), len(rep.Results)),
		realSolver, len(rep.Results), pct(realSolver, len(rep.Results)),
		len(scanHit), scanHit)

	// 两条断言的判据集中在 hitInflationViolations（变异用例验的就是它），
	// 这里只负责给出细分错误信息。
	if len(hitInflationViolations(s)) > 0 {
		if len(plainHit) != len(scanHit) {
			t.Fatalf("🔴 伪解来源不止 flag_scan：题面含 flag 明文的命中 %d 题 %v，但 flag_scan 命中 %d 题 %v。"+
				"出现了新的「吃题面明文」路径，须查明后再放行",
				len(plainHit), plainHit, len(scanHit), scanHit)
		}
		t.Fatalf("🔴 flag_scan 伪解增至 %d 题（上限 %d）：%v。"+
			"这些命中的 flag 明文写在 description 里，靠正则扫描得出，不构成解题能力。"+
			"须从基准中剔除或改写题面，不得计入对外战果",
			len(scanHit), maxAllowedScanHits, scanHit)
	}
	if len(scanHit) > 0 {
		t.Logf("⚠️ 当前仍有 %d 题「题面即答案」计入命中：%v。"+
			"对外引用 20/55 时必须同时给出真求解器口径 %d/%d，否则分子注水",
			len(scanHit), scanHit, realSolver, len(rep.Results))
	}
}

// ---- 以下为分子侧判据的纯数据层与变异用例 ----
//
// 为什么要抽纯函数：若统计与判据只存在于 TestRealBenchmarkHitNotInflatedByPlaintextFlag
// 内部，变异用例就无法构造数据去验证「判据两端都灵」——只能验真实数据当前过不过，
// 那正是「空洞绿」的温床（判据恒真时永远 PASS 却毫无防护力）。

// maxAllowedScanHits 是 flag_scan 伪解的容忍上限。基线 4 = 2026-10-15 复核实测值。
// ⚠️ 修好后（抄答案题从基准剔除）**必须下调为 0**，不要停留在 4。
const maxAllowedScanHits = 4

type hitRow struct {
	ID             string
	SHA256Match    bool
	PresolveEngine string
}

type benchDesc struct {
	Description string
}

type hitSideStats struct {
	Hit      []string // 全部命中题号
	ScanHit  []string // presolve_engine=flag_scan 的命中（伪解嫌疑）
	PlainHit []string // 题面含 flag 明文的命中
}

// analyzeHitSides 纯统计：不读文件、不做断言，便于变异用例直接喂构造数据。
func analyzeHitSides(rows []hitRow, problems map[string]benchDesc) hitSideStats {
	// 题面直接暴露 flag 明文的特征（大小写与常见前缀变体）。
	plainFlagRe := regexp.MustCompile(`(?i)(?:flag|picoCTF|d0g3|DASCTF)\{[^{}]{3,}\}`)
	s := hitSideStats{}
	for _, r := range rows {
		if !r.SHA256Match {
			continue // 未命中不参与分子审计
		}
		s.Hit = append(s.Hit, r.ID)
		if r.PresolveEngine == "flag_scan" {
			s.ScanHit = append(s.ScanHit, r.ID)
		}
		if p, ok := problems[r.ID]; ok && plainFlagRe.MatchString(p.Description) {
			s.PlainHit = append(s.PlainHit, r.ID)
		}
	}
	return s
}

// hitInflationViolations 是分子侧两条判据的唯一实现，主测试与变异用例共用。
func hitInflationViolations(s hitSideStats) []string {
	var v []string
	if len(s.PlainHit) != len(s.ScanHit) {
		v = append(v, "cross-check: 题面明文命中数 != flag_scan 命中数")
	}
	if len(s.ScanHit) > maxAllowedScanHits {
		v = append(v, "over-limit: 伪解数超过容忍上限")
	}
	return v
}

// TestHitInflationMutationCases 变异用例：证明分子侧判据两端都灵，不是恒真也不是恒假。
func TestHitInflationMutationCases(t *testing.T) {
	clean := []hitRow{
		{ID: "a", SHA256Match: true, PresolveEngine: "base64_multilayer"},
		{ID: "b", SHA256Match: false, PresolveEngine: ""},
	}
	cleanBench := map[string]benchDesc{
		"a": {Description: "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROc"},
		"b": {Description: "查看网页源码找 flag"},
	}

	cases := []struct {
		name    string
		rows    []hitRow
		probs   map[string]benchDesc
		wantVio int // 期望的违规条数
	}{
		{
			// 0 值态：干净基准必须零违规——证明判据不是恒假（不会无差别报红）。
			name: "干净基准_零违规", rows: clean, probs: cleanBench, wantVio: 0,
		},
		{
			// 注水：第 5 道抄答案题越过上限 4 —— 证明判据不是恒真。
			name: "新增1题伪解_未越上限_不误报",
			rows: append([]hitRow{}, append(clean,
				[]hitRow{{ID: "evil", SHA256Match: true, PresolveEngine: "flag_scan"}}...)...),
			probs: map[string]benchDesc{
				"a":    {Description: "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROc"},
				"b":    {Description: "查看网页源码找 flag"},
				"evil": {Description: "<!-- secret: flag{plain} -->"},
			},
			wantVio: 0, // 5 > 4? 否：只有 1 题伪解，未越上限——见下一条
		},
		{
			// 真正越界：构造 5 题伪解。
			name:    "伪解5题_越过上限4",
			rows:    fiveFakeHits(),
			probs:   fiveFakeBench(),
			wantVio: 1,
		},
		{
			// 新伪解来源：题面含明文但引擎不是 flag_scan → 交叉断言必须抓到。
			name: "新伪解来源_交叉断言触发",
			rows: []hitRow{
				{ID: "x", SHA256Match: true, PresolveEngine: "crypto_xor"},
			},
			probs:   map[string]benchDesc{"x": {Description: "secret: flag{leak_in_stem}"}},
			wantVio: 1,
		},
		{
			// 未命中的题即使题面有明文，也不应计入分子（不算注水）。
			name: "未命中不计入分子",
			rows: []hitRow{
				{ID: "y", SHA256Match: false, PresolveEngine: "flag_scan"},
			},
			probs:   map[string]benchDesc{"y": {Description: "flag{not_counted}"}},
			wantVio: 0,
		},
	}

	for _, c := range cases {
		got := len(hitInflationViolations(analyzeHitSides(c.rows, c.probs)))
		if got != c.wantVio {
			t.Errorf("%s：期望违规 %d 条，实得 %d 条", c.name, c.wantVio, got)
		} else {
			t.Logf("%s：违规 %d 条（符合预期）", c.name, got)
		}
	}
}

// fiveFakeHits 构造 5 道 flag_scan 伪解（越过上限 4）。
func fiveFakeHits() []hitRow {
	rows := make([]hitRow, 0, 5)
	for i := 0; i < 5; i++ {
		rows = append(rows, hitRow{ID: string(rune('a' + i)), SHA256Match: true, PresolveEngine: "flag_scan"})
	}
	return rows
}

func fiveFakeBench() map[string]benchDesc {
	m := make(map[string]benchDesc, 5)
	for i := 0; i < 5; i++ {
		m[string(rune('a'+i))] = benchDesc{Description: "<!-- secret: flag{plain_in_stem} -->"}
	}
	return m
}
