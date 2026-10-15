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
//     默认口径只喂 `description`（文本口径），测得的是 B 的**下限**，不是能力上限。
//     对附件仍在的 12 题，`TestCrossBench_AttachmentSubset` 另跑「有数据子集」口径，
//     且**含/剔除 flag.* 答案形态附件分别报告**，互不冒充。
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
	"strings"
	"testing"

	"go.uber.org/zap"
)

type crossBenchProblem struct {
	ID                  string                 `json:"id"`
	Category            string                 `json:"category"`
	Sub                 string                 `json:"sub"`
	Description         string                 `json:"description"`
	Title               string                 `json:"title"`
	FlagSHA256          string                 `json:"flag_sha256"`
	AttachmentAvailable bool                   `json:"attachment_available"`
	AttachmentFiles     []crossBenchAttachment `json:"attachment_files,omitempty"`
}

// crossBenchAttachment 登记一个已复制进 bench 目录的附件文件（由 build_cross_bench.py 生成）。
type crossBenchAttachment struct {
	Name           string `json:"name"`
	Size           int    `json:"size"`
	AnswerKeyShape bool   `json:"answer_key_shape"` // flag.* 前缀或登记的"题目本体含答案"文件
	GitExcluded    bool   `json:"git_excluded"`     // flag 明文/内嵌答案：只留本地，不进 PUBLIC 仓
	ExcludeReason  string `json:"exclude_reason"`
	// SHA256/RecoveredFrom（2026-10-15 补字段）：文件被 git 排除后 CI 检出读不到它，
	// 指纹+出处成为"登记契约"唯一可机验的锚点（见 TestRecoveredAttachmentHasInstanceTruth）。
	SHA256        string `json:"sha256"`
	RecoveredFrom string `json:"recovered_from"`
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

const (
	crossBenchAttachDir      = "attachments"
	crossBenchAttachMaxByte  = 512 * 1024  // 单文件截断：实测库内最大文本附件 163KB（simplelegendre output）
	crossBenchAttachTotalMax = 1024 * 1024 // 单题总截断：按现实题目体量留 ~3x 余量
	crossBenchBinaryRatio    = 0.3         // 首 4KB 不可打印字节占比超过此值 → 判二进制跳过
)

// ⚠️ 截断上限修订记录（2026-10-15，立尺口径修正，勿改回 4KB）：
// 旧值 4KB/文件、16KB/题，注释理由「数值型大 output 对正则扫描是纯成本」——
// 该判断对逐位加密题恰好相反：**数字本身就是题目数据**。实测 simplelegendre
// 的 output 有 163KB（phi + N + 264 个密文，恢复 264 比特 flag 需全部密文），
// 4KB 截断后只剩个位数密文 → 求解器数据不完整而不可解，被误记为「能力缺口」。
// 人类选手拿的是全量 output，harness 截断属**测量管道缺陷**（低估能力），
// 不是保守口径。修正后两种影响：
//   - simplelegendre 数据完整，legendre_bit_phi 可解（立尺 3/12 → 4/12）；
//   - 全量文本会进入全部注册求解器，最坏耗时由 solver 侧单独约束
//     （Håstad 裸数字回退按 12 数字封顶，见 presolve_crypto.go）。
// 答案文件排除逻辑（AnswerKeyShape/GitExcluded）不受本修订影响，防作弊边界不变。

// looksBinary 按内容判定二进制（presolve 是静态文本分析，喂原始字节无意义）。
func looksBinary(raw []byte) bool {
	n := len(raw)
	if n > 4096 {
		n = 4096
	}
	if n == 0 {
		return false
	}
	bad := 0
	for _, c := range raw[:n] {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c >= 0x7f {
			bad++
		}
	}
	return float64(bad)/float64(n) > crossBenchBinaryRatio
}

// loadCrossBenchAttachments 把某题已入仓的附件内容拼进描述（按上限截断，边界写进日志）。
// includeAnswerKey=false 时剔除 flag.* 答案形态文件——衡量真实解题能力，
// 而非"附件当场给答案"（后者按真实赛制计入，但必须单独一列）。
// 二进制附件（PE/ELF 等）跳过：presolve 不做二进制分析，喂字节只会虚增耗时。
// 返回值第二个/第三个分别为「预期缺失」（git 排除的答案文件，CI 检出不含属正常）
// 与「异常缺失」（非排除文件不在磁盘上——那意味着清单与实物脱节，必须显式记账）。
func loadCrossBenchAttachments(p crossBenchProblem, includeAnswerKey bool) (string, int, int) {
	var b strings.Builder
	total, expMissing, unexpMissing := 0, 0, 0
	for _, af := range p.AttachmentFiles {
		if af.AnswerKeyShape && !includeAnswerKey {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", "data", "questions_real_bench",
			crossBenchAttachDir, p.ID, af.Name))
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

// runCrossBenchSubset 仅对附件仍在的题跑 presolve（描述 + 附件内容），返回命中数、
// 命中题号、附件缺失记账（预期缺失=git 排除的答案文件；异常缺失=清单与实物脱节）。
func runCrossBenchSubset(doc crossBenchDoc, includeAnswerKey bool,
	fn func(*Challenge) *PresolveResult,
) (hits int, hitIDs []string, expMissing, unexpMissing int) {
	ids := make([]string, 0, len(doc.Problems))
	for id, p := range doc.Problems {
		if p.AttachmentAvailable {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := doc.Problems[id]
		att, em, um := loadCrossBenchAttachments(p, includeAnswerKey)
		expMissing += em
		unexpMissing += um
		desc := p.Description + att
		res := fn(&Challenge{ID: id, Category: p.Category, Description: desc})
		if res == nil || !res.Solved || len(res.Flags) == 0 {
			continue
		}
		sum := sha256.Sum256([]byte(res.Flags[0]))
		if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
			hits++
			hitIDs = append(hitIDs, id)
		}
	}
	return hits, hitIDs, expMissing, unexpMissing
}

// TestCrossBench_AttachmentSubset 对「附件仍在的 12 题」跑有数据口径（规划 §7 第 3 条）。
//
// 🔴 只报告不断言**命中率**：输入仍是部分完整（12/88），绝不把命中率变成 CI 红灯
// （那会逼出为了转绿而改阈值的退化）。
// 🔴 但「清单与实物脱节」是完整性故障，必须 fail-closed：非 git 排除的附件文件
// 在磁盘上不存在 → t.Errorf 直接红。这与"不拿命中率问责"是两件事，禁止为转绿删它。
// 🔴 两个口径互不冒充：
//   - 含 flag.* 答案形态附件——按真实赛制计入（附件当场给答案也是题型设计）；
//   - 剔除答案形态附件——衡量真实解题能力。
//
// 🔴 该子集命中不得写进对外材料当战果（cross_bench 仅作尺，不并入 KPI 基准）。
// ⚠️ 附件内容按 512KB/文件、1MB/题 截断（2026-10-15 由 4KB/16KB 上调，
// 修订理由见 crossBenchAttachMaxByte 上方记录），二进制附件（PE/ELF）跳过——
// presolve 是静态文本分析，喂原始字节只会虚增耗时（CI cross-bench-subset job
// 有 600s 预算；求解器侧最坏耗时由 Håstad 裸数字回退的配对数封顶单独约束）。
// 文本口径对比见 TestCrossBench_AgainstXihuRealQuestions
// （其中"附件仍存在的题命中 0"即本子集的文本基线）。
func TestCrossBench_AttachmentSubset(t *testing.T) {
	doc := loadCrossBench(t)
	pr := NewPresolver(zap.NewNop())

	total := 0
	for _, p := range doc.Problems {
		if p.AttachmentAvailable {
			total++
		}
	}
	if total == 0 {
		t.Skip("无附件可用的题（先跑 scripts/build_cross_bench.py 复制附件）")
	}

	t.Logf("=== A→B 同卷立尺 · 有数据子集（附件仍在的 %d 题，description + 文本附件，512KB/文件截断，二进制跳过）===", total)
	modes := []struct {
		label         string
		includeAnsKey bool
	}{
		{"文本+附件（含 flag.* 答案文件）", true},
		{"文本+附件（剔除答案文件）", false},
	}
	paths := []struct {
		name string
		fn   func(*Challenge) *PresolveResult
	}{
		{"生产路径", func(ch *Challenge) *PresolveResult { return pr.Presolve(context.Background(), ch, nil) }},
		{"注册表路径", func(ch *Challenge) *PresolveResult { return pr.PresolveWithRegistry(context.Background(), ch, nil) }},
	}
	for _, path := range paths {
		for _, m := range modes {
			hits, ids, expMissing, unexpMissing := runCrossBenchSubset(doc, m.includeAnsKey, path.fn)
			t.Logf("  %s｜%s：%d/%d", path.name, m.label, hits, total)
			if len(ids) > 0 {
				t.Logf("      命中题号：%s", strings.Join(ids, ", "))
			}
			t.Logf("      附件缺失记账：预期缺失(git排除答案文件) %d｜异常缺失 %d", expMissing, unexpMissing)
			if unexpMissing > 0 {
				t.Errorf("🔴 %d 个非排除附件文件在磁盘上不存在——cross_bench.json 清单与实物脱节，"+
					"请重跑 scripts/build_cross_bench.py", unexpMissing)
			}
		}
	}
	t.Logf("🔴 提醒：12/88 为部分完整输入；含答案口径按真实赛制计入，剔除口径衡量真实解题能力。")
	t.Logf("🔴 本子集命中数不得写进对外材料当战果（cross_bench 仅作尺，不并入 KPI 基准）。")
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
