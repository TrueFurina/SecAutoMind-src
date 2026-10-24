package ctfplatform

// crossbench_binary_test.go —— A→B 同卷立尺 · 二进制附件子集（2026-10-24 融合补齐）。
//
// 与 TestCrossBench_AttachmentSubset（文本口径，二进制跳过）互补：本子集把
// 二进制附件**原样字节**经 attachments map 喂给生产/注册表 presolve，
// 衡量 B 侧二进制嵌入 flag 提取能力（对齐 A 库「flag_pattern 附件直扫 +
// sha256 仲裁修复」，动机实证 = real_reverse_upx 阶段 1 立尺 miss）。
//
// 🔴 诚实边界（沿袭 crossbench 纪律）：
//   - 只报告不断言命中率（12/88 部分完整输入，不设 CI 红线）；
//   - 清单与实物脱节仍 fail-closed（非排除附件磁盘缺失 → Errorf）；
//   - 剔除答案形态附件（flag.*），只衡量真实解题能力；
//   - 双指标不冒充：「首位命中」= 生产等价（Flags[0] sha256 验过）；
//     「候选含真值」= 诊断口径（真值在候选列表但未排首）。
//   - 本子集命中数不得写进对外材料当战果。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// loadCrossBenchBinaryAttachments 原样加载附件字节（不跳二进制、不截断、剔除答案文件）。
// 返回 attachments map（name → 原始内容）与缺失记账。
func loadCrossBenchBinaryAttachments(p crossBenchProblem, includeAnswerKey bool) (map[string]string, int, int) {
	atts := make(map[string]string)
	expMissing, unexpMissing := 0, 0
	for _, af := range p.AttachmentFiles {
		if af.AnswerKeyShape && !includeAnswerKey {
			continue // 剔除口径：跳过答案形态附件（flag.* 前缀 / 显式登记的含答案文件）
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
		if len(raw) > crossBenchAttachTotalMax {
			raw = raw[:crossBenchAttachTotalMax]
		}
		atts[af.Name] = string(raw)
	}
	return atts, expMissing, unexpMissing
}

// TestCrossBench_BinaryAttachmentSubset 二进制附件子集立尺。
func TestCrossBench_BinaryAttachmentSubset(t *testing.T) {
	doc := loadCrossBench(t)
	pr := NewPresolver(zap.NewNop())

	ids := make([]string, 0, len(doc.Problems))
	for id, p := range doc.Problems {
		if p.AttachmentAvailable {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		t.Skip("无附件可用的题（先跑 scripts/build_cross_bench.py 复制附件）")
	}

	t.Logf("=== A→B 同卷立尺 · 二进制子集（附件仍在的 %d 题，原样字节入 attachments map）===", len(ids))
	modes := []struct {
		label         string
		includeAnsKey bool
	}{
		{"含答案文件（真实赛制）", true},
		{"剔除答案文件", false},
	}
	paths := []struct {
		name string
		fn   func(*Challenge, map[string]string) *PresolveResult
	}{
		{"生产路径", func(ch *Challenge, atts map[string]string) *PresolveResult {
			return pr.Presolve(context.Background(), ch, atts)
		}},
		{"注册表路径", func(ch *Challenge, atts map[string]string) *PresolveResult {
			return pr.PresolveWithRegistry(context.Background(), ch, atts)
		}},
	}
	for _, path := range paths {
		for _, m := range modes {
			firstHits, anyHits := 0, 0
			var firstIDs, anyOnlyIDs []string
			expMissing, unexpMissing := 0, 0
			for _, id := range ids {
				p := doc.Problems[id]
				atts, em, um := loadCrossBenchBinaryAttachments(p, m.includeAnsKey)
				expMissing += em
				unexpMissing += um
				ch := &Challenge{ID: id, Category: p.Category, Description: p.Description}
				res := path.fn(ch, atts)
				if res == nil || !res.Solved || len(res.Flags) == 0 {
					continue
				}
				any := false
				for _, f := range res.Flags {
					sum := sha256.Sum256([]byte(f))
					if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
						any = true
						break
					}
				}
				sum0 := sha256.Sum256([]byte(res.Flags[0]))
				first := hex.EncodeToString(sum0[:]) == p.FlagSHA256
				if first {
					firstHits++
					firstIDs = append(firstIDs, id)
				}
				if any {
					anyHits++
					if !first {
						anyOnlyIDs = append(anyOnlyIDs, id)
					}
				}
			}
			t.Logf("  %s｜%s：首位命中 %d/%d（生产等价）｜候选含真值 %d/%d（诊断口径）",
				path.name, m.label, firstHits, len(ids), anyHits, len(ids))
			if len(firstIDs) > 0 {
				t.Logf("      首位命中题号：%s", strings.Join(firstIDs, ", "))
			}
			if len(anyOnlyIDs) > 0 {
				t.Logf("      真值在候选但未排首（排序改进候选）：%s", strings.Join(anyOnlyIDs, ", "))
			}
			t.Logf("      附件缺失记账：预期缺失(git排除答案文件) %d｜异常缺失 %d", expMissing, unexpMissing)
			if unexpMissing > 0 {
				t.Errorf("🔴 %d 个非排除附件文件在磁盘上不存在——cross_bench.json 清单与实物脱节，"+
					"请重跑 scripts/build_cross_bench.py", unexpMissing)
			}
		}
	}
	t.Logf("🔴 提醒：12/88 为部分完整输入；含/剔除两口径互不冒充（同文本子集纪律）。")
	t.Logf("🔴 本子集命中数不得写进对外材料当战果（cross_bench 仅作尺，不并入 KPI 基准）。")
}
