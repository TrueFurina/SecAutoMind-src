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
