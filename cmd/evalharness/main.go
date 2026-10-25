// Command evalharness —— SecAutoMind 生产管线离线 eval 集成件。
//
// 它用**真实生产代码路径**（internal/ctfplatform.Presolver）把真题基准集在单次运行里
// 统一跑完，产出一份可比的 eval_report.json。
//
// 与现有设施的分工（避免重复造轮子 / 避免不可比数字）：
//   - data/ctf_benchmark/run_all_benchmarks.py + judge_*.py 是 Python judge 镜像编排；
//   - internal/ctfplatform/*_test.go 是分集、分层的 Go 测试；
//   - cross 附件子集（12 题有数据口径，5/12=41.7%）由权威 TestCrossBench_AttachmentSubset
//     覆盖，其选法（JSON attachment_available 标志）与调用方式（附件文本内联进 description
//     后 Presolve(ch,nil)）均与本件不同源——故本件**有意不重抄该子集**，避免产出不可比数字。
//
// 本件覆盖的、且为真空白的：real(55)+cross(88) 在单次运行中统一出报告，并作为
// **Layer 3 (LLM) 的集成接入点**。
//
// 反 RDD 自检：本件必须复现已知真值（real 20/55=36.4%、cross 文本 0/88）才证明接的是
// 真生产代码，而非另起炉灶。
//
// Layer 3 接入点（诚实占位，不造假）：
//   真实 LLM 决策在 cmd/runner/llm_fallback.go 的 solve()（生产主循环）。当模型端点可用时，
//   在此新增一个 llmSolver，复用同一条 solve() 跑同样基准，重跑即得 Layer 3 对真实解题数
//   的真实贡献。本离线构建不接死 LLM，避免"假离线路径虚报提升"。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"secautomind-ai/internal/ctfplatform"
)

// problem 与 real_benchmark.json / cross_bench.json 的题目同构（只取 eval 需要的字段）。
type problem struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Sub        string `json:"sub"`
	Description string `json:"description"`
	Title      string `json:"title"`
	FlagSHA256 string `json:"flag_sha256"`
}

type resultRow struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Sub           string `json:"sub"`
	Engine        string `json:"presolve_engine"`
	Sha256Match   bool   `json:"sha256_match"`
	ExpectedSkill string `json:"expected_skill"`
}

type subsetReport struct {
	Name        string      `json:"name"`
	Mode        string      `json:"mode"` // "description-only"
	Total       int         `json:"total"`
	Hit         int         `json:"hit"`
	Miss        int         `json:"miss"`
	CoveragePct float64     `json:"coverage_pct"`
	Results     []resultRow `json:"results"`
}

type evalReport struct {
	GeneratedAt string         `json:"generated_at"`
	Note        string         `json:"note"`
	Subsets     []subsetReport `json:"subsets"`
}

// Solver 抽象当前只接生产确定性层；Layer 3 (LLM) 是未来的实现（见文件头注释）。
type solver interface {
	solve(ctx context.Context, p problem) (engine string, flags []string, solved bool)
}

type presolveSolver struct {
	pr *ctfplatform.Presolver
}

func (s *presolveSolver) solve(ctx context.Context, p problem) (string, []string, bool) {
	res := s.pr.Presolve(ctx, &ctfplatform.Challenge{
		ID:          p.ID,
		Category:    p.Category,
		Description: p.Description,
	}, nil)
	if res == nil {
		return "", nil, false
	}
	return res.Engine, res.Flags, res.Solved
}

func loadProblems(path string) map[string]problem {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] 读取 %s 失败: %v\n", path, err)
		return map[string]problem{}
	}
	var doc struct {
		Problems map[string]problem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] 解析 %s 失败: %v\n", path, err)
		return map[string]problem{}
	}
	return doc.Problems
}

func sortedIDs(probs map[string]problem) []string {
	ids := make([]string, 0, len(probs))
	for id := range probs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func runSubset(name, mode string, probs map[string]problem, s solver) subsetReport {
	ctx := context.Background()
	rep := subsetReport{Name: name, Mode: mode, Total: len(probs)}
	for _, id := range sortedIDs(probs) {
		p := probs[id]
		engine, flags, solved := s.solve(ctx, p)
		row := resultRow{ID: id, Category: p.Category, Sub: p.Sub, Engine: engine, ExpectedSkill: "auto"}
		if solved && len(flags) > 0 {
			sum := sha256.Sum256([]byte(flags[0]))
			if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
				row.Sha256Match = true
				rep.Hit++
			}
		}
		rep.Results = append(rep.Results, row)
	}
	rep.Miss = rep.Total - rep.Hit
	if rep.Total > 0 {
		rep.CoveragePct = float64(rep.Hit) * 100.0 / float64(rep.Total)
	}
	return rep
}

func main() {
	realPath := flag.String("real", "data/ctf_benchmark/real_benchmark.json", "real 真题基准 json")
	crossPath := flag.String("cross", "data/questions_real_bench/cross_bench.json", "cross 真题基准 json")
	outPath := flag.String("out", "eval_report.json", "产出报告路径")
	flag.Parse()

	realProbs := loadProblems(*realPath)
	crossProbs := loadProblems(*crossPath)
	s := &presolveSolver{pr: ctfplatform.NewPresolver(nil)}

	rep := evalReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Note: "生产 ctfplatform.Presolver 路径离线 eval（real+cross 文本口径）。cross 附件子集(5/12=41.7%)由权威 TestCrossBench_AttachmentSubset 覆盖，本件有意不重抄以免不可比数字。Layer 3 (LLM) 接入点见 cmd/runner/llm_fallback.go solve()。无端点时不接死 LLM，避免假离线路径虚报提升。",
	}
	rep.Subsets = append(rep.Subsets, runSubset("real_static", "description-only", realProbs, s))
	rep.Subsets = append(rep.Subsets, runSubset("cross_text", "description-only", crossProbs, s))

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] 序列化报告失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] 写 %s 失败: %v\n", *outPath, err)
		os.Exit(1)
	}

	fmt.Println("=== SecAutoMind 离线 eval（生产管线路径）===")
	for _, sub := range rep.Subsets {
		fmt.Printf("  %-26s %3d/%-3d = %5.1f%%  (mode=%s)\n", sub.Name, sub.Hit, sub.Total, sub.CoveragePct, sub.Mode)
	}
	fmt.Printf("报告已写出: %s\n", *outPath)
	// 反 RDD 自检断言（仅打印告警，不强行 exit，便于当基线读数用）：
	if len(realProbs) > 0 {
		realPct := float64(rep.Subsets[0].Hit) * 100.0 / float64(rep.Subsets[0].Total)
		if realPct < 30.0 || realPct > 42.0 {
			fmt.Fprintf(os.Stderr, "[SELFCHECK] real_static 覆盖率 %5.1f%% 偏离已知真值 36.4%%，请核查 Presolver 接线\n", realPct)
		}
	}
}
