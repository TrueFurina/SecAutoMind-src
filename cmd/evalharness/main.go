// Command evalharness —— SecAutoMind 生产管线离线 eval 集成件。
//
// 它用**真实生产代码路径**（internal/ctfplatform.Presolver + internal/runnerl3.LLMFallback）
// 把基准集在单次运行里统一跑完，产出一份可比的 eval_report.json。
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
// 反 RDD 自检：real 子集必须复现已知真值（real 20/55=36.4%）才证明接的是真生产代码，
// 而非另起炉灶。
//
// Layer 3 接入点（已落地，2026-10-29）：
//   --practice 模式从 CTF² 练习场加载题目（LoadPracticeChallenges），用 runnerl3.LLMFallback
//   解每题，提交候选到练习场 submit 端点查 isCorrect（**真校验**，非 sha256 假路径）。
//   --llm 可配合 --practice 强制走 LLM solver；RUNNER_LLM_* 环境变量未配时自动降级为
//   仅加载+映射验证（不烧 token，全 miss），作为 dry 模式。
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
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
	"secautomind-ai/internal/runnerl3"
	"secautomind-ai/internal/procenv"
)

// problem 与 real_benchmark.json / cross_bench.json 的题目同构（只取 eval 需要的字段）。
type problem struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
	Title       string `json:"title"`
	FlagSHA256  string `json:"flag_sha256"`
}

type resultRow struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Sub           string `json:"sub"`
	Engine        string `json:"presolve_engine"`
	SolvedBy      string `json:"solved_by"` // "presolve" | "llm"
	Sha256Match   bool   `json:"sha256_match"`
	ExpectedSkill string `json:"expected_skill"`
	Candidates    string `json:"candidates,omitempty"` // LLM 产出的候选 flag（诊断用；仅 LLM 猜测，非真值）
}

type subsetReport struct {
	Name        string      `json:"name"`
	Mode        string      `json:"mode"` // "description-only" | "llm-real-submit"
	Total       int         `json:"total"`
	Hit         int         `json:"hit"`
	Miss        int         `json:"miss"`
	CoveragePct float64     `json:"coverage_pct"`
	Results     []resultRow `json:"results"`
}

type evalReport struct {
	GeneratedAt string         `json:"generated_at"`
	Note        string         `json:"note"`
	// Solver 记录本次跑批用的是哪一层（presolve / llm:<model>）。
	// 口径铁律：成绩必须与「模型档位」同框，否则 17% 这种数字无法解释
	// （弱模型跑出来的低分不等于系统能力上限）。
	Solver  string         `json:"solver"`
	Model   string         `json:"model"`
	Subsets []subsetReport `json:"subsets"`
}

// Solver 抽象：presolveSolver（L1，0 token）与 llmSolver（L3，真 token）都满足。
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

// llmSolver 用 Layer 3 (LLM fallback) 解练习场题，并用真 submit 校验。
// 它持有练习场完整 Challenge 映射（byID），solve() 时从中取 AttachmentURLs 等喂给 LLM。
type llmSolver struct {
	fb       *runnerl3.LLMFallback
	submitFn func(ctx context.Context, challengeID, flag string) (bool, error)
	byID     map[string]*ctfplatform.Challenge
	mu       sync.Mutex
	cache    map[string]bool // 已确认解出的题，避免重复提交
}

func (s *llmSolver) solve(ctx context.Context, p problem) (string, []string, bool) {
	ch, ok := s.byID[p.ID]
	if !ok || s.fb == nil || !s.fb.Enabled {
		why := "fb-disabled"
		if !ok {
			why = "challenge-not-in-byID"
		} else if s.fb == nil {
			why = "fb-nil"
		}
		fmt.Fprintf(os.Stderr, "[llm] SKIP id=%s cat=%s reason=%s\n", p.ID, p.Category, why)
		return "llm", nil, false
	}
	flags, err := s.fb.Solve(ctx, ch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[llm] ERR id=%s cat=%s err=%v\n", p.ID, p.Category, err)
		return "llm", flags, false
	}
	fmt.Fprintf(os.Stderr, "[llm] SOLVE id=%s cat=%s nflags=%d\n", p.ID, p.Category, len(flags))
	for _, f := range flags {
		s.mu.Lock()
		done := s.cache[p.ID]
		s.mu.Unlock()
		if done {
			fmt.Fprintf(os.Stderr, "[llm] CACHED id=%s\n", p.ID)
			return "llm", flags, true
		}
		if s.submitFn != nil {
			correct, e := s.submitFn(ctx, p.ID, f)
			fmt.Fprintf(os.Stderr, "[llm] SUBMIT id=%s flag=%q ok=%v err=%v\n", p.ID, redactFlag(f), correct, e)
			if e != nil {
				// 提交失败（网络/拒绝）不是解题失败，继续试下一个候选
				continue
			}
			if correct {
				s.mu.Lock()
				s.cache[p.ID] = true
				s.mu.Unlock()
				return "llm", flags, true
			}
		}
	}
	return "llm", flags, false
}

// redactFlag 仅保留前缀用于诊断格式（flag{...}? picoCTF{...}?），不暴露完整候选。
func redactFlag(f string) string {
	if len(f) <= 16 {
		return f
	}
	return f[:16] + "..."
}

// evalLogger 构造写 stderr 的 zap logger。
//
// 曾踩坑：这里用 zap.NewNop()，导致 L3 每轮的工具调用/失败/截断全部静默，
// 只剩 nflags=0 一个数字，无法定位「为什么零候选」（2026-10-29 首次 smoke 0/5）。
// 评测必须可观测：stdout 保持纯净报告，诊断一律走 stderr。
func evalLogger() *zap.Logger {
	if strings.EqualFold(os.Getenv("EVALHARNESS_QUIET"), "true") {
		return zap.NewNop()
	}
	cfg := zap.NewDevelopmentConfig()
	cfg.OutputPaths = []string{"stderr"}
	lg, err := cfg.Build()
	if err != nil {
		return zap.NewNop()
	}
	return lg
}

func solverName(s solver) string {
	if _, ok := s.(*llmSolver); ok {
		return "llm"
	}
	return "presolve"
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
		row := resultRow{
			ID:            id,
			Category:      p.Category,
			Sub:           p.Sub,
			Engine:        engine,
			SolvedBy:      solverName(s),
			ExpectedSkill: "auto",
			Candidates:    strings.Join(flags, " | "),
		}
		if solved && len(flags) > 0 {
			if p.FlagSHA256 != "" {
				// real/cross：sha256 校验（已知真值，绝不反推明文）
				sum := sha256.Sum256([]byte(flags[0]))
				if hex.EncodeToString(sum[:]) == p.FlagSHA256 {
					row.Sha256Match = true
					rep.Hit++
				}
			} else {
				// 练习场：solved 已由真 submit 校验决定（非 sha256 假路径）
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
	// 环境失敏（2026-11-01 事故）：ps eww 能读本进程 /proc/<pid>/environ。
	_ = procenv.Harden() // 最好努力：失败不阻断评测
	realPath := flag.String("real", "data/ctf_benchmark/real_benchmark.json", "real 真题基准 json")
	crossPath := flag.String("cross", "data/questions_real_bench/cross_bench.json", "cross 真题基准 json")
	outPath := flag.String("out", "eval_report.json", "产出报告路径")
	practice := flag.Bool("practice", false, "从 CTF² 练习场加载题目作为评测集（L3 真机校验）")
	practiceGround := flag.String("practice-ground", os.Getenv("CTF2_PRACTICE_GROUND_ID"), "练习场 ID（默认读 CTF2_PRACTICE_GROUND_ID）")
	limit := flag.Int("limit", 0, "只跑前 N 题（按 ID 排序；0=全跑）。用于 smoke 验证，避免一次性烧全量 token")
	flag.Parse()

	rep := evalReport{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}

	if *practice {
		ctx := context.Background()
		chs, err := ctfplatform.LoadPracticeChallenges(ctx, *practiceGround)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] 加载练习场失败: %v\n", err)
			os.Exit(1)
		}
		probs := make(map[string]problem, len(chs))
		byID := make(map[string]*ctfplatform.Challenge, len(chs))
		var skippedContainer int
		for i := range chs {
			ch := &chs[i]
			byID[ch.ID] = ch // 保留完整映射供 Solve 取附件/提交
			if ch.HasInstance {
				// Phase 1：跳过敏容器题（web/pwn 需 live target）。没有活靶无法解，跑必 miss，纯烧 token。
				// runnerl3 当前不自动跳过，故 harness 层先剔除；phase 2 接 acquire_target 后再纳入。
				skippedContainer++
				continue
			}
			probs[ch.ID] = problem{ID: ch.ID, Category: ch.Category, Description: ch.Description, Title: ch.Title}
		}
		fmt.Fprintf(os.Stderr, "[practice] 加载 %d 题，Phase1 跳过敏容器题(HasInstance) %d，参评 %d\n", len(chs), skippedContainer, len(probs))
		// --limit：smoke 验证用，只跑前 N 题（按 ID 排序），避免一次性烧全量 token。
		if *limit > 0 && len(probs) > *limit {
			limited := make(map[string]problem, *limit)
			for _, id := range sortedIDs(probs)[:*limit] {
				limited[id] = probs[id]
			}
			probs = limited
		}
		// L3 solver：pyBridge 传 nil → execute_python 自动降级（量化 L2 缺口），
		// 仅 read_attachment / python_session 可用。RUNNER_LLM_* 未配时 Enabled=false，
		// Solve 直接返回空 → 全 miss（dry 模式，不烧 token）。
		fb := runnerl3.NewLLMFallback(ctx, evalLogger(), nil)
		fmt.Fprintf(os.Stderr, "[llm] fallback enabled=%v (RUNNER_LLM_FALLBACK=%q)\n", fb.Enabled, os.Getenv("RUNNER_LLM_FALLBACK"))
		if !fb.Enabled {
			fmt.Fprintln(os.Stderr, "[WARN] RUNNER_LLM_FALLBACK 未启用 → 练习场 LLM solver 不烧 token（仅做加载+映射验证，全部 miss）")
		}
		s := &llmSolver{
			fb:    fb,
			byID:  byID,
			cache: map[string]bool{},
			submitFn: func(ctx context.Context, cid, flag string) (bool, error) {
				return ctfplatform.SubmitPracticeFlag(ctx, *practiceGround, cid, flag)
			},
		}
		rep.Note = "CTF² 练习场（PRAC-2026-4739）L3 真机评测：LoadPracticeChallenges 加载 → runnerl3.LLMFallback.Solve → 提交候选到练习场 submit 端点查 isCorrect（真校验，非 sha256 假路径）。Phase 1 由 harness 跳过敏容器题（HasInstance=true，需 live target），仅参评非容器题；phase 2 接 acquire_target 后再纳入容器题。"
		rep.Subsets = append(rep.Subsets, runSubset("practice_llm", "llm-real-submit", probs, s))
	} else {
		realProbs := loadProblems(*realPath)
		crossProbs := loadProblems(*crossPath)
		s := &presolveSolver{pr: ctfplatform.NewPresolver(nil)}
		rep.Note = "生产 ctfplatform.Presolver 路径离线 eval（real+cross 文本口径）。cross 附件子集(5/12=41.7%)由权威 TestCrossBench_AttachmentSubset 覆盖，本件有意不重抄以免不可比数字。Layer 3 (LLM) 接入点见 internal/runnerl3（已从 cmd/runner 抽出）。无端点时不接死 LLM，避免假离线路径虚报提升。"
		rep.Subsets = append(rep.Subsets, runSubset("real_static", "description-only", realProbs, s))
		rep.Subsets = append(rep.Subsets, runSubset("cross_text", "description-only", crossProbs, s))
	}

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
	// 仅 real_static 套用已知真值窗口；练习场不暴露 sha256，跳过。
	if !*practice {
		if len(rep.Subsets) > 0 && rep.Subsets[0].Name == "real_static" && rep.Subsets[0].Total > 0 {
			realPct := float64(rep.Subsets[0].Hit) * 100.0 / float64(rep.Subsets[0].Total)
			if realPct < 30.0 || realPct > 42.0 {
				fmt.Fprintf(os.Stderr, "[SELFCHECK] real_static 覆盖率 %5.1f%% 偏离已知真值 36.4%%，请核查 Presolver 接线\n", realPct)
			}
		}
	}
}
