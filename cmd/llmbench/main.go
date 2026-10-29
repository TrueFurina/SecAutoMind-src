// Command llmbench —— 离线题集 × Layer 3 真 LLM 的跑批入口（2026-10-29）。
//
// 为什么单独建一个命令（不并入 cmd/evalharness）：
//   evalharness 的非 practice 分支只接 L1 presolve（确定性层，0 token），其 LLM
//   路径被设计为「CTF² 练习场真 submit 校验」，硬依赖 CTF2_AGENT_TOKEN + 平台权限；
//   而当前平台全端点 40403、服务器无任何 CTF2 凭证 ⇒ 那条路跑不出数。
//   本件补的是**离线题集 + flag_sha256 判分**这条路，两者题源不同、判分口径不同，
//   混进同一个报告只会产出不可比数字（口径铁律）。
//
// 为什么必须用 runnerl3 而不是 ctf-agent 引擎：
//   ctf-agent 解题需要 Docker 沙箱，而本仓服务器 172.16.222.99 实测**无 docker**
//   （which docker 为空，podman/nerdctl 也没有）。runnerl3 走原生 shell
//   （internal/security/shell_execute_stream.go，Linux 固定 /bin/sh），零容器依赖
//   ⇒ 这是目前**唯一**能在合规服务器跑真 LLM 解题的路径。
//
// 反作弊/反自欺约束（每条都是踩过坑后的硬约束）：
//   1. 判分**只认 flag_sha256**，绝不读明文 flag（读了等于自己批自己卷子）。
//   2. LLM 未装配成功（缺 key / 通道不可用）时 **拒绝跑批**（exit 2），
//      而不是产出一份「跑了 0 命中」的报告 —— 后者看起来像「跑了但没解出」，
//      实际是「根本没跑」，这是最贵的假动作。
//   3. 成绩必须带 **模型档位**（model + tier）一起归档，否则无法解释
//      「17% 到底是系统上限还是弱模型拉低」。
//
// 运行位置：**只允许在服务器 172.16.222.99**。本机跑题一律不合规、结果作废。
// 本机只做交叉编译（GOOS=linux go build）与 scp。
//
// 用法（服务器内）：
//   export RUNNER_LLM_FALLBACK=true
//   export RUNNER_LLM_BASE_URL=https://tokenhub.tencentmaas.com/v1
//   export RUNNER_LLM_API_KEY=<key>          # 走 stdin/环境注入，不落盘
//   export RUNNER_LLM_MODEL=step-5-preview
//   ./llmbench_linux --real data/ctf_benchmark/real_benchmark.json --limit 5   # 冒烟
//   ./llmbench_linux --real data/ctf_benchmark/real_benchmark.json --out r.json
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
	"secautomind-ai/internal/runnerl3"
)

type artifact struct {
	Path string `json:"path"`
}

type problem struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Sub         string `json:"sub"`
	Title       string `json:"title"`
	Description string `json:"description"`
	FlagSHA256  string `json:"flag_sha256"`
	// Cid / Artifacts 只有「有附件的题集」才有（如 ycb2026_static.json）。
	// real_benchmark.json 这类纯文本题集没有，此时退化为 description-only。
	Cid       any        `json:"cid"`
	Artifacts []artifact `json:"artifacts"`
}

type row struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Sub         string `json:"sub"`
	Engine      string `json:"engine"`
	Sha256Match bool   `json:"sha256_match"`
	// Candidates 只记候选个数，绝不记候选内容（防答案二次落盘）。
	Candidates int    `json:"candidates"`
	Seconds    float64 `json:"seconds"`
	// HasAttachment 记本题是否真有工件在场。判读分数时必须看它：
	// 纯文本题（false）解不出往往是**按构造不可解**，不是模型能力问题。
	HasAttachment bool   `json:"has_attachment"`
	Err           string `json:"error,omitempty"`
}

type report struct {
	GeneratedAt string  `json:"generated_at"`
	Solver      string  `json:"solver"`       // "llm"
	Model       string  `json:"model"`        // 如 step-5-preview
	BaseURL     string  `json:"base_url"`     // 通道（可判是否走了 failover 到别的通道）
	Note        string  `json:"note"`
	Total       int     `json:"total"`
	Hit         int     `json:"hit"`
	Miss        int     `json:"miss"`
	CoveragePct float64 `json:"coverage_pct"`
	Results     []row   `json:"results"`
}

// loadProblems 兼容两种题集形态：`{"problems": {id: {...}}}`（real_benchmark）与
// `{"problems": [ ... ]}`（ycb2026_static）。不做第三种子形态的猜测——解析不了就报错。
func loadProblems(path string) (map[string]problem, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var byID struct {
		Problems map[string]problem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &byID); err == nil && len(byID.Problems) > 0 {
		return byID.Problems, nil
	}
	var byList struct {
		Problems []problem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &byList); err != nil {
		return nil, err
	}
	out := make(map[string]problem, len(byList.Problems))
	for _, p := range byList.Problems {
		out[p.ID] = p
	}
	return out, nil
}

// prepareWorkdir 把该题工件复制进干净工作目录并 chdir 进去。
//
// 为什么必须 chdir 而不是塞给 read_attachment：
//   read_attachment 只接受 **URL**（内部 http.Get 下载），而 YCB 工件是服务器上的
//   本地文件，没有 URL 可给。L3 真正能碰本地文件的是 **python_session**（持久
//   Python REPL，cwd 落在进程当前目录）⇒ 把进程切进工作目录，模型就能
//   `open("VVMM.exe","rb")`。这是零改动的注入方式（不碰 runnerl3）。
//
// 返回 (是否有工件, 错误)。
func prepareWorkdir(base string, p problem, attRoot string) (bool, error) {
	if attRoot == "" || len(p.Artifacts) == 0 {
		return false, nil
	}
	srcDir := filepath.Join(attRoot, fmt.Sprint(p.Cid))
	dir := filepath.Join(base, sanitizeID(p.ID))
	if err := os.RemoveAll(dir); err != nil {
		return false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	n := 0
	for _, a := range p.Artifacts {
		src := filepath.Join(srcDir, a.Path)
		dst := filepath.Join(dir, filepath.Base(a.Path))
		b, rerr := os.ReadFile(src)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "[WARN] %s: 工件缺失 %s → 该题退化为无附件\n", p.ID, src)
			continue
		}
		if werr := os.WriteFile(dst, b, 0o644); werr != nil {
			return false, werr
		}
		n++
	}
	if n == 0 {
		return false, nil
	}
	// 题面也写进去，模型不需要，但便于事后人工复核工作目录内容。
	_ = os.WriteFile(filepath.Join(dir, "CHALLENGE.md"),
		[]byte("# "+p.ID+"\n\n"+p.Description+"\n"), 0o644)
	return true, os.Chdir(dir)
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// tier 只是**标注**，不参与任何判分。用来回答「这个分是哪个档位的模型跑出来的」。
// 判断依据是模型名子串，匹配不上就老实写 unknown —— 绝不猜。
func tier(model string) string {
	m := strings.ToLower(model)
	switch {
	case m == "":
		return "unknown"
	case strings.Contains(m, "max"), strings.Contains(m, "k2-thinking"), strings.Contains(m, "r1"),
		strings.Contains(m, "thinking"), strings.Contains(m, "o3"), strings.Contains(m, "step-5"):
		return "flagship"
	case strings.Contains(m, "pro"), strings.Contains(m, "plus"), strings.Contains(m, "k2"),
		strings.Contains(m, "v3"), strings.Contains(m, "glm-5"):
		return "mainline"
	case strings.Contains(m, "flash"), strings.Contains(m, "lite"), strings.Contains(m, "mini"),
		strings.Contains(m, "preview"), strings.Contains(m, "turbo"):
		return "light"
	default:
		return "unknown"
	}
}

func main() {
	realPath := flag.String("real", "data/ctf_benchmark/real_benchmark.json", "离线题集 json")
	outPath := flag.String("out", "llmbench_report.json", "产出报告路径")
	attRoot := flag.String("att-root", "", "工件根目录（如 /tmp/ycb_static_survey，其下按 cid 分目录）；为空=纯文本题集")
	workBase := flag.String("work-base", "/tmp/llmbench_work", "每题工作目录的父目录")
	limit := flag.Int("limit", 0, "只跑前 N 题（按 id 排序），0=全跑")
	idsRaw := flag.String("ids", "", "只跑这些 id（逗号分隔），优先于 --limit")
	flag.Parse()

	if os.Getenv("RUNNER_LLM_FALLBACK") != "true" {
		fmt.Fprintln(os.Stderr, "[ERR] 必须先 export RUNNER_LLM_FALLBACK=true")
		os.Exit(2)
	}
	probs, err := loadProblems(*realPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] 读题集失败: %v\n", err)
		os.Exit(2)
	}

	ids := make([]string, 0, len(probs))
	for id := range probs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if strings.TrimSpace(*idsRaw) != "" {
		want := map[string]bool{}
		for _, x := range strings.Split(*idsRaw, ",") {
			if t := strings.TrimSpace(x); t != "" {
				want[t] = true
			}
		}
		kept := ids[:0]
		for _, id := range ids {
			if want[id] {
				kept = append(kept, id)
			}
		}
		ids = kept
	} else if *limit > 0 && *limit < len(ids) {
		ids = ids[:*limit]
	}

	logger, lerr := zap.NewDevelopment()
	if lerr != nil {
		logger = zap.NewNop()
	}
	// pyBridge 传 nil → execute_python 自动降级，仅 read_attachment / python_session 可用。
	fb := runnerl3.NewLLMFallback(context.Background(), logger, nil)
	if !fb.Enabled {
		fmt.Fprintln(os.Stderr, "[ERR] LLM fallback 装配失败（RUNNER_LLM_API_KEY 缺失或通道不可用）→ 拒绝跑批，"+
			"避免产出一份看起来像「跑了 0 命中」、实际根本没跑的报告")
		os.Exit(2)
	}

	model := os.Getenv("RUNNER_LLM_MODEL")
	rep := report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Solver:      "llm",
		Model:       model,
		BaseURL:     os.Getenv("RUNNER_LLM_BASE_URL"),
		Note:        "离线题集 × runnerl3.LLMFallback（Layer 3 真 token），判分只认 flag_sha256。未解出照常计入分母，绝不剔除。",
		Total:       len(ids),
	}

	ctx := context.Background()
	if err := os.MkdirAll(*workBase, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] 建工作目录失败: %v\n", err)
		os.Exit(2)
	}
	for _, id := range ids {
		p := probs[id]
		// 有工件就切进该题工作目录（python_session 的 cwd 随之改变）；
		// 无工件则保持进程 cwd，退化为 description-only。
		hasAtt, aerr := prepareWorkdir(*workBase, p, *attRoot)
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %s 准备工作目录失败: %v\n", id, aerr)
			os.Exit(2)
		}
		t0 := time.Now()
		flags, err := fb.Solve(ctx, &ctfplatform.Challenge{
			ID:           p.ID,
			Title:        p.Title,
			Category:     p.Category,
			Description:  p.Description,
			HasAttachment: hasAtt,
		})
		secs := time.Since(t0).Seconds()
		r := row{ID: id, Category: p.Category, Sub: p.Sub, Engine: "llm:" + model,
			Candidates: len(flags), Seconds: secs, HasAttachment: hasAtt}
		if err != nil {
			r.Err = err.Error()
		}
		if len(flags) > 0 && p.FlagSHA256 != "" {
			for _, f := range flags {
				sum := sha256.Sum256([]byte(f))
				if hex.EncodeToString(sum[:]) == strings.ToLower(p.FlagSHA256) {
					r.Sha256Match = true
					break
				}
			}
		}
		if r.Sha256Match {
			rep.Hit++
		} else {
			rep.Miss++
		}
		rep.Results = append(rep.Results, r)
		fmt.Printf("[%s] %-28s cand=%d hit=%v %.1fs\n", id, p.Category, r.Candidates, r.Sha256Match, secs)
	}
	if rep.Total > 0 {
		rep.CoveragePct = float64(rep.Hit) * 100.0 / float64(rep.Total)
	}

	b, merr := json.MarshalIndent(rep, "", "  ")
	if merr != nil {
		fmt.Fprintf(os.Stderr, "[ERR] 序列化失败: %v\n", merr)
		os.Exit(1)
	}
	if werr := os.WriteFile(*outPath, b, 0o644); werr != nil {
		fmt.Fprintf(os.Stderr, "[ERR] 写报告失败: %v\n", werr)
		os.Exit(1)
	}
	fmt.Printf("=== llmbench: %d/%d = %.1f%%  (model=%s tier=%s) ===\n",
		rep.Hit, rep.Total, rep.CoveragePct, rep.Model, tier(rep.Model))
	fmt.Printf("报告: %s\n", *outPath)
}
