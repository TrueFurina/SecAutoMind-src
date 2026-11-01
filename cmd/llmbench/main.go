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
	"secautomind-ai/internal/procenv"
	"secautomind-ai/internal/pyskill"
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
	// 外部真题池（external_bench.json）用 attachment_files 字段名且按 id 子目录存放，
	// 与 ycb2026 的 artifacts/cid 形态不同；这里单独接，再并入 Artifacts 统一处理。
	AttachmentFiles []struct {
		Name string `json:"name"`
	} `json:"attachment_files"`
}

// mergeAttachmentFiles 把外部池的 attachment_files 并入统一 Artifacts 形态。
func (p problem) withAttachments() problem {
	if len(p.AttachmentFiles) > 0 && len(p.Artifacts) == 0 {
		for _, af := range p.AttachmentFiles {
			p.Artifacts = append(p.Artifacts, artifact{Path: af.Name})
		}
	}
	return p
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
	HasAttachment bool `json:"has_attachment"`
	// Layer 记这题是谁解的：l2=确定性 skill 路由（零 token）/ l3=LLM。
	// 不记就无法回答"这分是 skill 挣的还是模型挣的"。
	Layer string `json:"layer,omitempty"`
	Err   string `json:"error,omitempty"`
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
		for id, p := range byID.Problems {
			byID.Problems[id] = p.withAttachments()
		}
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
		out[p.ID] = p.withAttachments()
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
// prepareWorkdir 为每题准备**全新空目录**并 chdir 进去；返回是否有附件。
//
// ⚠️ 2026-11-01 修复（严重）：原实现对"无附件 / 无 attRoot"的题**直接 return，
// 不做 chdir**。后果有两层，第二层是伪造分数线：
//  1. 纯文本题在**上一题的工作目录**（或启动时的 cwd）里跑，跨题残留互相可见；
//  2. 启动 cwd 通常是仓库根 ⇒ 路径围栏按 cwd 建白名单 ⇒ **整个仓库放行**。
//     假端点实测：模型 `open('/home/user/SecAutoMind/data/answers/ycb2026_truth.json')`
//     读到明文真值 —— 读了再提交，sha256 必然匹配，账本上就是一条"LLM 解出"。
//
// 所以：无论有没有附件，都先 RemoveAll + MkdirAll 一个**新目录**再 chdir。
// 空目录是安全的默认值；有附件往里放。
func prepareWorkdir(base string, p problem, attRoot string) (bool, error) {
	if err := os.MkdirAll(base, 0o755); err != nil {
		return false, err
	}
	// 删之前先离开目标目录：cwd 落在被删目录里时，Windows 直接 unlinkat 失败，
	// Linux 虽允许但会留下"cwd 已删除"的悬空状态。先退回 base 最稳。
	_ = os.Chdir(base)

	dir := filepath.Join(base, sanitizeID(p.ID))
	if err := os.RemoveAll(dir); err != nil {
		return false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}

	// 外部真题池用 attachment_files（不是 artifacts）。**这里必须合并**：
	// 2026-11-01 实锤 —— 字段加了但没并入 Artifacts，于是 len(p.Artifacts)==0
	// 直接跳过整段，40/40 题的附件一个都没落盘，模型 working dir 里只有
	// CHALLENGE.md，跑批退化成"看题面硬猜"（连 [WARN] 工件缺失 都不会打，
	// 因为条件压根没进去）。声明了附件却没文件可用，属于静默能力阉割。
	arts := p.Artifacts
	if len(arts) == 0 && len(p.AttachmentFiles) > 0 {
		for _, f := range p.AttachmentFiles {
			if strings.TrimSpace(f.Name) != "" {
				arts = append(arts, artifact{Path: f.Name})
			}
		}
	}

	hasAtt := false
	if attRoot != "" && len(arts) > 0 {
		// 外部真题池按 id 子目录存放（无 cid 字段）；ycb2026 等按 cid 子目录。
		cidKey := p.Cid
		if cidKey == nil || fmt.Sprint(cidKey) == "" || fmt.Sprint(cidKey) == "<nil>" {
			cidKey = p.ID
		}
		srcDir := filepath.Join(attRoot, fmt.Sprint(cidKey))
		n := 0
		for _, a := range arts {
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
		hasAtt = n > 0
		if n == 0 {
			// 声明有附件却一个都没落地 = 该题被静默阉割，必须喊出来。
			fmt.Fprintf(os.Stderr, "[WARN] %s: 声明了 %d 个附件，一个都没复制成功（源目录 %s）→ 该题退化为无附件\n",
				p.ID, len(arts), srcDir)
		}
	}

	// 题面也写进去：模型不需要（已在 prompt 里），但便于事后人工复核工作目录内容。
	_ = os.WriteFile(filepath.Join(dir, "CHALLENGE.md"),
		[]byte("# "+p.ID+"\n\n"+p.Description+"\n"), 0o644)
	return hasAtt, os.Chdir(dir)
}

// anyFlagMatches 只认 sha256 精确相等。want 为空一律 false —— 题集没给真值时
// 无法判分，绝不能"看到 flag 形态就算解出"（那正是 10-31 误报 291 条的同型错误）。
func anyFlagMatches(flags []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	for _, f := range flags {
		sum := sha256.Sum256([]byte(f))
		if hex.EncodeToString(sum[:]) == want {
			return true
		}
	}
	return false
}

// workdirFiles 列出**当前**工作目录里的附件绝对路径（跳过题面 CHALLENGE.md）。
// 必须绝对路径：skill 子进程的工作目录不是这里，相对路径会解析到别处。
// 调用时机固定在 prepareWorkdir 之后（它会把 cwd 切进该题目录）。
func workdirFiles() []string {
	wd, err := os.Getwd()
	if err != nil {
		return nil
	}
	ents, err := os.ReadDir(wd)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() || e.Name() == "CHALLENGE.md" {
			continue
		}
		out = append(out, filepath.Join(wd, e.Name()))
	}
	sort.Strings(out)
	return out
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
	withSkills := flag.Bool("with-skills", false,
		"接入 internal/pyskill 真实桥接（execute_python 可用 = 生产 runner 形态）；"+
			"默认关 = 纯 LLM 下界口径。两种口径不可混算，报告里会写明")
	withL2 := flag.Bool("with-l2", false,
		"Layer 3 之前先跑 Layer 2 确定性 skill 路由（按 category 顺序试 skill，**零 token**），"+
			"命中记 layer=l2。理由（2026-11-01 真机实测）：模型拿到正确清单+参数契约后仍然"+
			"不用 skill（23s 就放弃、只调 python_session），不能只靠模型自觉")
	l2Budget := flag.Duration("l2-budget", 300*time.Second,
		"--with-l2 的**整类**时间预算；0=不限。"+
			"crypto 有 28 个 skill、单个 30s，不限会拖到 14 分钟/题，赛时不可接受")
	flag.Parse()

	// 所有路径型参数**先转绝对路径**再进跑批：prepareWorkdir 会 chdir 进每题
	// 工作目录，此后相对路径的基址就变了。2026-11-01 实锤 —— `--att-root
	// data/questions_external_bench/_attachments` 明明存在，日志却打
	// `工件缺失 .../chall.py`，因为解析时进程 cwd 已是 /tmp/lb_att/<id>。
	// 同一坑对 --out / --work-base 同样成立（相对路径会把结果写到别处）。
	for _, p := range []*string{attRoot, outPath, workBase} {
		if p == nil || strings.TrimSpace(*p) == "" {
			continue
		}
		if abs, aerr := filepath.Abs(*p); aerr == nil {
			*p = abs
		}
	}

	// 这道闸是防"误跑 L3 烧 token"，不是防 L2（L2 零 token、不需要任何凭证）。
	// 因此 --with-l2 时放行；是否真跑 L3 由后面 fb.Enabled 决定（不可用 → l2Only）。
	if os.Getenv("RUNNER_LLM_FALLBACK") != "true" && !*withL2 {
		fmt.Fprintln(os.Stderr, "[ERR] 必须先 export RUNNER_LLM_FALLBACK=true（只跑零 token 的 Layer 2 请加 --with-l2）")
		os.Exit(2)
	}
	// 环境失敏（2026-11-01 事故）：同 uid 的 `ps eww` 能读本进程的
	// /proc/<pid>/environ（初始快照，unsetenv 清不掉）⇒ 模型能拿到 API key。
	// 子进程环境白名单只挡"继承"，这条要内核开关。见 internal/procenv。
	if err := procenv.Harden(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] 进程环境加固失败（ps 仍可能读到 /proc/<pid>/environ）：%v\n", err)
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
	// pyBridge 默认传 nil → execute_python 自动降级，仅 read_attachment / python_session 可用。
	// --with-skills 打开后才接入真实桥接，此时才等于生产 runner 形态（86 skill 可被 LLM 调用）。
	// 口径红线：两种形态必须分开记账，否则"带 skill 的提升"会被误读成模型变强。
	var (
		bridge runnerl3.SkillRunner
		engine = "llm"
		pr     *pyskill.Runner // --with-skills 与 --with-l2 共用同一个桥接实例
	)
	if *withSkills || *withL2 {
		pr = pyskill.New(context.Background(), logger)
		if pr.SkillsDir() == "" {
			fmt.Fprintln(os.Stderr, "[WARN] 已开启 --with-skills/--with-l2，但未找到 skills 目录（可用 CTF_SKILLS_DIR 指定）→ "+
				"execute_python 虽然可调，但实际没有任何 skill 可跑；本报告**不能**当作「带 skill 形态」使用")
		} else {
			fmt.Fprintf(os.Stderr, "[INFO] skill 桥接已接入：dir=%s catalog=%d contracts=%d\n",
				pr.SkillsDir(), pr.CatalogSize(), len(pr.SkillContracts()))
		}
	}
	if *withSkills {
		bridge = pr
		engine = "llm+skills"
	}
	if *withL2 {
		engine += "+l2"
	}
	fb := runnerl3.NewLLMFallback(context.Background(), logger, bridge)
	// l2Only：LLM 通道不可用但开了 --with-l2 → 只跑确定性层。
	// 这条路径零 token，是回答"不花一分钱能解几道"的唯一入口；硬要求 key 会把
	// 它锁死。未命中的题照常记 miss，绝不因为"没跑 L3"而剔除分母。
	l2Only := false
	if !fb.Enabled {
		if *withL2 {
			fmt.Fprintln(os.Stderr, "[WARN] LLM 通道不可用，--with-l2 已开 → 只跑 Layer 2（零 token）；"+
				"未命中一律记 miss，分母不剔除")
			l2Only = true
		} else {
			fmt.Fprintln(os.Stderr, "[ERR] LLM fallback 装配失败（RUNNER_LLM_API_KEY 缺失或通道不可用）→ 拒绝跑批，"+
				"避免产出一份看起来像「跑了 0 命中」、实际根本没跑的报告")
			os.Exit(2)
		}
	}

	model := os.Getenv("RUNNER_LLM_MODEL")
	rep := report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Solver:      "llm",
		Model:       model,
		BaseURL:     os.Getenv("RUNNER_LLM_BASE_URL"),
		Note:        "离线题集 × runnerl3.LLMFallback（Layer 3 真 token），判分只认 flag_sha256。未解出照常计入分母，绝不剔除。engine=" + engine,
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
		ch := &ctfplatform.Challenge{
			ID:            p.ID,
			Title:         p.Title,
			Category:      p.Category,
			Description:   p.Description,
			HasAttachment: hasAtt,
		}

		// ── Layer 2：确定性 skill 路由（零 token）────────────────────────
		// 放在 L3 之前，命中的题根本不烧 token；未命中才进 L3。
		// 2026-11-01 实测：模型拿到正确清单 + 参数契约后仍然不用 skill（23s 放弃、
		// 只调 python_session）——所以"模型自己会不会用"不能作为 skill 的价值判据。
		var l2secs float64
		if pr != nil && *withL2 {
			lt := time.Now()
			l2flags, hit := pr.TryCategoryLocal(ctx, p.Category, ch, workdirFiles(), *l2Budget)
			l2secs = time.Since(lt).Seconds()
			if hit && anyFlagMatches(l2flags, p.FlagSHA256) {
				rep.Hit++
				rep.Results = append(rep.Results, row{
					ID: id, Category: p.Category, Sub: p.Sub, Engine: engine + ":" + model,
					Candidates: len(l2flags), Seconds: l2secs, HasAttachment: hasAtt,
					Sha256Match: true, Layer: "l2",
				})
				fmt.Printf("[%s] %-28s L2-HIT cand=%d %.1fs（零 token）\n", id, p.Category, len(l2flags), l2secs)
				continue
			}
			fmt.Printf("[%s] %-28s L2 未命中 cand=%d %.1fs → 进 L3\n", id, p.Category, len(l2flags), l2secs)
		}

		if l2Only {
			rep.Miss++
			rep.Results = append(rep.Results, row{
				ID: id, Category: p.Category, Sub: p.Sub, Engine: engine + ":" + model,
				Seconds: l2secs, HasAttachment: hasAtt, Layer: "l2-miss",
			})
			fmt.Printf("[%s] %-28s L2-MISS %.1fs（无 L3）\n", id, p.Category, l2secs)
			continue
		}

		flags, err := fb.Solve(ctx, ch)
		secs := time.Since(t0).Seconds()
		r := row{ID: id, Category: p.Category, Sub: p.Sub, Engine: engine + ":" + model,
			Candidates: len(flags), Seconds: secs, HasAttachment: hasAtt, Layer: "l3"}
		if err != nil {
			r.Err = err.Error()
		}
		r.Sha256Match = anyFlagMatches(flags, p.FlagSHA256)
		if r.Sha256Match {
			rep.Hit++
		} else {
			rep.Miss++
		}
		rep.Results = append(rep.Results, r)
		fmt.Printf("[%s] %-28s cand=%d hit=%v %.1fs (L2 %.1fs)\n", id, p.Category, r.Candidates, r.Sha256Match, secs, l2secs)
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
