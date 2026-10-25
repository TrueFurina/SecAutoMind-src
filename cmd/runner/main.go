// runner —— SecAutoMind 独立 CTF 参赛入口。
//
// 作用：脱离 cmd/server Web 服务和 Eino Agent 运行时，直接用
//   internal/ctfplatform 里已有的 Poller + Presolver + Platform
//   跑"拉题 → 确定性求解 → 自动提交 → 释放靶机"全链路。
//
// 为什么存在：
//   cmd/server 里虽然已经有 Poller 接线（app.go CTF_POLL_ENABLED），
//   但它绑定在 Web 服务启动流程里，没法"一条命令起一个进程就跑到底"。
//   这个 main 就是把那段接线从 app.go 里抽出来做成独立 CLI。
//
// 覆盖范围：
//   ✅ 所有 Presolver 能确定性解的题型（crypto/web/forensics/encoding/misc）
//   ❌ reverse / pwn（需要 LLM 动态分析二进制，presolve-only 覆盖不到）
//
// 用法：
//   # 跑到底，自动提交：
//   CTF2_AGENT_TOKEN=xxx CTF2_COMPETITION_ID=xxx go run ./cmd/runner
//
//   # 只轮询不提交（赛前 dry-run）：
//   CTF_AUTOSOLVE_SUBMIT=false go run ./cmd/runner
//
//   # 调参（全部复用 app.go 的同名 env 约定，避免再造一套）：
//   CTF_POLL_INTERVAL=15 CTF_SOLVE_TIMEOUT=120 CTF_MAX_CONCURRENCY=4 \
//   CTF_AUTO_BUILD_ENV=true CTF_AUTO_FETCH_DETAIL=true CTF_AUTO_RELEASE_ENV=true \
//   go run ./cmd/runner

package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

var (
	flagForceClaim = flag.Bool("force-claim", false, "检测到已有参赛进程（runner/ctf-agent）时 kill 再启动，避免 token 限流")
	flagDryRun     = flag.Bool("dry-run", false, "轮询解题但不提交 flag（CTF_AUTOSOLVE_SUBMIT=false 覆盖）")
)

func envDurationMs(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	if secs, e := strconv.Atoi(v); e == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	if n, e := strconv.Atoi(v); e == nil && n >= 0 {
		return n
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	return v == "true" || v == "1" || v == "yes"
}

func main() {
	flag.Parse()

	// ── dry-run 覆盖 env ────────────────────────────────────
	if *flagDryRun {
		os.Setenv("CTF_AUTOSOLVE_SUBMIT", "false")
	}

	// ── 进程冲突检测 ─────────────────────────────────────────
	// 同一个 CTF2_AGENT_TOKEN 被两个进程用会触发 429 限流或封禁
	if conflicts := detectConflictingProcs(); len(conflicts) > 0 {
		logger2, _ := zap.NewProduction()
		defer logger2.Sync()
		logger2.Warn("检测到已有参赛进程",
			zap.Strings("conflicts", conflicts),
			zap.Bool("force_claim", *flagForceClaim))
		if *flagForceClaim {
			for _, pid := range conflicts {
				logger2.Info("kill 进程", zap.String("pid", pid))
				_ = killPID(pid)
			}
			time.Sleep(1 * time.Second) // 等进程退出释放资源
		} else {
			logger2.Error("已有进程在跑，拒绝启动（加 --force-claim 强抢）")
			os.Exit(1)
		}
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	logger.Info("SecAutoMind Runner 启动",
		zap.String("ctf2_token", mask(os.Getenv("CTF2_AGENT_TOKEN"))),
		zap.String("competition_id", os.Getenv("CTF2_COMPETITION_ID")),
		zap.Bool("dry_run", *flagDryRun),
		zap.Bool("force_claim", *flagForceClaim))

	// ── 1. CTF² 平台客户端 ────────────────────────────────
	platform := ctfplatform.NewCTF2Platform("", "", logger)

	// ── 2. Presolver（确定性预解层，零 token 成本）────────
	presolver := ctfplatform.NewPresolver(logger)

	// ── 2.5 Python skill bridge（西湖论剑真跑 skill）─────
	pyBridge := newPySkillRunner(context.Background(), logger)

	// ── 2.6 LLM fallback Layer 3（Eino ChatModel + 工具绑定）──
	// 依赖门控：RUNNER_LLM_FALLBACK=true 且有 API key 才启用
	// pyBridge 传入 → execute_python 工具可用；nil → 自动降级
	llmFB := newLLMFallback(context.Background(), logger, pyBridge)

	// ── 3. Solver 闭包（三层链 + 监督接入）──────────────
	//   Layer 1: Presolve 确定性求解（189 Go solver，0 token）
	//   Layer 2: Python skill bridge（angr/pwntools 真跑，有依赖门控）
	//   Layer 3: Eino ChatModel + 工具绑定（可选）
	// 每步喂 SupervisionStep，三层全空时 ReflectSupervision 判定 ABANDON/SWITCH/CONTINUE
	solver := func(ctx context.Context, ch *ctfplatform.Challenge) ([]string, error) {
		var supSteps []ctfplatform.SupervisionStep

		// Layer 1: presolve
		res := presolver.Presolve(ctx, ch, nil)
		if res.Solved {
			candidates := ctfplatform.FilterFlagCandidates(res.Flags)
			if len(candidates) > 0 {
				logger.Info("Layer 1 Presolve 命中",
					zap.String("challenge", ch.Title),
					zap.String("category", ch.Category),
					zap.Strings("flags", candidates))
				return candidates, nil
			}
		}
		supSteps = append(supSteps, ctfplatform.SupervisionStep{Observation: "presolve 未命中"})

		// Layer 2: Python skill bridge（依赖有就跑，没有就跳过）
		layer2Hit := false
		if ch.Category == "reverse" || ch.Category == "pwn" || ch.Category == "crypto" || ch.Category == "misc" {
			if flags, ok := pyBridge.tryCategory(ctx, ch.Category, ch); ok {
				logger.Info("Layer 2 Python skill 命中",
					zap.String("challenge", ch.Title),
					zap.String("category", ch.Category),
					zap.Strings("flags", flags))
				return flags, nil
			}
			layer2Hit = true
		}
		if layer2Hit {
			supSteps = append(supSteps, ctfplatform.SupervisionStep{Observation: "python skill 未命中/无依赖"})
		} else {
			supSteps = append(supSteps, ctfplatform.SupervisionStep{Observation: "python skill 跳过（非目标类别）"})
		}

		// Layer 3: LLM fallback（带工具绑定）
		layer3Hit := false
		if llmFB.enabled {
			if flags, err := llmFB.solve(ctx, ch); err != nil {
				logger.Debug("Layer 3 LLM 调用失败（非致命）",
					zap.String("challenge", ch.Title),
					zap.Error(err))
				supSteps = append(supSteps, ctfplatform.SupervisionStep{
					Observation: "",
					ErrCategory: string(ctfplatform.ClassifyError(err.Error())),
				})
			} else if len(flags) > 0 {
				return flags, nil
			}
			layer3Hit = true
		}
		if layer3Hit {
			supSteps = append(supSteps, ctfplatform.SupervisionStep{Observation: "LLM 未命中/未启用"})
		} else {
			supSteps = append(supSteps, ctfplatform.SupervisionStep{Observation: "LLM 跳过（未启用）"})
		}

		// 三层全空 → 监督反思
		candCount := 0
		decision := ctfplatform.ReflectSupervision(
			ctfplatform.SupervisionState{BudgetTotal: 3, BudgetUsed: 3, Candidates: &candCount},
			supSteps, nil,
		)

		logger.Info("三层监督反思",
			zap.String("challenge", ch.Title),
			zap.String("decision", decision.Decision),
			zap.String("reason", decision.Reason))

		// ABANDON → 不 retry（当前 Poller 重试未接，先只打日志；后续接 retry 控制）
		return nil, nil
	}

	// ── 4. Poller 配置（全部从 env 取，约定与 app.go 保持一致）─
	pc := ctfplatform.DefaultPollerConfig()

	pc.PollInterval = envDurationMs("CTF_POLL_INTERVAL", pc.PollInterval)
	pc.SolveTimeout = envDurationMs("CTF_SOLVE_TIMEOUT", pc.SolveTimeout)
	pc.MaxConcurrency = envInt("CTF_MAX_CONCURRENCY", pc.MaxConcurrency)
	pc.MaxRetrySubmit = envInt("CTF_MAX_RETRY_SUBMIT", pc.MaxRetrySubmit)
	// 首血扫描（2026-10-24 吞并 P0-3 接线）：窗口内短间隔抢新题，默认 0=关闭（秒，同族 env 惯例）
	pc.FirstBloodWindow = envDurationMs("CTF_FIRST_BLOOD_WINDOW", pc.FirstBloodWindow)
	pc.FirstBloodInterval = envDurationMs("CTF_FIRST_BLOOD_INTERVAL", pc.FirstBloodInterval)
	pc.SubmitAfterSolve = envBool("CTF_AUTOSOLVE_SUBMIT", true) // 赛时默认自动提交
	pc.AutoBuildEnv = envBool("CTF_AUTO_BUILD_ENV", true)
	pc.AutoFetchAttachment = envBool("CTF_AUTO_FETCH_ATTACHMENT", false)
	pc.AutoFetchDetail = envBool("CTF_AUTO_FETCH_DETAIL", true)
	pc.AutoReleaseEnv = envBool("CTF_AUTO_RELEASE_ENV", true)

	// 首血窗口（比赛开场 15 分钟高频抢新题）
	if w := envDurationMs("CTF_FIRST_BLOOD_WINDOW", 0); w > 0 {
		pc.FirstBloodWindow = w
		if i := envDurationMs("CTF_FIRST_BLOOD_INTERVAL", 0); i > 0 && i < pc.PollInterval {
			pc.FirstBloodInterval = i
		}
	}

	logger.Info("Poller 配置",
		zap.Duration("poll_interval", pc.PollInterval),
		zap.Duration("solve_timeout", pc.SolveTimeout),
		zap.Int("max_concurrency", pc.MaxConcurrency),
		zap.Bool("submit_after_solve", pc.SubmitAfterSolve),
		zap.Bool("auto_build_env", pc.AutoBuildEnv),
		zap.Bool("auto_fetch_detail", pc.AutoFetchDetail),
		zap.Bool("auto_release_env", pc.AutoReleaseEnv))

	// ── 5. 开跑 ──────────────────────────────────────────
	poller := ctfplatform.NewPoller(platform, solver, pc, logger)
	poller.SetAdvisor(platform) // 注入抗打击建议（连续 429 阶梯 / WAF 冷却跳过）

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 信号处理：Ctrl+C 优雅退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("收到信号，停止轮询器", zap.String("signal", sig.String()))
		cancel()
	}()

	if err := poller.RunForever(ctx); err != nil && err != context.Canceled {
		logger.Error("轮询器异常退出", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("SecAutoMind Runner 正常退出")
}

func mask(s string) string {
	if s == "" {
		return "(未设置)"
	}
	if len(s) <= 12 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// detectConflictingProcs 检测已有参赛进程（runner 或 ctf-agent）。
// 返回命中的 PID 列表（字符串格式），空列表表示无冲突。
// 排除本进程自己（os.Getpid），避免自匹配。
func detectConflictingProcs() []string {
	selfPid := strconv.Itoa(os.Getpid())

	var patterns []string
	if runtime.GOOS == "windows" {
		patterns = []string{
			"runner.exe", "runner_ctf.exe", "runner_ctf2.exe",
			"runner_v2.exe", "runner_v3.exe", "runner_v4.exe",
			"final_entry.py", "runner_ctf2.py",
		}
	} else {
		// pgrep -f 收紧：匹配二进制路径片段，排除 bash -c wrapper 里的 runner 文字
		patterns = []string{
			"ctf_run/runner",   // 服务器标准路径 ~/ctf_run/runner_v*
			"/runner_ctf",      // runner_ctf / runner_ctf2
			"/final_entry",     // final_entry.py 或二进制
			"sm_dev_20261020/cmd/runner", // go run 临时二进制
		}
	}

	var conflicts []string
	seen := make(map[string]bool)

	for _, p := range patterns {
		var out string
		if runtime.GOOS == "windows" {
			outBytes, e := exec.Command("tasklist", "/FI", "IMAGENAME eq "+p).CombinedOutput()
			if e != nil {
				continue
			}
			out = string(outBytes)
		} else {
			outBytes, e := exec.Command("pgrep", "-f", p).CombinedOutput()
			if e != nil {
				continue
			}
			out = string(outBytes)
		}
		for _, line := range strings.Split(out, "\n") {
			pid := strings.TrimSpace(line)
			if pid == "" || pid == selfPid {
				continue
			}
			if !seen[pid] {
				seen[pid] = true
				conflicts = append(conflicts, pid)
			}
		}
	}
	return conflicts
}

// killPID 跨平台 kill 一个进程。
func killPID(pidStr string) error {
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid)).Run()
	}
	return exec.Command("kill", "-TERM", strconv.Itoa(pid)).Run()
}
