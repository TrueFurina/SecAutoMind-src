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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
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
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	logger.Info("SecAutoMind Runner 启动",
		zap.String("ctf2_token", mask(os.Getenv("CTF2_AGENT_TOKEN"))),
		zap.String("competition_id", os.Getenv("CTF2_COMPETITION_ID")))

	// ── 1. CTF² 平台客户端 ────────────────────────────────
	platform := ctfplatform.NewCTF2Platform("", "", logger)

	// ── 2. Presolver（确定性预解层，零 token 成本）────────
	presolver := ctfplatform.NewPresolver(logger)

	// ── 2.5 Python skill bridge（西湖论剑真跑 skill）─────
	pyBridge := newPySkillRunner(context.Background(), logger)

	// ── 3. Solver 闭包（两层链）────────────────────────
	//   Layer 1: Presolve 确定性求解（189 Go solver，0 token）
	//   Layer 2: Python skill bridge（angr/pwntools 真跑，有依赖门控）
	solver := func(ctx context.Context, ch *ctfplatform.Challenge) ([]string, error) {
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

		// Layer 2: Python skill bridge（依赖有就跑，没有就跳过）
		if ch.Category == "reverse" || ch.Category == "pwn" || ch.Category == "crypto" || ch.Category == "misc" {
			if flags, ok := pyBridge.tryCategory(ctx, ch.Category, ch); ok {
				logger.Info("Layer 2 Python skill 命中",
					zap.String("challenge", ch.Title),
					zap.String("category", ch.Category),
					zap.Strings("flags", flags))
				return flags, nil
			}
		}

		// 两层都没命中 → 返回 nil（Poller 标记 solved=false）
		logger.Debug("两层求解都未命中",
			zap.String("challenge", ch.Title),
			zap.String("category", ch.Category))
		return nil, nil
	}

	// ── 4. Poller 配置（全部从 env 取，约定与 app.go 保持一致）─
	pc := ctfplatform.DefaultPollerConfig()

	pc.PollInterval = envDurationMs("CTF_POLL_INTERVAL", pc.PollInterval)
	pc.SolveTimeout = envDurationMs("CTF_SOLVE_TIMEOUT", pc.SolveTimeout)
	pc.MaxConcurrency = envInt("CTF_MAX_CONCURRENCY", pc.MaxConcurrency)
	pc.MaxRetrySubmit = envInt("CTF_MAX_RETRY_SUBMIT", pc.MaxRetrySubmit)
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
