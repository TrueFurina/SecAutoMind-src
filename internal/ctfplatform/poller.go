package ctfplatform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SolverFunc 定义求解函数签名：输入题目信息，输出候选 flag 列表。
type SolverFunc func(ctx context.Context, ch *Challenge) ([]string, error)

// BackoffAdvisor 平台抗打击建议接口（由 DasCTFPlatform 实现；可选注入 Poller）。
// Poller 据此动态拉长轮询间隔（连续 429 阶梯）或在 WAF 冷却期跳过本轮，
// 避免雪崩式打平台。
type BackoffAdvisor interface {
	BackoffSuggestion(base float64) float64
	WafBlockedSeconds() float64
	LastListOK() bool
}

// PollerConfig 轮询器配置。
type PollerConfig struct {
	PollInterval     time.Duration `json:"poll_interval"`      // 拉题间隔，默认 30s
	SolveTimeout     time.Duration `json:"solve_timeout"`      // 单题求解超时，默认 300s
	SubmitAfterSolve bool          `json:"submit_after_solve"` // 解出后自动提交
	MaxRetrySubmit   int           `json:"max_retry_submit"`   // 提交失败重试次数，默认 2
	MaxConcurrency   int           `json:"max_concurrency"`    // 跨题并发上限，默认 2
	// AutoBuildEnv 对 HasInstance 的题自动「起靶机 → 取访问地址」，并把地址并入题目描述交给求解器。
	// 🔴 默认 false：CreateInstance/GetAccess 此前从未被生产代码调用过（09-17 实锤的生产缺口），
	//    开启前先跑演练台验证（internal/ctfplatform/rehearsal_test.go）。决赛由
	//    环境变量 CTF_AUTO_BUILD_ENV=true 开启（见决赛 runbook）。
	AutoBuildEnv bool `json:"auto_build_env"`
	// AutoFetchAttachment 对 HasAttachment 的题自动「下载附件 → 落到 chat_uploads 白名单 →
	// 以 [用户上传的文件] 标记块并入描述」，让既有执行层求解器（exec_strings / exec_pcap_http …）
	// 直接吃到附件内容 —— Presolve 的 loadChatAttachmentFiles 会自动识别该标记块。
	// 🔴 默认 false：DownloadAttachment 目前是存根（官方附件端点待确认）；链路已由
	//    演练 TestRehearsalAttachmentChain 验证，端点一实现、开关一开即通。
	AutoFetchAttachment bool `json:"auto_fetch_attachment"`
	// AutoFetchDetail 用「题目详情」补全题干与标记。
	// 平台列表里的 description 可能是**摘要**；完整题干（含附件/端点提示）在详情里才给 ——
	// 直接决定解题输入质量。同时详情才标出 has_instance / has_attachment 的题，
	// 这里补齐标记，后两个阶段才不会漏掉（只补 true，绝不覆盖已有 true 为 false）。
	// 默认 false：拿不到详情就静默沿用列表描述，无回退风险。
	AutoFetchDetail bool `json:"auto_fetch_detail"`
	// AutoReleaseEnv 解出并 accepted 后销毁靶机，释放平台配额（起完不销毁会一直占资源）。
	// 仅对"本轮确实起过环境"且"已 accepted"的题生效 —— 未解出的题保留靶机，供人工接手。
	AutoReleaseEnv bool `json:"auto_release_env"`
}

func DefaultPollerConfig() PollerConfig {
	return PollerConfig{
		PollInterval:     30 * time.Second,
		SolveTimeout:     300 * time.Second,
		SubmitAfterSolve: true,
		MaxRetrySubmit:   2,
		MaxConcurrency:   2,
	}
}

// Poller 平台轮询器：定时拉题 → 去重 → 求解 → 提交。
type Poller struct {
	platform PlatformAPI
	solver   SolverFunc
	config   PollerConfig
	logger   *zap.Logger
	advisor  BackoffAdvisor // 可选：平台抗打击建议（连续 429 阶梯 / WAF 冷却）

	mu        sync.Mutex
	processed map[string]bool        // 已处理题目 ID（去重）
	records   map[string]*PollRecord // 审计记录
}

// NewPoller 创建轮询器。
func NewPoller(platform PlatformAPI, solver SolverFunc, config PollerConfig, logger *zap.Logger) *Poller {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Poller{
		platform:  platform,
		solver:    solver,
		config:    config,
		logger:    logger,
		processed: make(map[string]bool),
		records:   make(map[string]*PollRecord),
	}
}

// SetAdvisor 注入平台抗打击建议（可选；nil 表示不做动态退避/WAF 跳过）。
func (p *Poller) SetAdvisor(advisor BackoffAdvisor) {
	p.advisor = advisor
}

// RunOnce 执行一轮：拉题 → 对未处理的新题求解/提交。
func (p *Poller) RunOnce(ctx context.Context) ([]PollRecord, error) {
	challenges, err := p.platform.ListChallenges(ctx)
	if err != nil {
		return nil, fmt.Errorf("拉取题目列表失败: %w", err)
	}

	p.mu.Lock()
	var newChallenges []Challenge
	for _, ch := range challenges {
		// 题号为空 = 列表解析异常：既无法提交（exerciseId 无效），
		// 又会在去重表里坍缩成一个条目吞掉后续题，必须直接跳过。
		if ch.ID == "" {
			continue
		}
		if !p.processed[ch.ID] {
			newChallenges = append(newChallenges, ch)
		}
	}
	p.mu.Unlock()

	if len(newChallenges) == 0 {
		p.mu.Lock()
		n := len(p.processed)
		p.mu.Unlock()
		p.logger.Debug("轮询：无新题", zap.Int("已处理", n))
		return nil, nil
	}

	p.logger.Info("轮询：发现新题", zap.Int("count", len(newChallenges)))

	// 并发求解（受 maxConcurrency 限制）
	sem := make(chan struct{}, p.config.MaxConcurrency)
	var wg sync.WaitGroup
	var recMu sync.Mutex // 仅保护 records 切片；共享 map 一律走 p.mu（GetRecords 亦读 p.mu）
	var records []PollRecord

	for _, ch := range newChallenges {
		wg.Add(1)
		go func(c Challenge) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rec := p.handleChallenge(ctx, &c)

			recMu.Lock()
			records = append(records, *rec)
			recMu.Unlock()
			p.mu.Lock()
			p.records[c.ID] = rec
			p.processed[c.ID] = true
			p.mu.Unlock()
		}(ch)
	}
	wg.Wait()
	return records, nil
}

// RunForever 持续轮询（阻塞）。
// 引入 advisor 后，轮询节奏由「固定 ticker」改为「动态退避」：
//   - ⑤ WAF 冷却中 → 跳过本轮，休眠至冷却结束，避免雪崩；
//   - ④ 连续 429 ≥3 → 按阶梯拉长本轮等待（30s/60s/120s/300s），而非死磕平台。
func (p *Poller) RunForever(ctx context.Context) error {
	p.logger.Info("轮询器启动",
		zap.Duration("interval", p.config.PollInterval),
		zap.Bool("submit_after_solve", p.config.SubmitAfterSolve))

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("轮询器停止")
			return ctx.Err()
		default:
		}

		// ⑤ WAF 冷却中：跳过本轮，休眠至冷却结束
		if p.advisor != nil {
			if secs := p.advisor.WafBlockedSeconds(); secs > 0 {
				p.logger.Warn("WAF 风控冷却中，跳过本轮", zap.Float64("剩余秒", secs))
				if err := p.sleepCtx(ctx, time.Duration(secs)*time.Second); err != nil {
					return err
				}
				continue
			}
		}

		records, err := p.RunOnce(ctx)
		if err != nil {
			p.logger.Error("轮询失败", zap.Error(err))
		} else {
			for _, rec := range records {
				if rec.Accepted {
					p.logger.Info("✅ flag 已接受",
						zap.String("题目", rec.Title),
						zap.String("flag", rec.Flag))
				}
			}
		}

		// ④ 连续 429 阶梯退避：建议间隔 > 基础间隔时拉长本轮等待
		wait := p.config.PollInterval
		if p.advisor != nil {
			if s := p.advisor.BackoffSuggestion(p.config.PollInterval.Seconds()); s > wait.Seconds() {
				wait = time.Duration(s) * time.Second
			}
		}
		if err := p.sleepCtx(ctx, wait); err != nil {
			return err
		}
	}
}

// sleepCtx 在 ctx 取消前休眠 d（尊重生命周期，便于优雅退出）。
func (p *Poller) sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// FilterFlagCandidates 仅保留 flag 形态的候选，杜绝把 "hash_crack: x=weak" 这类
// 非 flag 文本误提交到真实平台。旗形判定沿用 flagRegex。
func FilterFlagCandidates(flags []string) []string {
	var out []string
	for _, f := range flags {
		if flagRegex.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

// GetRecords 获取审计记录。
func (p *Poller) GetRecords() map[string]*PollRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make(map[string]*PollRecord, len(p.records))
	for k, v := range p.records {
		result[k] = v
	}
	return result
}

// handleChallenge 处理单题：求解 → 提交（含墙钟止损）。
func (p *Poller) handleChallenge(ctx context.Context, ch *Challenge) *PollRecord {
	rec := &PollRecord{
		ChallengeID: ch.ID,
		Title:       ch.Title,
		Category:    ch.Category,
		StartedAt:   time.Now(),
	}

	// 墙钟止损
	solveCtx, cancel := context.WithTimeout(ctx, p.config.SolveTimeout)
	defer cancel()

	// ① 详情补全（放最前：详情可能才标出需要靶机/附件，后两步依赖这些标记）
	var builtEnv bool
	if p.config.AutoFetchDetail {
		p.enrichFromDetail(ctx, ch, rec)
	}

	// ①-b HasInstance 兜底双保险（防隐藏翻车）：
	// 若开了 AutoBuildEnv 但题目标记「需要靶机」仍未被任何来源确认
	// （列表接口不返回 has_instance 字段，且上面 ① 因 AutoFetchDetail 未开没跑过），
	// 则专门为建靶机目的用独立短超时再拉一次详情补全 HasInstance。
	// 否则会静默跳过 buildEnvAndInject → web/pwn 题整题 0 分，且全程无任何报错。
	// 失败/超时一律静默沿用（不阻塞求解），仅记入 rec.Detail。
	// 收窄：仅对「需要靶机的题型」(web/pwn/reverse) 补全，避免对 MISC/CRYPTO 明文题
	// 误建靶机（rehearsal 反向对照依赖此语义：build-env 仅对真正需靶机题调用）。
	if p.config.AutoBuildEnv && !ch.HasInstance && !p.config.AutoFetchDetail && isEnvCategory(ch.Category) {
		detailCtx, detailCancel := context.WithTimeout(ctx, 15*time.Second)
		p.enrichFromDetail(detailCtx, ch, rec)
		detailCancel()
	}

	// ② 起靶机（决赛关键链，默认关闭；见 PollerConfig.AutoBuildEnv）。
	// 官方平台把靶机地址放在 challenge_detail.endpoints[].exposeIps[0]，
	// 而 CreateInstance/GetAccess 此前从未被生产代码调用（09-17 实锤的生产缺口）——
	// 需要靶机的题会因"没有可打的地址"整题 0 分。
	if p.config.AutoBuildEnv && ch.HasInstance {
		builtEnv = p.buildEnvAndInject(ctx, ch, rec)
	}

	// ③ 附件下载（默认关闭；见 PollerConfig.AutoFetchAttachment）。
	// 此前 DownloadAttachment 是存根且无人调用、app 层恒传 nil attachments ——
	// 附件题（取证/二进制/pcap）的执行层求解器在真实流程里整个休眠。
	if p.config.AutoFetchAttachment && ch.HasAttachment {
		p.fetchAttachments(ctx, ch, rec)
	}

	// 求解
	flags, err := p.solver(solveCtx, ch)
	if err != nil {
		rec.Error = err.Error()
		rec.FinishedAt = time.Now()
		p.logger.Warn("求解失败", zap.String("题目", ch.Title), zap.Error(err))
		return rec
	}

	if len(flags) == 0 {
		rec.Error = "无候选 flag"
		rec.FinishedAt = time.Now()
		return rec
	}

	// 兜底闸门：只认 flag 形态候选。Poller 是被外部复用的公开 API，
	// 调用方若未过滤，此处必须拦住 "hash_crack: x=weak" 之类文本误提交真实平台。
	flags = FilterFlagCandidates(flags)
	if len(flags) == 0 {
		rec.Error = "候选均不符合 flag 格式，已拦截"
		rec.FinishedAt = time.Now()
		p.logger.Warn("拦截非 flag 形态候选", zap.String("题目", ch.Title))
		return rec
	}

	rec.Flag = flags[0]
	rec.ExtraCandidates = flags

	// 提交
	if p.config.SubmitAfterSolve {
		for i, flag := range flags {
			if i > p.config.MaxRetrySubmit {
				break
			}
			result, submitErr := p.platform.SubmitFlag(ctx, ch.ID, flag)
			if submitErr != nil {
				rec.Error = submitErr.Error()
				continue
			}
			rec.Submitted = true
			rec.Accepted = result.Correct
			rec.Detail = result.Detail
			if result.Correct {
				rec.Flag = flag
				break
			}
		}
	}

	// ④ 回收靶机：仅对本轮确实起过环境且已 accepted 的题（未解出的保留环境供人工接手）
	if builtEnv && p.config.AutoReleaseEnv && rec.Accepted {
		if err := p.platform.DestroyInstance(ctx, ch.ID); err != nil {
			p.logger.Warn("销毁靶机失败（仅影响资源占用，不影响本题得分）",
				zap.String("题目", ch.Title), zap.Error(err))
			rec.Detail += "销毁靶机失败: " + err.Error() + "; "
		} else {
			rec.Detail += "靶机已回收; "
			p.logger.Info("靶机已回收", zap.String("题目", ch.Title))
		}
	}

	rec.FinishedAt = time.Now()
	return rec
}

// enrichFromDetail 用题目详情补全题干与标记（见 PollerConfig.AutoFetchDetail）。
// 失败/详情为空一律静默沿用列表描述 —— 无回退风险（这是它默认也能安全开启的原因）。
func (p *Poller) enrichFromDetail(ctx context.Context, ch *Challenge, rec *PollRecord) {
	d, err := p.platform.GetChallenge(ctx, ch.ID)
	if err != nil || d == nil {
		p.logger.Debug("取题目详情失败，沿用列表描述",
			zap.String("题目", ch.Title), zap.Error(err))
		rec.Detail += "取详情失败（沿用列表描述）; "
		return
	}
	if len(strings.TrimSpace(d.Description)) > len(strings.TrimSpace(ch.Description)) {
		ch.Description = d.Description
		rec.Detail += "题干已用详情补全; "
		p.logger.Info("题干已用详情补全", zap.String("题目", ch.Title),
			zap.Int("长度", len(ch.Description)))
	}
	// 只补 true，绝不把已有 true 改成 false（详情缺失不能反过来削弱列表信息）
	if d.HasInstance {
		ch.HasInstance = true
	}
	if d.HasAttachment {
		ch.HasAttachment = true
	}
	if strings.TrimSpace(ch.Category) == "" && strings.TrimSpace(d.Category) != "" {
		ch.Category = d.Category
	}
}

// buildEnvAndInject 为需要靶机的题启动环境，并把访问地址注入求解上下文。
// 返回值：本轮是否**确实起过环境**（供 AutoReleaseEnv 决定是否回收）。
//
// 注入方式有二（求解器两条路都能吃到）：
//  1. ch.Extra["target_url"]  —— 结构化读取（新求解器用这个）；
//  2. 追加到 ch.Description   —— 既有求解器/presolve 的 ExploitURLsInText 会扫文本里的 URL，
//     这样不改任何既有求解器就能打上靶。
//
// 失败不致命：记入 rec.Detail 后继续求解（"没有靶机也试一把"好过整题卡死）。
// ch 是每题一份的副本（RunOnce 里 go func(c Challenge) 传值），这里改它不影响共享状态。
// isEnvCategory 判断题型是否需要启动靶机实例（web/pwn/reverse 类）。
func isEnvCategory(cat string) bool {
	switch strings.ToLower(strings.TrimSpace(cat)) {
	case "web", "pwn", "reverse":
		return true
	}
	return false
}

func (p *Poller) buildEnvAndInject(ctx context.Context, ch *Challenge, rec *PollRecord) bool {
	created := false
	if inst, err := p.platform.CreateInstance(ctx, ch.ID); err != nil {
		// 平台可能返回"环境已存在"之类的业务错误 —— 不视为致命，继续取地址。
		p.logger.Warn("起靶机失败（继续尝试取地址）",
			zap.String("题目", ch.Title), zap.String("challengeID", ch.ID), zap.Error(err))
		rec.Detail += "起靶机失败: " + err.Error() + "; "
	} else {
		created = true
		p.logger.Info("靶机已启动", zap.String("题目", ch.Title),
			zap.String("instance", inst.InstanceID), zap.String("status", inst.Status))
		rec.Detail += "靶机实例 " + inst.InstanceID + "; "
	}

	// GetAccess 传的是 exerciseId（题号）—— 真源踩坑记录：靶机地址在
	// challenge_detail.endpoints[].exposeIps[0]，不在 build_env 返回里。
	acc, err := p.platform.GetAccess(ctx, ch.ID)
	if err != nil {
		p.logger.Warn("获取靶机地址失败", zap.String("题目", ch.Title), zap.Error(err))
		rec.Detail += "取靶机地址失败: " + err.Error() + "; "
		return created
	}
	if strings.TrimSpace(acc.URL) == "" {
		rec.Detail += "靶机地址为空; "
		return created
	}
	if ch.Extra == nil {
		ch.Extra = map[string]interface{}{}
	}
	ch.Extra["target_url"] = acc.URL
	if !strings.Contains(ch.Description, acc.URL) {
		ch.Description += "\n靶机地址: " + acc.URL
	}
	rec.Detail += "靶机地址 " + acc.URL + "; "
	return created
}

// fetchAttachments 下载题目附件，并以「[用户上传的文件]」标记块并入题目描述。
//
// 为什么用这个格式：Presolve 入口的 loadChatAttachmentFiles 已实现
// 「识别标记块 → 校验 chat_uploads 白名单 → 读入内容 → 灌给执行层求解器」的完整链路
//（见 presolve_attachment.go），这里只是把平台附件接进同一入口，零求解器改动。
//
// 失败/为空都不致命：附件端点尚未由官方确认（DownloadAttachment 存根），
// 如实记入 rec.Detail 后继续求解。
func (p *Poller) fetchAttachments(ctx context.Context, ch *Challenge, rec *PollRecord) {
	paths, err := p.platform.DownloadAttachment(ctx, ch.ID)
	if err != nil {
		p.logger.Warn("附件下载失败", zap.String("题目", ch.Title), zap.Error(err))
		rec.Detail += "附件下载失败: " + err.Error() + "; "
		return
	}
	if len(paths) == 0 {
		// 存根返回 nil,nil → 如实记录，不算失败
		rec.Detail += "平台未返回附件（DownloadAttachment 存根，官方端点待确认）; "
		return
	}

	final, err := ensureUnderChatUploads(ch.ID, paths)
	if err != nil {
		p.logger.Warn("附件落位白名单目录失败", zap.String("题目", ch.Title), zap.Error(err))
		rec.Detail += "附件落位失败: " + err.Error() + "; "
		return
	}

	var b strings.Builder
	b.WriteString("\n[用户上传的文件]\n")
	for _, f := range final {
		b.WriteString("- " + filepath.Base(f) + ": " + f + "\n")
	}
	ch.Description += b.String()
	rec.Detail += fmt.Sprintf("附件 %d 个已就位; ", len(final))
	p.logger.Info("附件已就位", zap.String("题目", ch.Title), zap.Int("count", len(final)))
}

// ensureUnderChatUploads 把附件路径归位到 chat_uploads 白名单之下
//（presolve 的 loadChatAttachmentFiles 只读该目录内的文件）。
// 已在白名单内的直接复用；在外的复制一份进去（平台实现方存哪不管，链路不断）。
func ensureUnderChatUploads(challengeID string, paths []string) ([]string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	uploadRoot, err := filepath.Abs(filepath.Join(cwd, "chat_uploads"))
	if err != nil {
		return nil, err
	}
	dest := filepath.Join(uploadRoot, "ctf", challengeID)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(paths))
	for _, raw := range paths {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		abs, err := filepath.Abs(raw)
		if err != nil {
			continue
		}
		if inDir(abs, uploadRoot) {
			out = append(out, abs) // 已在白名单内
			continue
		}
		st, err := os.Stat(abs)
		if err != nil || !st.Mode().IsRegular() {
			continue // 不存在/非普通文件：跳过，不影响其余附件
		}
		dst := filepath.Join(dest, filepath.Base(abs))
		if err := copyFile(abs, dst); err != nil {
			continue
		}
		out = append(out, dst)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无有效附件可落位（原始 %d 个）", len(paths))
	}
	return out, nil
}

// inDir 判断 abs 是否位于 dir 目录内（防穿越）。
func inDir(abs, dir string) bool {
	rel, err := filepath.Rel(dir, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// copyFile 复制普通文件（覆盖同名）。
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// flagRegex 通用 flag 格式匹配。
var flagRegex = regexp.MustCompile(`(?i)(?:flag|ctf|dasctf)\{[^}]{3,}\}`)

// ExtractFlags 从文本中提取 flag 候选。
func ExtractFlags(text string) []string {
	matches := flagRegex.FindAllString(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}
