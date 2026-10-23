package ctfplatform

// CTF2Platform：CTF² 平台（ctf2.dasctf.com）AI Agent REST 客户端。
//
// 与 DasCTFPlatform（/slab-match/... + X-Agent-AccessKey）不同，CTF² 的 Agent 协议为：
//   - 端点前缀：/api/open/v1/user/agent/（比赛模式 competitions/{id}/stages/{stageId}/challenges/...）
//   - 鉴权：Authorization: Bearer <CTF2_AGENT_TOKEN>
//   - 提交 flag 需 confirmation=true（防误交）；规则禁止爆破 flag
// 协议真源：docs/ctf2_user_openapi.json（平台 /api/openapi/v1/user.json，2026-10-23 拉取）。
//
// 抗打击治理镜像 DasCTFPlatform（7 项）：指数退避重试、Retry-After 尊重、连续 429
// 计数与阶梯建议、403 WAF 冷却、列表 TTL 缓存、HTTP 连接复用、UA/Content-Type 伪装。
// 所有方法类型安全——失败返回零值/默认对象 + error，不 panic。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PlatformClient 生产接线所需的最小方法集：平台选择（DasCTF / CTF²）的统一入口。
// 两个实现都满足：PlatformAPI（9 个生命周期方法）+ BackoffAdvisor（429 阶梯/WAF
// 冷却建议）+ SetAntiBlock（抗打击治理开关）。app.go 构造时据此接口选择平台。
type PlatformClient interface {
	PlatformAPI
	BackoffAdvisor
	SetAntiBlock(o AntiBlockOptions)
}

// 编译期断言：两个平台实现都满足接线接口。
var (
	_ PlatformClient = (*DasCTFPlatform)(nil)
	_ PlatformClient = (*CTF2Platform)(nil)
)

// CTF2Platform 实现 PlatformAPI + BackoffAdvisor + SetAntiBlock。
type CTF2Platform struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	Logger     *zap.Logger

	// 比赛上下文：competition_id + stage_id（AI Agent 赛道阶段）。
	// 可用环境变量 CTF2_COMPETITION_ID / CTF2_STAGE_ID 显式指定；
	// 未指定时自动发现：agent/me 的 active_competitions 中 running 且
	// agent_stage_count>0 的第一个比赛，取其 audience=agent 的第一个 running 阶段。
	CompetitionID string
	StageID       string

	// ── 抗打击治理（镜像 DasCTFPlatform）──
	MaxRetries       int
	RetryBackoff     time.Duration
	WAFTimeout       time.Duration
	listCacheTTL     time.Duration
	mu               sync.Mutex
	consec429        int
	wafBlockedUntil  time.Time
	lastListOK       bool
	listCache        []Challenge
	listCacheAt      time.Time
	lastError        string
	antiBlockDisabled bool

	ctxOnce sync.Once
	ctxErr  error
}

// CTF2 默认端点前缀（对齐平台 OpenAPI，2026-10-23 实测）。
const (
	ctf2AgentBase = "/api/open/v1/user/agent"
	// Bearer 鉴权头模板
	ctf2AuthScheme = "Bearer"
	// CTF² 平台默认地址
	ctf2DefaultBaseURL = "https://ctf2.dasctf.com"
)

// ctf2AgentCompID / ctf2AgentStageID 从环境变量读取（显式指定优先）。
const (
	envCTF2BaseURL       = "CTF2_BASE_URL"
	envCTF2Token         = "CTF2_AGENT_TOKEN"
	envCTF2CompetitionID = "CTF2_COMPETITION_ID"
	envCTF2StageID       = "CTF2_STAGE_ID"
)

// NewCTF2Platform 创建 CTF² 平台客户端。base_url/token 为空时从环境变量读取。
func NewCTF2Platform(baseURL, token string, logger *zap.Logger) *CTF2Platform {
	if baseURL == "" {
		baseURL = os.Getenv(envCTF2BaseURL)
	}
	if baseURL == "" {
		baseURL = ctf2DefaultBaseURL
	}
	if token == "" {
		token = os.Getenv(envCTF2Token)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CTF2Platform{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      token,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Logger:     logger,
		CompetitionID: os.Getenv(envCTF2CompetitionID),
		StageID:       os.Getenv(envCTF2StageID),
		MaxRetries:    5,
		RetryBackoff:  2 * time.Second,
		WAFTimeout:    300 * time.Second,
		listCacheTTL:  listCacheTTLFromEnv(),
	}
}

// CTF2Configured 报告 CTF² 环境是否具备接入条件（base_url + token 均已设置）。
func CTF2Configured() bool {
	return os.Getenv(envCTF2BaseURL) != "" && os.Getenv(envCTF2Token) != ""
}

// ── 抗打击治理（与 DasCTFPlatform 同语义）────────────────

func (p *CTF2Platform) antiBlockOn() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.antiBlockDisabled
}

func (p *CTF2Platform) wafTimeout() time.Duration {
	if p.WAFTimeout <= 0 {
		return 300 * time.Second
	}
	return p.WAFTimeout
}

func (p *CTF2Platform) setLastError(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastError = msg
}

// SetAntiBlock 开关抗打击治理（镜像 DasCTFPlatform：关闭时清零残留状态）。
func (p *CTF2Platform) SetAntiBlock(o AntiBlockOptions) {
	p.mu.Lock()
	p.antiBlockDisabled = !o.Enabled
	if !o.Enabled {
		p.consec429 = 0
		p.wafBlockedUntil = time.Time{}
		p.listCache = nil
		p.listCacheAt = time.Time{}
		p.lastListOK = true
	}
	p.mu.Unlock()
	if o.Enabled {
		if o.MaxRetries > 0 {
			p.MaxRetries = o.MaxRetries
		}
		if o.RetryBackoff > 0 {
			p.RetryBackoff = o.RetryBackoff
		}
		if o.WAFTimeout > 0 {
			p.WAFTimeout = o.WAFTimeout
		}
		if o.ListCacheTTL != nil {
			p.listCacheTTL = *o.ListCacheTTL
		}
	}
}

func (p *CTF2Platform) LastListOK() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastListOK
}

func (p *CTF2Platform) incConsec429() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consec429++
	return p.consec429
}

func (p *CTF2Platform) resetConsec429() {
	p.mu.Lock()
	p.consec429 = 0
	p.mu.Unlock()
}

func (p *CTF2Platform) Consec429() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.consec429
}

// BackoffSuggestion 连续 429 阶梯建议（≥12→300s；≥8→120s；≥5→60s；≥3→30s）。
func (p *CTF2Platform) BackoffSuggestion(base float64) float64 {
	if !p.antiBlockOn() {
		return 0
	}
	n := p.Consec429()
	switch {
	case n >= 12:
		return 300
	case n >= 8:
		return 120
	case n >= 5:
		return 60
	case n >= 3:
		return 30
	default:
		return 0
	}
}

// WafBlockedSeconds 返回 WAF 冷却剩余秒数（>0 = 冷却中）。
func (p *CTF2Platform) WafBlockedSeconds() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.antiBlockDisabled {
		return 0
	}
	if p.wafBlockedUntil.IsZero() {
		return 0
	}
	d := time.Until(p.wafBlockedUntil)
	if d <= 0 {
		p.wafBlockedUntil = time.Time{}
		return 0
	}
	return d.Seconds()
}

func (p *CTF2Platform) sleepCtx(ctx context.Context, d time.Duration) error {
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

// ── 底层请求（Bearer 鉴权 + 重试 + 429/403 治理，镜像 dasctf.go）────────────────

func (p *CTF2Platform) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	if p.BaseURL == "" {
		return nil, 0, fmt.Errorf("CTF² BaseURL 未配置（设置 %s 环境变量）", envCTF2BaseURL)
	}
	url := p.BaseURL + path

	antiBlock := p.antiBlockOn()

	if antiBlock {
		if secs := p.WafBlockedSeconds(); secs > 0 {
			return nil, 0, fmt.Errorf("CTF² WAF 风控冷却中(剩余 %.0fs)，跳过平台请求", secs)
		}
	}

	maxRetries := p.MaxRetries
	if !antiBlock {
		maxRetries = 0
	} else if maxRetries <= 0 {
		maxRetries = 5
	}
	backoff := p.RetryBackoff
	if backoff <= 0 {
		backoff = 2 * time.Second
	}

	var lastErr error
	var lastStatus int
	var retryAfter string
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := p.sleepCtx(ctx, computeBackoff(backoff, attempt, retryAfter)); err != nil {
				return nil, lastStatus, err
			}
		}
		var reqBody io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, 0, fmt.Errorf("序列化请求体失败: %w", err)
			}
			reqBody = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return nil, 0, fmt.Errorf("创建请求失败: %w", err)
		}
		// CTF² 鉴权：Authorization: Bearer <token>
		if p.Token != "" {
			req.Header.Set("Authorization", ctf2AuthScheme+" "+p.Token)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", defaultUserAgent)
		resp, err := p.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			lastStatus = 0
			p.setLastError(fmt.Sprintf("%v", err))
			continue
		}
		data, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			lastStatus = resp.StatusCode
			p.setLastError(fmt.Sprintf("读取响应失败: %v", rerr))
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated:
			if antiBlock {
				p.resetConsec429()
			}
			return data, resp.StatusCode, nil
		case http.StatusForbidden:
			if antiBlock {
				cooldown := p.wafTimeout()
				p.mu.Lock()
				p.wafBlockedUntil = time.Now().Add(cooldown)
				p.mu.Unlock()
				msg := fmt.Sprintf("CTF² 平台 403 WAF 风控（冷却 %s）", cooldown)
				p.setLastError(msg)
				return nil, resp.StatusCode, fmt.Errorf("%s", msg)
			}
			msg := fmt.Sprintf("CTF² 平台 403（抗打击治理已回退，未启用 WAF 冷却）: %s", truncate(string(data), 200))
			p.setLastError(msg)
			return nil, resp.StatusCode, fmt.Errorf("%s", msg)
		case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			if antiBlock && resp.StatusCode == http.StatusTooManyRequests {
				p.incConsec429()
			}
			retryAfter = resp.Header.Get("Retry-After")
			lastStatus = resp.StatusCode
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			p.setLastError(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 200)))
			continue
		default:
			p.setLastError(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 200)))
			return nil, resp.StatusCode, fmt.Errorf("CTF² 平台返回 HTTP %d, body=%s", resp.StatusCode, truncate(string(data), 400))
		}
	}
	if !antiBlock {
		return nil, lastStatus, fmt.Errorf("CTF² 平台请求失败(抗打击治理已回退，未重试): %v", lastErr)
	}
	return nil, lastStatus, fmt.Errorf("CTF² 平台请求重试耗尽(%d次): %v", maxRetries, lastErr)
}

// ── 比赛上下文发现 ────────────────────────────

// ensureContext 确保 competition_id + stage_id 可用：显式配置优先，否则自动发现
// （agent/me → active_competitions 中 running + agent_stage_count>0 → 该比赛
// 的 agent 阶段中 running 的第一个）。失败时给出可操作错误。
func (p *CTF2Platform) ensureContext(ctx context.Context) error {
	p.ctxOnce.Do(func() {
		if p.CompetitionID != "" && p.StageID != "" {
			return
		}
		cid, sid, err := p.discoverContext(ctx)
		if err != nil {
			p.ctxErr = err
			return
		}
		p.CompetitionID = cid
		p.StageID = sid
	})
	return p.ctxErr
}

// discoverContext 自动发现运行中的 Agent 比赛与阶段。
// 已显式配置 CompetitionID 时直接用它查阶段（不再从 agent/me 猜比赛，
// 避免赛前调试赛与正式赛并存时选错目标）。
func (p *CTF2Platform) discoverContext(ctx context.Context) (string, string, error) {
	// 0) 显式比赛优先
	if p.CompetitionID != "" {
		return p.discoverStage(ctx, p.CompetitionID)
	}
	// 1) agent/me → active_competitions
	data, _, err := p.doRequest(ctx, http.MethodGet, ctf2AgentBase+"/me/?limit=1", nil)
	if err != nil {
		return "", "", fmt.Errorf("CTF² agent/me 失败（需先配置 %s 且在平台创建 Agent）: %w", envCTF2Token, err)
	}
	var meResp struct {
		Data struct {
			ActiveCompetitions []struct {
				ID              string `json:"id"`
				Name            string `json:"name"`
				Status          string `json:"status"`
				AgentStageCount int    `json:"agent_stage_count"`
			} `json:"active_competitions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &meResp); err != nil {
		return "", "", fmt.Errorf("解析 agent/me 失败: %w", err)
	}
	var comp *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	for i := range meResp.Data.ActiveCompetitions {
		c := &meResp.Data.ActiveCompetitions[i]
		if c.Status == "running" && c.AgentStageCount > 0 {
			comp = &struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{ID: c.ID, Name: c.Name}
			break
		}
	}
	if comp == nil {
		// 无运行中的比赛：可能比赛未开放或 Agent 未关联。回到 agent/me 列表兜底取第一个。
		if len(meResp.Data.ActiveCompetitions) == 0 {
			return "", "", fmt.Errorf("CTF² 无可用比赛（agent/me 的 active_competitions 为空）；请确认平台赛事已开放 Agent 赛道")
		}
		comp = &struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{ID: meResp.Data.ActiveCompetitions[0].ID, Name: meResp.Data.ActiveCompetitions[0].Name}
	}
	return p.discoverStage(ctx, comp.ID)
}

// discoverStage 查询指定比赛的 AI Agent 阶段（running + CTF 优先，兜底取首个阶段）。
func (p *CTF2Platform) discoverStage(ctx context.Context, compID string) (string, string, error) {
	data, _, err := p.doRequest(ctx, http.MethodGet,
		ctf2AgentBase+"/competitions/"+compID+"/?limit=1", nil)
	if err != nil {
		return "", "", fmt.Errorf("CTF² 比赛详情失败（比赛 %s）: %w", compID, err)
	}
	var compResp struct {
		Data struct {
			Name string `json:"name"`
			Stages []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
				Type   string `json:"type"`
			} `json:"stages"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &compResp); err != nil {
		return "", "", fmt.Errorf("解析比赛详情失败: %w", err)
	}
	for _, s := range compResp.Data.Stages {
		if s.Status == "running" && s.Type == "CTF" {
			p.Logger.Info("CTF² 上下文发现",
				zap.String("competition_id", compID),
				zap.String("competition", compResp.Data.Name),
				zap.String("stage_id", s.ID),
				zap.String("stage", s.Name))
			return compID, s.ID, nil
		}
	}
	if len(compResp.Data.Stages) > 0 {
		s := compResp.Data.Stages[0]
		p.Logger.Info("CTF² 上下文发现（取首个阶段）",
			zap.String("competition_id", compID),
			zap.String("stage_id", s.ID),
			zap.String("stage", s.Name))
		return compID, s.ID, nil
	}
	return "", "", fmt.Errorf("CTF² 比赛 %s 无可用阶段（stages 为空）", compID)
}

// challengeListPath / challengePath / challengeSubPath 构建比赛模式端点。
func (p *CTF2Platform) challengeListPath() (string, error) {
	if err := p.ensureContext(context.Background()); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/competitions/%s/stages/%s/challenges/",
		ctf2AgentBase, p.CompetitionID, p.StageID), nil
}

func (p *CTF2Platform) challengePath(id string) (string, error) {
	base, err := p.challengeListPath()
	if err != nil {
		return "", err
	}
	return base + id + "/", nil
}

// ── PlatformAPI 实现 ───────────────────────────

// ListChallenges 拉取比赛阶段题目列表（含 solve 状态），带 TTL 缓存。
func (p *CTF2Platform) ListChallenges(ctx context.Context) ([]Challenge, error) {
	p.mu.Lock()
	if !p.antiBlockDisabled && p.listCacheTTL > 0 && p.listCacheAt.After(time.Now().Add(-p.listCacheTTL)) && p.listCache != nil {
		cache := append([]Challenge(nil), p.listCache...)
		p.mu.Unlock()
		return cache, nil
	}
	p.mu.Unlock()

	path, err := p.challengeListPath()
	if err != nil {
		return nil, err
	}
	data, status, err := p.doRequest(ctx, http.MethodGet, path+"?limit=100", nil)
	if err != nil {
		p.mu.Lock()
		p.lastListOK = false
		p.mu.Unlock()
		return nil, err
	}
	var listResp struct {
		Data struct {
			Items []struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				Category      string `json:"category"`
				Difficulty    string `json:"difficulty"`
				Points        int    `json:"points"`
				HasAttach     bool   `json:"has_attachments"`
				HasContainer  bool   `json:"has_container"`
				IsSolved      bool   `json:"is_solved"`
				SolveCount    int    `json:"solve_count"`
				SubmissionT   string `json:"submission_type"`
				ScoreMult     float64 `json:"score_multiplier"`
				CompetitionID string `json:"competition_id"`
				StageID       string `json:"stage_id"`
			} `json:"items"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &listResp); err != nil {
		return nil, fmt.Errorf("解析题目列表失败: %w", err)
	}
	challenges := make([]Challenge, 0, len(listResp.Data.Items))
	for _, it := range listResp.Data.Items {
		extra := map[string]interface{}{
			"submission_type": it.SubmissionT,
			"competition_id":  it.CompetitionID,
			"stage_id":        it.StageID,
			"is_solved":       it.IsSolved,
			"solve_count":     it.SolveCount,
			"score_multiplier": it.ScoreMult,
		}
		challenges = append(challenges, Challenge{
			ID:            it.ID,
			Title:         it.Name,
			Category:      it.Category,
			Score:         it.Points,
			HasInstance:   it.HasContainer,
			HasAttachment: it.HasAttach,
			Difficulty:    it.Difficulty,
			Extra:         extra,
		})
	}
	p.mu.Lock()
	p.lastListOK = true
	if p.listCacheTTL > 0 {
		p.listCache = append([]Challenge(nil), challenges...)
		p.listCacheAt = time.Now()
	} else {
		p.listCache = nil
	}
	p.mu.Unlock()
	_ = status
	return challenges, nil
}

// GetChallenge 获取单题完整详情（题干/附件列表/提交类型）。
func (p *CTF2Platform) GetChallenge(ctx context.Context, challengeID string) (*Challenge, error) {
	path, err := p.challengePath(challengeID)
	if err != nil {
		return nil, err
	}
	data, _, err := p.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var detailResp struct {
		Data struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			Category          string `json:"category"`
			Difficulty        string `json:"difficulty"`
			Description       string `json:"description"`
			Points            int    `json:"points"`
			HasAttach         bool   `json:"has_attachments"`
			HasContainer      bool   `json:"has_container"`
			SubmissionT       string `json:"submission_type"`
			PersonalFilesSt   string `json:"personal_files_status"`
			Files             []struct {
				FileID   string `json:"file_id"`
				FileName string `json:"file_name"`
				Kind     string `json:"kind"`
				MimeType string `json:"mime_type"`
				Size     int64  `json:"size"`
			} `json:"files"`
			SolveCount int `json:"solve_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &detailResp); err != nil {
		return nil, fmt.Errorf("解析题详情失败: %w", err)
	}
	d := &detailResp.Data
	files := make([]map[string]interface{}, 0, len(d.Files))
	for _, f := range d.Files {
		files = append(files, map[string]interface{}{
			"file_id":   f.FileID,
			"file_name": f.FileName,
			"kind":      f.Kind,
			"mime_type": f.MimeType,
			"size":      f.Size,
		})
	}
	extra := map[string]interface{}{
		"submission_type":      d.SubmissionT,
		"personal_files_status": d.PersonalFilesSt,
		"files":                files,
		"solve_count":          d.SolveCount,
	}
	ch := &Challenge{
		ID:            d.ID,
		Title:         d.Name,
		Category:      d.Category,
		Description:   d.Description,
		Score:         d.Points,
		HasInstance:   d.HasContainer,
		HasAttachment: d.HasAttach,
		Difficulty:    d.Difficulty,
		FlagFormat:    extractFlagFormat(d.Description),
		Extra:         extra,
	}
	return ch, nil
}

// flagRe 从题干描述中提取 flag 格式（如 DASCTF{...} / flag{...}）。
var flagRe = regexp.MustCompile(`(?i)([a-zA-Z0-9_]{2,20})\{([^}]*\.[^}]*)|\{([^}]+)\}`)

func extractFlagFormat(desc string) string {
	if desc == "" {
		return ""
	}
	// 常见形式：flag 格式：DASCTF{...}、flag{xxx} 等
	if m := regexp.MustCompile(`(?i)(?:flag|格式)[^\n]{0,60}?(DASCTF\{[^}\n]{0,20}\}|flag\{[^}\n]{0,20}\}|[A-Za-z0-9_]+\{[^}\n]{0,20}\})`).FindString(desc); m != "" {
		return m
	}
	return ""
}

// CreateInstance 启动比赛靶机环境（首次 start 自动参赛）。
func (p *CTF2Platform) CreateInstance(ctx context.Context, challengeID string) (*Instance, error) {
	path, err := p.challengePath(challengeID)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{}
	data, _, err := p.doRequest(ctx, http.MethodPost, path+"environment/start/", body)
	if err != nil {
		return nil, err
	}
	var envResp struct {
		Data struct {
			EnvironmentID string `json:"environment_id"`
			Status        string `json:"status"`
			AccessReady   bool   `json:"access_ready"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &envResp); err != nil {
		return nil, fmt.Errorf("解析启动环境响应失败: %w", err)
	}
	status := envResp.Data.Status
	if status == "" {
		status = "starting"
	}
	return &Instance{
		InstanceID: envResp.Data.EnvironmentID,
		Status:     status,
		Extra:      map[string]interface{}{"access_ready": envResp.Data.AccessReady},
	}, nil
}

// GetAccess 读取环境状态与访问地址。
func (p *CTF2Platform) GetAccess(ctx context.Context, instanceID string) (*Access, error) {
	// CTF² 以 challengeId 为环境上下文；instanceID 即 environment_id，
	// 环境查询端点同样挂在 challenge 下——用 instanceID 兜底：先尝试按
	// challenge 路径查（instanceID 为 challengeID 语义，挑战杯兼容），
	// 失败则报错提示。真实赛程中 ListChallenges 返回的 Challenge.ID 即 challengeId。
	path, err := p.challengePath(instanceID)
	if err != nil {
		return nil, err
	}
	data, _, err := p.doRequest(ctx, http.MethodGet, path+"environment/", nil)
	if err != nil {
		return nil, err
	}
	var envResp struct {
		Data struct {
			EnvironmentID string `json:"environment_id"`
			Status        string `json:"status"`
			AccessReady   bool   `json:"access_ready"`
			AccessType    string `json:"access_type"`
			AccessURL     string `json:"access_url"`
			AccessURLs    []struct {
				Type  string `json:"type"`
				URL   string `json:"url"`
				NCSSL *bool  `json:"nc_ssl"`
			} `json:"access_urls"`
			RemainingSeconds int `json:"remaining_seconds"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &envResp); err != nil {
		return nil, fmt.Errorf("解析环境状态失败: %w", err)
	}
	d := &envResp.Data
	acc := &Access{
		URL: d.AccessURL,
		Extra: map[string]interface{}{
			"environment_id":  d.EnvironmentID,
			"access_type":     d.AccessType,
			"access_ready":    d.AccessReady,
			"remaining_seconds": d.RemainingSeconds,
			"status":          d.Status,
		},
	}
	if host, port, err := parseHostPort(d.AccessURL); err == nil {
		acc.Host = host
		acc.Port = port
	}
	for _, u := range d.AccessURLs {
		ep := EntryPoint{Name: u.Type, Type: u.Type}
		if h, pn, err := parseHostPort(u.URL); err == nil {
			ep.Host = h
			ep.Port = pn
		}
		if u.NCSSL != nil {
			acc.Extra["nc_ssl_"+u.Type] = *u.NCSSL
		}
		acc.EntryPoints = append(acc.EntryPoints, ep)
	}
	return acc, nil
}

// parseHostPort 从 URL 解析 host:port（http://h:p/path、host:port 等）。
func parseHostPort(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, fmt.Errorf("空地址")
	}
	u := raw
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	host, portStr, err := splitURL(u)
	if err != nil {
		return "", 0, err
	}
	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}
	return host, port, nil
}

// splitURL 把 URL 拆为 host 与 port 字符串（处理协议/路径/userinfo/IPv6）。
func splitURL(u string) (string, string, error) {
	idx := strings.Index(u, "://")
	if idx < 0 {
		return "", "", fmt.Errorf("无协议")
	}
	rest := u[idx+3:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		rest = rest[:slash]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if rb := strings.Index(rest, "]"); rb >= 0 {
			host := rest[:rb+1]
			p := ""
			if len(rest) > rb+1 && rest[rb+1] == ':' {
				p = rest[rb+2:]
			}
			return host, p, nil
		}
	}
	if colon := strings.LastIndex(rest, ":"); colon >= 0 {
		return rest[:colon], rest[colon+1:], nil
	}
	return rest, "", nil
}

// DownloadAttachment 下载比赛题附件：files 里的 file_id → 签名 URL → HTTP 下载。
func (p *CTF2Platform) DownloadAttachment(ctx context.Context, challengeID string) ([]string, error) {
	ch, err := p.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	files, _ := ch.Extra["files"].([]map[string]interface{})
	if len(files) == 0 {
		return nil, nil
	}
	base, err := p.challengePath(challengeID)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, f := range files {
		fid, _ := f["file_id"].(string)
		fname, _ := f["file_name"].(string)
		if fid == "" {
			continue
		}
		// 签名 URL
		data, _, err := p.doRequest(ctx, http.MethodGet,
			base+"attachments/"+fid+"/url/?limit=1", nil)
		if err != nil {
			p.Logger.Warn("CTF² 附件签名 URL 失败", zap.String("challenge_id", challengeID), zap.String("file_id", fid), zap.Error(err))
			continue
		}
		var urlResp struct {
			Data struct {
				URL      string `json:"url"`
				FileName string `json:"file_name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &urlResp); err != nil {
			p.Logger.Warn("CTF² 附件签名 URL 解析失败", zap.Error(err))
			continue
		}
		if fname == "" {
			fname = urlResp.Data.FileName
		}
		local, err := p.downloadSigned(ctx, urlResp.Data.URL, fname)
		if err != nil {
			p.Logger.Warn("CTF² 附件下载失败", zap.String("url", truncate(urlResp.Data.URL, 120)), zap.Error(err))
			continue
		}
		paths = append(paths, local)
	}
	return paths, nil
}

// downloadSigned 下载签名 URL 到本地临时目录（文件名清洗防路径穿越）。
func (p *CTF2Platform) downloadSigned(ctx context.Context, rawURL, name string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("空附件 URL")
	}
	dir := filepath.Join(os.TempDir(), "ctf2_attachments")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if name == "" {
		name = "attachment"
	}
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == "/" || name == "" {
		name = "attachment"
	}
	dst := filepath.Join(dir, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("附件下载 HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", err
	}
	return dst, nil
}

// SubmitFlag 提交 flag（confirmation=true 防误交）。choice 题走 Extra。
func (p *CTF2Platform) SubmitFlag(ctx context.Context, challengeID string, flag string) (*SubmitResult, error) {
	path, err := p.challengePath(challengeID)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"flag":         flag,
		"confirmation": true,
	}
	data, _, err := p.doRequest(ctx, http.MethodPost, path+"submit/", body)
	if err != nil {
		return &SubmitResult{RequestFailed: true, Detail: fmt.Sprintf("请求失败: %v", err), Extra: map[string]interface{}{"error": err.Error()}}, nil
	}
	var submitResp struct {
		Data struct {
			Accepted    bool   `json:"accepted"`
			Attempt     int    `json:"attempt"`
			AttemptsLeft int   `json:"attempts_left"`
			EarnedPoints int   `json:"earned_points"`
			IsSolved    bool   `json:"is_solved"`
			Points      int    `json:"points"`
			SubmissionID string `json:"submission_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &submitResp); err != nil {
		return &SubmitResult{RequestFailed: true, Detail: fmt.Sprintf("解析提交响应失败: %v", err)}, nil
	}
	d := &submitResp.Data
	res := &SubmitResult{
		Accepted: d.Accepted,
		Correct:  d.Accepted,
		Detail: fmt.Sprintf("submission_id=%s attempt=%d points=%d",
			d.SubmissionID, d.Attempt, d.Points),
		RemainingAttempts: d.AttemptsLeft,
		Extra: map[string]interface{}{
			"submission_id":  d.SubmissionID,
			"attempt":        d.Attempt,
			"earned_points":  d.EarnedPoints,
			"is_solved":      d.IsSolved,
			"points":         d.Points,
			"attempts_left":  d.AttemptsLeft,
		},
	}
	return res, nil
}

// ResetInstance CTF² 无重置端点（环境只有 start/extend/delete）。返回 no-op 错误提示。
func (p *CTF2Platform) ResetInstance(ctx context.Context, instanceID string) error {
	p.Logger.Warn("CTF² 无 ResetInstance 端点（环境生命周期为 start/extend/delete）；如需重置请 Destroy 后重建",
		zap.String("instance_id", instanceID))
	return nil
}

// DestroyInstance 销毁比赛环境（释放靶机配额）。
func (p *CTF2Platform) DestroyInstance(ctx context.Context, instanceID string) error {
	path, err := p.challengePath(instanceID)
	if err != nil {
		return err
	}
	_, _, err = p.doRequest(ctx, http.MethodDelete, path+"environment/", nil)
	if err != nil {
		return err
	}
	return nil
}

// GetMatchInfo 读取比赛规则/时间窗。
func (p *CTF2Platform) GetMatchInfo(ctx context.Context) (map[string]interface{}, error) {
	if err := p.ensureContext(ctx); err != nil {
		return nil, err
	}
	data, _, err := p.doRequest(ctx, http.MethodGet,
		ctf2AgentBase+"/competitions/"+p.CompetitionID+"/?limit=1", nil)
	if err != nil {
		return nil, err
	}
	var compResp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(data, &compResp); err != nil {
		return nil, fmt.Errorf("解析比赛信息失败: %w", err)
	}
	return compResp.Data, nil
}

// GetOverview 读取 Agent 排行榜与本 Agent 排名。
func (p *CTF2Platform) GetOverview(ctx context.Context) (map[string]interface{}, error) {
	if err := p.ensureContext(ctx); err != nil {
		return nil, err
	}
	data, _, err := p.doRequest(ctx, http.MethodGet,
		ctf2AgentBase+"/competitions/"+p.CompetitionID+"/scoreboard/?limit=100", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("解析排行榜失败: %w", err)
	}
	return resp.Data, nil
}
