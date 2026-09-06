package ctfplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DasCTFPlatform 实现挑战杯决赛官方 AI Agent API 客户端。
//
// 端点映射对齐西湖论剑 ctfplatform/dasctf.py 的 DEFAULT_ENDPOINTS，
// 以 /slab-match/api/v1/agent/ 为前缀。
//
// 鉴权：X-Agent-AccessKey 请求头（环境变量 DASCTF_TOKEN 或 CTF_AGENT_PLATFORM_TOKEN）。
// 所有方法返回类型安全——失败返回零值/默认对象 + error，不 panic。
type DasCTFPlatform struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	Logger     *zap.Logger
	Endpoints  map[string]string
}

// 默认端点映射（对齐官方 AI Agent API）
var defaultEndpoints = map[string]string{
	"match_info":       "/slab-match/api/v1/agent/match/notice/match-info",
	"overview":         "/slab-match/api/v1/agent/answer-panel/overview",
	"challenges":       "/slab-match/api/v1/agent/ctf/exercise-list",
	"challenge_detail": "/slab-match/api/v1/agent/ctf/exercise",
	"build_env":        "/slab-match/api/v1/agent/ctf/build-exercise-env",
	"recover_env":      "/slab-match/api/v1/agent/ctf/recover-exercise-env",
	"submit":           "/slab-match/api/v1/agent/answer-panel/answer",
	"notice_list":      "/slab-match/api/v1/agent/match/notice/now-list",
	"notice_detail":    "/slab-match/api/v1/agent/match/notice/detail",
}

// NewDasCTFPlatform 创建平台客户端。
// base_url 和 token 支持从环境变量 DASCTF_BASE_URL / DASCTF_TOKEN 读取。
func NewDasCTFPlatform(baseURL, token string, logger *zap.Logger) *DasCTFPlatform {
	if baseURL == "" {
		baseURL = os.Getenv("DASCTF_BASE_URL")
	}
	if token == "" {
		token = os.Getenv("DASCTF_TOKEN")
		if token == "" {
			token = os.Getenv("CTF_AGENT_PLATFORM_TOKEN")
		}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	eps := make(map[string]string, len(defaultEndpoints))
	for k, v := range defaultEndpoints {
		eps[k] = v
	}
	return &DasCTFPlatform{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Logger:    logger,
		Endpoints: eps,
	}
}

// ── 底层请求 ──────────────────────────────────────────

func (p *DasCTFPlatform) doRequest(ctx context.Context, method, endpointKey string, body interface{}) ([]byte, int, error) {
	path, ok := p.Endpoints[endpointKey]
	if !ok {
		return nil, 0, fmt.Errorf("未知端点: %s", endpointKey)
	}
	url := p.BaseURL + path

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
	if p.Token != "" {
		req.Header.Set("X-Agent-AccessKey", p.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("读取响应失败: %w", err)
	}
	return data, resp.StatusCode, nil
}

// ── 平台 API 实现 ─────────────────────────────────────

// ListChallenges 拉取题目列表。
func (p *DasCTFPlatform) ListChallenges(ctx context.Context) ([]Challenge, error) {
	data, status, err := p.doRequest(ctx, "GET", "challenges", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("拉取题目列表失败: HTTP %d, body=%s", status, string(data))
	}
	// 解析响应（平台返回格式：{"data": [...], "code": 0}）
	var resp struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("解析题目列表失败: %w", err)
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("平台返回错误: code=%d, msg=%s", resp.Code, resp.Msg)
	}
	// 尝试解析为数组或对象包裹
	var challenges []Challenge
	if err := json.Unmarshal(resp.Data, &challenges); err != nil {
		// 可能是 {"list": [...]} 格式
		var wrapped struct {
			List []Challenge `json:"list"`
		}
		if err2 := json.Unmarshal(resp.Data, &wrapped); err2 != nil {
			return nil, fmt.Errorf("解析题目数据失败: %w (原始: %s)", err, string(resp.Data)[:200])
		}
		challenges = wrapped.List
	}
	p.Logger.Info("拉取题目列表成功", zap.Int("count", len(challenges)))
	return challenges, nil
}

// GetChallenge 获取单题详情。
func (p *DasCTFPlatform) GetChallenge(ctx context.Context, challengeID string) (*Challenge, error) {
	url := p.BaseURL + p.Endpoints["challenge_detail"] + "?exerciseId=" + challengeID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if p.Token != "" {
		req.Header.Set("X-Agent-AccessKey", p.Token)
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取题目详情失败: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取题目详情失败: HTTP %d", resp.StatusCode)
	}
	var result struct {
		Code int       `json:"code"`
		Data Challenge `json:"data"`
		Msg  string    `json:"msg"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("解析题目详情失败: %w", err)
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("平台返回错误: code=%d, msg=%s", result.Code, result.Msg)
	}
	result.Data.ID = challengeID
	return &result.Data, nil
}

// CreateInstance 启动题目环境/容器。
func (p *DasCTFPlatform) CreateInstance(ctx context.Context, challengeID string) (*Instance, error) {
	body := map[string]string{"exerciseId": challengeID}
	data, status, err := p.doRequest(ctx, "POST", "build_env", body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("启动环境失败: HTTP %d, body=%s", status, string(data))
	}
	var resp struct {
		Code int      `json:"code"`
		Data Instance `json:"data"`
		Msg  string   `json:"msg"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("解析实例信息失败: %w", err)
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("平台返回错误: code=%d, msg=%s", resp.Code, resp.Msg)
	}
	p.Logger.Info("环境启动成功", zap.String("instance_id", resp.Data.InstanceID))
	return &resp.Data, nil
}

// GetAccess 获取实例访问信息。
func (p *DasCTFPlatform) GetAccess(ctx context.Context, instanceID string) (*Access, error) {
	// 平台可能在 CreateInstance 返回中已包含访问信息
	// 这里提供独立查询接口（如有需要）
	return &Access{}, nil
}

// DownloadAttachment 下载题目附件。
func (p *DasCTFPlatform) DownloadAttachment(ctx context.Context, challengeID string) ([]string, error) {
	// 附件通常在题目详情中包含下载链接
	p.Logger.Debug("附件下载（待平台 API 确认具体端点）", zap.String("challenge_id", challengeID))
	return nil, nil
}

// SubmitFlag 提交 flag。
func (p *DasCTFPlatform) SubmitFlag(ctx context.Context, challengeID string, flag string) (*SubmitResult, error) {
	body := map[string]string{
		"exerciseId": challengeID,
		"answer":     flag,
	}
	data, status, err := p.doRequest(ctx, "POST", "submit", body)
	if err != nil {
		return &SubmitResult{RequestFailed: true, Detail: err.Error()}, err
	}
	result := &SubmitResult{}
	if status != http.StatusOK {
		result.RequestFailed = true
		result.Detail = fmt.Sprintf("HTTP %d: %s", status, string(data))
		return result, fmt.Errorf("提交失败: HTTP %d", status)
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Correct bool   `json:"correct"`
			Detail  string `json:"detail"`
		} `json:"data"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		result.Detail = fmt.Sprintf("解析失败: %s", string(data)[:200])
		return result, nil
	}
	result.Accepted = resp.Code == 0
	result.Correct = resp.Data.Correct
	result.Detail = resp.Data.Detail
	if result.Detail == "" {
		result.Detail = resp.Msg
	}
	return result, nil
}

// ResetInstance 重置实例环境。
func (p *DasCTFPlatform) ResetInstance(ctx context.Context, instanceID string) error {
	body := map[string]string{"instanceId": instanceID}
	_, status, err := p.doRequest(ctx, "POST", "recover_env", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("重置环境失败: HTTP %d", status)
	}
	return nil
}

// DestroyInstance 销毁实例。
func (p *DasCTFPlatform) DestroyInstance(ctx context.Context, instanceID string) error {
	return p.ResetInstance(ctx, instanceID) // 平台可能用同一接口
}

// GetMatchInfo 获取竞赛规则/状态。
func (p *DasCTFPlatform) GetMatchInfo(ctx context.Context) (map[string]interface{}, error) {
	data, status, err := p.doRequest(ctx, "GET", "match_info", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("获取比赛信息失败: HTTP %d", status)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetOverview 获取得分排名。
func (p *DasCTFPlatform) GetOverview(ctx context.Context) (map[string]interface{}, error) {
	data, status, err := p.doRequest(ctx, "GET", "overview", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("获取排名失败: HTTP %d", status)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Ensure DasCTFPlatform implements PlatformAPI
var _ PlatformAPI = (*DasCTFPlatform)(nil)
