// Package ctfplatform 实现 CTF 竞赛平台对接（拉题/启动环境/提交flag/回收）。
//
// 设计参考：西湖论剑 CTF-Agent 的 ctfplatform/ Python 实现，
// 对齐挑战杯决赛官方 AI Agent API（/slab-match/api/v1/agent/ 端点族）。
//
// 架构：PlatformAPI 接口 → DasCTF 实现 → Poller 轮询调度 → Solver 求解。
package ctfplatform

import (
	"context"
	"time"
)

// Challenge 表示一道 CTF 题目。
type Challenge struct {
	ID string `json:"id"`
	// SolvedBy 解出归因（测量口径基建，立尺 2026-10-25）：由求解链命中层写入
	// "presolve" / "python_skill" / "llm" / ""（未解出）。序列化忽略——它不是
	// 题目属性，是本次求解的 provenance，经 PollRecord.SolvedBy 对外报告。
	// 🔴 口径铁律：presolve/python_skill 命中不得计入 LLM 解出（A 库 E3 报告
	// 实证：无归因字段时 14/15 presolve 直出曾整体冒充链路能力）。
	SolvedBy      string `json:"-"`
	Title         string `json:"title"`
	Category      string `json:"category"` // web / crypto / misc / reverse / pwn
	Description   string `json:"description"`
	FlagFormat    string `json:"flag_format"` // 如 "flag{[^}]+}"
	Score         int    `json:"score"`
	HasInstance   bool   `json:"has_instance"`   // 是否需要启动容器
	HasAttachment bool   `json:"has_attachment"` // 是否有附件
	// AttachmentURLs 由 parseChallenge 从题目详情提取的附件下载 URL（供 DownloadAttachment 使用）。
	// 平台把附件 URL 嵌在详情 JSON 的 attachment/attachments/file 字段里（DASCTF 形态），
	// 不另设独立下载 API，故先提取再 HTTP GET 落盘。
	AttachmentURLs []string               `json:"attachment_urls,omitempty"`
	Difficulty     string                 `json:"difficulty"` // VERY_EASY / EASY / MEDIUM / HARD
	// FlagSHA256 题目真值（flag 或 flag 内文的 SHA-256 小写十六进制），**仅当确实掌握
	// 答案时**才填（内部题库 / 评测 / 平台回传）。
	// 🔴 真实比赛拿不到答案 → 恒为空 → flagverify 走 Unknown 分支 → 行为与未接线时
	// 完全一致（不判对也不判错，交回平台判定）。**禁止为了"能验证"去猜真值**：
	// 2026-09-19 事故的通用形态就是「验证器的真值来源 ≠ 被验证对象的真值来源」，
	// 拿退役题库的真值去裁今天的题，会把正确 flag 一律判成幻觉（当日 1/10 是冤案）。
	FlagSHA256     string                 `json:"flag_sha256,omitempty"`
	Extra          map[string]interface{} `json:"extra,omitempty"`
}

// Instance 表示一个启动的题目环境实例。
type Instance struct {
	InstanceID string                 `json:"instance_id"`
	Status     string                 `json:"status"` // starting / running / error / stopped
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

// Access 表示实例的访问信息（IP/端口/凭证）。
type Access struct {
	Host        string                 `json:"host"`
	Port        int                    `json:"port"`
	Username    string                 `json:"username"`
	Password    string                 `json:"password"`
	URL         string                 `json:"url"` // 若平台给的是 URL
	EntryPoints []EntryPoint           `json:"entry_points,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// EntryPoint 表示一个访问入口（多端口/多服务场景）。
type EntryPoint struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Type string `json:"type"` // web / ssh / mysql / redis / ...
}

// SubmitResult 表示提交 flag 的结果。
type SubmitResult struct {
	Accepted          bool   `json:"accepted"`           // 平台是否接受
	Correct           bool   `json:"correct"`            // flag 是否正确
	Detail            string `json:"detail"`             // 平台返回详情
	RemainingAttempts int    `json:"remaining_attempts"` // 剩余提交次数
	RequestFailed     bool   `json:"request_failed"`     // 请求层是否失败（网络/HTTP/鉴权）
	// 与 Correct=false 区分：请求失败时 flag 可能是对的
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// PollRecord 表示单题的轮询处理记录（审计可追溯）。
type PollRecord struct {
	ChallengeID     string    `json:"challenge_id"`
	Title           string    `json:"title"`
	Category        string    `json:"category"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	Flag            string    `json:"flag"`
	Submitted       bool      `json:"submitted"`
	Accepted        bool      `json:"accepted"`
	Detail          string    `json:"detail"`
	Error           string    `json:"error"`
	ErrorClass      string    `json:"error_class,omitempty"` // supervision.go 单一真值分类（truncated/non-retryable 口径）
	SolvedBy        string    `json:"solved_by,omitempty"`   // 解出归因：presolve / python_skill / llm（口径铁律见 Challenge.SolvedBy）
	ExtraCandidates []string  `json:"extra_candidates,omitempty"`
}

// PlatformAPI 定义 CTF 平台的完整生命周期接口。
// 决赛当天只需实现一个具体 struct（如 DasCTFPlatform）。
type PlatformAPI interface {
	// ListChallenges 拉取题目列表。
	ListChallenges(ctx context.Context) ([]Challenge, error)

	// GetChallenge 获取单题完整定义（含描述/附件信息）。
	GetChallenge(ctx context.Context, challengeID string) (*Challenge, error)

	// CreateInstance 启动题目环境/容器。
	CreateInstance(ctx context.Context, challengeID string) (*Instance, error)

	// GetAccess 获取实例访问信息（地址/端口/账号）。
	GetAccess(ctx context.Context, instanceID string) (*Access, error)

	// DownloadAttachment 下载题目附件，返回本地路径列表。
	DownloadAttachment(ctx context.Context, challengeID string) ([]string, error)

	// SubmitFlag 提交 flag。
	SubmitFlag(ctx context.Context, challengeID string, flag string) (*SubmitResult, error)

	// ResetInstance 重置实例环境。
	ResetInstance(ctx context.Context, instanceID string) error

	// DestroyInstance 销毁实例（释放资源）。
	DestroyInstance(ctx context.Context, instanceID string) error

	// GetMatchInfo 获取竞赛规则/状态。
	GetMatchInfo(ctx context.Context) (map[string]interface{}, error)

	// GetOverview 获取得分排名。
	GetOverview(ctx context.Context) (map[string]interface{}, error)
}
