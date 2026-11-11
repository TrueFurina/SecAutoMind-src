// Package runnerl3 —— SecAutoMind runner Layer 3: Eino ChatModel 独立调用 + 工具绑定。
//
// 本包从 cmd/runner 抽出，使 Layer 3 求解逻辑可被其他入口（如 cmd/evalharness
// 的离线真机评测）复用，而不必把整个 runner 作为 main 包依赖。
//
// 设计原则：
//   1. 不启动 agent/db/mcp —— 纯 ChatModel.Generate() + 手动 tool calling 循环
//   2. 两个工具（最小集）：
//      - execute_python: 桥接 Layer 2 Python skill（angr/pwntools 真跑）
//      - read_attachment: 下载 CTF 附件到临时目录，返回 strings 输出
//   3. 安全硬限：
//      - 每题最多 12 次工具调用 + 12 轮 LLM 对话（防无限循环）
//        （2026-10-25 听风第二刀：3/5 → 12/12 对齐 A 库步数预算——原 3 轮
//        预算下监督规则⑥（零候选需 used>=5）结构上不可触发；预算放大后
//        由逐轮 ReflectSupervision 守护尾部：零候选 60% 即 ABANDON 收口）
//      - execute_python subprocess 超时 120s
//      - read_attachment 下载超时 30s
//      - 总 LLM 调用超时由 ctx + RUNNER_LLM_TIMEOUT_SEC 双重控制
//   4. 依赖门控：RUNNER_LLM_FALLBACK=true 且有 API key 才启用
//
// Env 变量约定（全部 runner 专属）：
//   RUNNER_LLM_FALLBACK     默认 false，显式 true 才启用
//   RUNNER_LLM_API_KEY      API key（必需，缺则跳过）
//   RUNNER_LLM_BASE_URL     默认 https://api.deepseek.com/v1
//   RUNNER_LLM_MODEL        默认 deepseek-reasoner
//   RUNNER_LLM_TIMEOUT_SEC  默认 300（**整题**总预算，不是单次请求超时，见下方事故说明）
//   RUNNER_LLM_MAX_TOKENS   默认 8000（推理 token 与正文共用预算，见 WithMaxTokens 处的出处）
//   RUNNER_LLM_MAX_TOOL_CALLS 默认 12（每题工具调用上限）
//   RUNNER_LLM_MAX_ROUNDS   默认 12（LLM 对话轮数上限 = 监督步数预算）
//   RUNNER_LLM_FAILOVER     默认 true —— 通道 failover（P0-4）；false = 退回单通道
//   RUNNER_LLM_FAILOVER_CHANNELS     逗号分隔通道 ID 顺序；空 = 内置优先级（见 llmchannel）
//   RUNNER_LLM_FAILOVER_COOLDOWN_SEC 单通道失败冷却秒数，默认 300
package runnerl3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
	"secautomind-ai/internal/llmchannel"
)

// ErrLLMUnavailable 表示 LLM 所有通道均不可用（配额耗尽/网络故障），
// 与「模型跑了但没解出」不同：这是基础设施失效，结果应标 skipped、排除出 KPI 分母。
var ErrLLMUnavailable = errors.New("LLM 通道全部不可用（配额耗尽/网络故障），非能力问题")

// SkillRunner 是 execute_python 工具的依赖抽象，使本包不耦合 cmd/runner 的
// pySkillRunner 具体类型。cmd/runner 的 *pySkillRunner 实现 RunSkill 后即满足。
type SkillRunner interface {
	RunSkill(ctx context.Context, skillName string, ch *ctfplatform.Challenge) ([]string, bool)
}

// RichSkillRunner 是 SkillRunner 的可选富结果扩展（P0-1 ctf_sage 模板接入，2026-10-25）。
// 存在原因：数学模板（t1-t6）的产出是中间量（小根/私钥/明文），flag 契约会把它们
// 丢掉，LLM 拿不到任何可用信息；且 execute_python 工具描述一直承诺 params 可传、
// 实现却忽略（LLM 无法向 skill 传数学参数）。本接口同时补这两个洞：
//   - extra：LLM 经工具参数 params 传入的数学参数（n/e/c/f_coeffs/sigs...）；
//   - 返回完整结果文本（截断后进 ToolMessage），由 LLM 决定怎么用。
// 实现方（cmd/runner 的 *pySkillRunner）可选实现；未实现时 execute_python 自动
// 回落到既有 flag 契约——现有 fake 与生产行为零变化。
type RichSkillRunner interface {
	RunSkillRich(ctx context.Context, skillName string, ch *ctfplatform.Challenge, extra map[string]any) (string, bool)
}

// SkillCatalogProvider 由 bridge 可选实现：把**真实** skill 清单交给 LLM。
//
// 存在原因（2026-11-01 P0 实锤，crypto 6 题 A/B 真机对比得出）：
// execute_python 的 Desc 里原有一张手写的 skill 名清单，与 bridge 的实际
// skillCatalog 早已脱节 —— 列出的 16 个名字里 15 个不存在
// （factor_integer / rsa_wiener_attack / rsa_hastad_attack / xor_bruteforce /
//  angr_decompile / angr_symbolic / ghidra_analyze / objdump_disasm /
//  pwn_checksec / pwn_ret2libc / pwn_ret2win / pwn_canary_bruteforce /
//  zip_crack / image_steg / pcap_analyze），只有 pwn_ret2dlresolve 是真的。
// 模型据描述调 factor_integer ⇒ import 失败 ⇒ 实测 6 题里 execute_python 只被
// 调用 1 次且用的就是那个幻觉名，79 个真 skill 全程零使用。
//
// 结论：清单必须从 catalog 现取（单一真值源），禁止在 Desc 里手写。
type SkillCatalogProvider interface {
	SkillCatalog() map[string][]string
}

// SkillContractProvider 是**可选**能力：skill 名 → 该 skill 从 params 里读取的键。
//
// 存在原因（2026-11-01 第二层缺口，真机实测）：第一层修好之后模型确实开始用
// 真名调 skill 了 —— 但它传的是 {"a1": [], "a2": [], "b": [], "c": []}，全是空数组。
// 名字对了、参数全错，产出依然是零。只列名字等于让模型对着函数签名盲调。
//
// 不实现该接口 → Desc 只列名字（= 修复前行为），不报错。
type SkillContractProvider interface {
	SkillContracts() map[string]string
}

// LLMFallback 是 Layer 3（真 token 成本）的求解器。
type LLMFallback struct {
	// model 放宽为接口（BaseChatModel = BaseModel[*schema.Message]）：生产注入
	// *einoopenai.ChatModel，测试可注入 fake（监督逐轮反思需要可脚本化模型，
	// 原具体类型不可 fake）。
	model    model.BaseChatModel
	pyBridge SkillRunner
	logger   *zap.Logger
	Enabled  bool

	maxToolCalls int // 每题工具调用上限
	maxRounds    int // LLM 对话轮数上限（= 监督步数预算，A 库口径 12）

	// outcome 记录最近一次 Solve 的收口归因（零值可用，不需要在 New 里初始化）。
	// 为什么放在这里：报告里的 cand=0 同时代表"没答"和"给了假答案"，两者处置
	// 方向相反。归因口径唯一的真值来源是 outcome.go 的 classifyMiss。
	outcome outcomeBox
}

// NewLLMFallback 从 env 变量构造 LLM fallback。缺任何必需项返回 disabled 实例。
// pyBridge 用于 execute_python 工具，nil 时工具自动降级。
func NewLLMFallback(ctx context.Context, logger *zap.Logger, pyBridge SkillRunner) *LLMFallback {
	if !envBool("RUNNER_LLM_FALLBACK", false) {
		logger.Info("LLM fallback 未启用（RUNNER_LLM_FALLBACK 未设或非 true）")
		return &LLMFallback{logger: logger, pyBridge: pyBridge}
	}

	apiKey := strings.TrimSpace(os.Getenv("RUNNER_LLM_API_KEY"))
	if apiKey == "" {
		logger.Warn("LLM fallback 启用但 RUNNER_LLM_API_KEY 未设 → 跳过")
		return &LLMFallback{logger: logger, pyBridge: pyBridge}
	}

	baseURL := envOrDefault("RUNNER_LLM_BASE_URL", "https://api.deepseek.com/v1")
	modelName := envOrDefault("RUNNER_LLM_MODEL", "deepseek-reasoner")

	var m model.BaseChatModel
	var err error
	var ids []string

	if envBool("RUNNER_LLM_FAILOVER", true) {
		// P0-4：主通道 + 已验证免费通道按优先级 failover（单通道抖动不再整条失能）。
		m, ids, err = buildFailoverModel(ctx, llmchannel.Channel{
			ID: "primary", BaseURL: baseURL, Model: modelName, APIKey: apiKey,
		}, logger)
		if err != nil {
			logger.Warn("LLM failover 构造失败 → 退回单通道", zap.Error(err))
			m, err = einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
				APIKey:  apiKey,
				BaseURL: baseURL,
				Model:   modelName,
			})
			if err != nil {
				logger.Warn("LLM fallback 初始化失败 → 跳过", zap.Error(err),
					zap.String("base_url", baseURL), zap.String("model", modelName))
				return &LLMFallback{logger: logger, pyBridge: pyBridge}
			}
			ids = []string{"primary"}
		}
	} else {
		// 旧路径：单通道（RUNNER_LLM_FAILOVER=false 显式退回）
		m, err = einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
			APIKey:  apiKey,
			BaseURL: baseURL,
			Model:   modelName,
		})
		if err != nil {
			logger.Warn("LLM fallback 初始化失败 → 跳过", zap.Error(err),
				zap.String("base_url", baseURL), zap.String("model", modelName))
			return &LLMFallback{logger: logger, pyBridge: pyBridge}
		}
	}

	ff := &LLMFallback{
		model:        m,
		pyBridge:     pyBridge,
		logger:       logger,
		Enabled:      true,
		maxToolCalls: envInt("RUNNER_LLM_MAX_TOOL_CALLS", 12),
		maxRounds:    envInt("RUNNER_LLM_MAX_ROUNDS", 12),
	}

	logger.Info("LLM fallback 就绪（含工具绑定）",
		zap.String("base_url", baseURL),
		zap.String("model", modelName),
		zap.Strings("failover_channels", ids),
		zap.Int("max_tool_calls", ff.maxToolCalls),
		zap.Int("max_rounds", ff.maxRounds),
		zap.Bool("execute_python", pyBridge != nil))

	return ff
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	return v == "true" || v == "1" || v == "yes"
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

// Solve 把题干喂给 LLM（带工具绑定），让它输出 flag 候选列表。
// 手动 tool calling 循环：LLM → 检查 ToolCalls → 执行 → 追加 ToolMessage → 再 Generate。
// 硬限：maxToolCalls 次工具调用 + maxRounds 轮对话，超过就停。
func (f *LLMFallback) Solve(ctx context.Context, ch *ctfplatform.Challenge) (flags []string, err error) {
	if !f.Enabled || f.model == nil {
		// 归因要覆盖所有退出路径，否则"禁用"会被误读成"零候选=模型不行"。
		f.outcome.set(SolveOutcome{Reason: ReasonDisabled})
		return nil, nil
	}

	// 🔴 这是**整题**总预算，不是单次请求超时 —— ctx 建在 round 循环之外，
	// 到点后后续每一轮都会 context deadline exceeded → Solve 直接 return nil,nil → 记 MISS。
	//
	// 默认值 60 → 300 的实测依据（2026-10-29 服务器真机，step-5-preview / TokenHub）：
	//   - 设 120s 时，YCB 两题**精确停在 120.0s**（round 3/4 起即 deadline），
	//     real_benchmark 里 buuctf_upload_basic 同样精确 120.0s；
	//   - 放开到 600s 后，12 题全部**自然结束**，耗时 7~63s —— 说明 60s 连一轮
	//     带工具的长链推理都装不下，是纯人为截断，不是模型慢。
	//   ⇒ 旧默认 60s 会把「正在解」的题系统地判成「没解出」，直接压真实解题数。
	// 300s 的取值：覆盖实测绝大多数题的自然耗时（<70s），又不至于让单题无限挂住；
	// 需要更长链条的题仍可用环境变量显式抬高（如 ycb12085_vvmm 用 900/1800）。
	timeout := time.Duration(envInt("RUNNER_LLM_TIMEOUT_SEC", defaultWholeSolveTimeoutSec)) * time.Second
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// P0-3：本轮的环境事实源（只由工具成功返回写入，模型复述不算）
	facts := newFactLedger()

	// P1-2：本轮的有状态 Python 会话（惰性启动；Solve 返回即销毁，题目间零状态泄漏）
	sess := newPySessionMgr(f.logger)
	defer sess.Close()

	// 准备工具定义（动态根据 pyBridge 可用性）
	tools := f.buildToolDefs()

	systemPrompt := f.buildSystemPrompt()
	userContent := f.buildUserPrompt(ch)

	msgs := []*schema.Message{
		schema.SystemMessage(systemPrompt),
		schema.UserMessage(userContent),
	}

	toolCallCount := 0
	// truncated 统计**因输出预算耗尽被截断**的轮次数（finish_reason=="length"）。
	//
	// 为什么必须单列：推理模型的 reasoning_content 与正文共用 max_tokens，
	// 预算不足时模型会"想了一半被掐断"，content 为空或半截 JSON。这种题的
	// 报告表现是 cand=0 / 半截答案，与"模型不会"完全同形 —— 但修法相反
	// （抬预算 vs 补能力）。不记这个字段，等于把预算缺陷算进能力分母。
	// 2026-11-01 前全部历史日志都没有 finish_reason 记录，故此前的
	// "零候选"归因都不排除截断污染（见 docs/evidence/复盘二）。
	truncated := 0
	var supSteps []ctfplatform.SupervisionStep // 监督进展信号（逐轮累积）
	candSeen := 0                             // 工具输出中实际提取到的候选 flag 数（不可自欺硬信号）
	// droppedSet 记录"模型产出过、但最终没进提交链"的候选（去重）。
	//
	// 两类来源，都必须计：
	//  ① 反幻觉闸门当场打回（终局文本里的候选）；
	//  ② 带工具调用的轮次里，模型自己的正文 / 工具参数中的候选 —— 候选池
	//     只吃**工具输出**（下面的 obs 扫描块在 ToolCalls 分支内），所以模型
	//     自己写的 flag 从来不参与判分。Primes 的 CTF{YkDOLI...} 就是这一类。
	//
	// 为什么要计：不计的话"模型编了个假答案"会被归因成"零候选"，而这两者
	// 要修的东西正好相反（补幻觉抑制 vs 补能力）。本字段只做可见化，
	// **不改变任何提交语义**。
	droppedSet := make(map[string]struct{})
	// noteDropped 按**去重后**计数：同一个假 flag 往往在多个轮次反复出现
	// （2026-11-01 实测 Primes 同一串出现 8 次）。按出现次数记会让人误以为
	// "有 8 个不同候选"，所以这里与 bestCandSeen 同口径 —— 只认不同值。
	noteDropped := func(vals []string) {
		for _, v := range vals {
			if v != "" {
				droppedSet[v] = struct{}{}
			}
		}
	}
	var bestCandidates []string                // 跨轮累积的候选（含工具返回里的 flag，防御"模型算出但没停手"漏抓）
	bestCandSeen := make(map[string]bool)
	var conf float64                          // 模型自评信心（听风第三刀）；nil 语义 = 中性 0.5
	haveConf := false                         // 是否解析到过自评信心（没解析到 = 无信号）

	// maxOutTokens 是每次生成请求的输出上限，**唯一事实源**。
	//
	// 此前默认值 4096 在三处各写一遍（注释写 2048、两处 envInt 写 4096），
	// 注释与实现早已漂移 —— 同源项目把这类"同一常量多处硬编码"列为
	// 「清单只允许有一处事实源」的违反项，本条即按该纪律收敛。
	// 取值依据见下面 WithMaxTokens 处的出处说明。
	maxOutTokens := envInt("RUNNER_LLM_MAX_TOKENS", 8000)
	tokenBudget := f.maxRounds * maxOutTokens
	usedTokens := 0 // 累计 token 用量（听风第四刀：喂监督 TokenRatio，走真实预算口径）

	// 收口归因（2026-11-01）：Solve 有 8 个以上 return 点，逐点手写必然漏，
	// 且以后新增 return 还会继续漏 —— defer 是唯一不随 return 点增加而失效的写法。
	// 读命名返回值 flags/err 才能知道"最终交没交出东西"。
	defer func() {
		f.recordOutcome(err, len(flags), solveTally{
			CandSeen:   candSeen,
			Distinct:   len(bestCandidates),
			Suppressed: len(droppedSet),
			ToolCalls:  toolCallCount,
			Truncated:  truncated,
		})
	}()

	for round := 0; round < f.maxRounds; round++ {
		opts := []model.Option{}
		if len(tools) > 0 {
			opts = append(opts, model.WithTools(tools))
		}
		// 推理模型（deepseek-reasoner / deepseek-v4-* 等）先把额度花在
		// reasoning_content 上，**推理 token 与正文共用同一个 max_tokens 预算**。
		// 预算偏小的后果不是"答案差一点"，而是 content 为空或只剩半截 JSON
		// —— 在报告里与"模型没答"完全同形，无法区分。
		//
		// 默认值 8000 的出处（非拍脑袋）：同源项目 Security-Agent 在
		// `ai/client.py::DEFAULT_MAX_OUTPUT_TOKENS` 上真机踩过这一族，
		// 其注释原文「预算偏小时推理尚未结束正文已被截断：content 为空或只剩
		// 半截 JSON，调用方随即静默回退规则引擎——表面『已接入真 LLM』，
		// 实际 AI 未生效」，故对输出预算设 8000 下限。max_tokens 是上限、
		// 按实际生成计费，调高不产生额外成本。
		opts = append(opts, model.WithMaxTokens(maxOutTokens))

		resp, err := f.model.Generate(callCtx, msgs, opts...)
		if err != nil {
			if callCtx.Err() != nil {
				// 调用方整题预算/超时耗尽：模型确实在跑、只是没在预算内产出 → 合法 miss（仍计入分母）。
				f.logger.Warn("LLM fallback 因预算/超时中断（记合法 miss）",
					zap.String("challenge", ch.Title),
					zap.Int("round", round), zap.Error(callCtx.Err()))
				return nil, nil
			}
			// 所有通道都不可用（配额耗尽/网络故障）：基础设施失效，非能力问题 → 标 skipped（排除分母）。
			f.logger.Error("LLM fallback 所有通道不可用（基础设施失效，非能力问题）",
				zap.String("challenge", ch.Title),
				zap.Int("round", round), zap.Error(err))
			return nil, ErrLLMUnavailable
		}

		if resp == nil {
			return nil, nil
		}

		// token 用量采集（听风第四刀）：喂给监督的 TokenRatio，让规则①走真实预算口径。
		// 仅在确有用量时累加；模型不报用量则 usedTokens 恒 0 → TokenRatio 不设置 →
		// 规则⑥ 回落步数口径（nil 分支），避免 nil→0.0 误关 ⑥ 的 token 双口径闸。
		if resp.ResponseMeta != nil && resp.ResponseMeta.Usage != nil {
			usedTokens += resp.ResponseMeta.Usage.TotalTokens
		}

		// 空响应分级诊断（2026-11-01）：推理 token 与正文共用 max_tokens 预算，
		// 预算耗尽时正文可能为空或只剩半截 JSON。
		//
		// 此前整个仓库没有任何一处读 finish_reason / reasoning_content ⇒
		// 「被预算截断」与「模型真的没答」在报告里完全同形，且前者会被算进
		// 能力分母。这里只做**可见化**：WARN 留痕 + 计数进收口归因，
		// 不改变解题语义。
		//
		// 分两类而非一类（分类依据取自 Security-Agent 的
		// `ai/client.py::_log_empty_response`，它在真机上区分过这两条）：
		//   ① finish_reason=="length"  预算确实耗尽；
		//   ② 正文空但 reasoning 非空 预算被推理吃掉，正文没机会写出来
		//      —— 这一类的 finish_reason 可能不是 length，只看 ① 会漏。
		//
		// ⚠️ ② 必须排除「有 ToolCalls」：OpenAI 格式下模型调工具时 content
		// 本来就为空，那是正常运行路径，不是截断。不排除会把每轮工具调用
		// 都误计成截断，让这个信号彻底失去意义。
		if resp.ResponseMeta != nil {
			fr := strings.TrimSpace(resp.ResponseMeta.FinishReason)
			reasoningLen := len(resp.ReasoningContent)
			reasoningTokens := 0
			if resp.ResponseMeta.Usage != nil {
				reasoningTokens = resp.ResponseMeta.Usage.CompletionTokensDetails.ReasoningTokens
			}
			switch {
			case fr == "length":
				truncated++
				f.logger.Warn("LLM 输出被预算截断（finish_reason=length），本轮 content 可能为空或半截",
					zap.String("challenge", ch.Title),
					zap.Int("round", round),
					zap.Int("max_tokens", maxOutTokens),
					zap.Int("content_len", len(resp.Content)),
					zap.Int("reasoning_len", reasoningLen),
					zap.Int("reasoning_tokens", reasoningTokens),
					zap.Int("tool_calls", len(resp.ToolCalls)))
			case resp.Content == "" && reasoningLen > 0 && len(resp.ToolCalls) == 0:
				truncated++
				f.logger.Warn("LLM 只返回 reasoning、正文为空（推理吃掉输出预算）",
					zap.String("challenge", ch.Title),
					zap.Int("round", round),
					zap.String("finish_reason", fr),
					zap.Int("max_tokens", maxOutTokens),
					zap.Int("reasoning_len", reasoningLen),
					zap.Int("reasoning_tokens", reasoningTokens))
			}
		}

		// 自评信心（听风第三刀）：按契约解析 CONFIDENCE 行；缺失保持上次值
		// （首次缺失 = nil → 中性 0.5，不伪造）。
		if c, ok := parseConfidence(resp.Content); ok {
			conf = c
			haveConf = true
		}

		// 检查工具调用
		if len(resp.ToolCalls) > 0 {
			msgs = append(msgs, resp) // 助手消息（含 ToolCalls）

			roundObs := &strings.Builder{}
			callsThisRound := 0
			allErr := true // 一轮内所有调用都是错误才算错误步（混合=有实质进展）
			for _, tc := range resp.ToolCalls {
				toolCallCount++
				if toolCallCount > f.maxToolCalls {
					f.logger.Warn("LLM 工具调用超上限，截断",
						zap.Int("limit", f.maxToolCalls),
						zap.String("challenge", ch.Title))
					break
				}

				// 执行工具
				result := f.executeTool(callCtx, tc, ch, facts, sess)

				// 归因可见化：模型把 flag 塞进工具参数（"拿这个去验一下"）也算它
				// 产出过候选，但这类候选从不参与判分。只记账，不影响任何行为。
				noteDropped(extractFlagCandidates(tc.Function.Arguments))

				// 可观测性（2026-10-29）：工具执行全过程必须留痕。
				// 踩坑背景：练习场 smoke 报 0/5，日志里只有「nflags=0」，完全看不出
				// 模型调了哪些工具、工具为什么失败、模型在想什么，只能盲改。
				// 评测链路的每一步都要能事后复盘，否则「排障」就退化成「猜」。
				f.logger.Debug("工具执行",
					zap.String("challenge", ch.Title),
					zap.Int("round", round),
					zap.String("tool", tc.Function.Name),
					zap.String("args", truncate(tc.Function.Arguments, 300)),
					zap.Bool("is_error", isToolError(result)),
					zap.String("result", truncate(result, 600)))

				roundObs.WriteString(result)
				roundObs.WriteString("\n")
				if !isToolError(result) {
					allErr = false
				}
				callsThisRound++
				msgs = append(msgs, schema.ToolMessage(result, tc.ID))
			}
			// 助手本轮的推理文本（有工具调用时容易被忽略，但是判断
			// 「模型在干嘛」的唯一直接证据，必须留痕）。
			if c := strings.TrimSpace(resp.Content); c != "" {
				// 归因可见化：带工具调用的轮次里，模型正文中的候选同样从不进
				// 候选池（候选池只吃工具输出）。Primes 的假 flag 就出在这类地方。
				noteDropped(extractFlagCandidates(c))
				f.logger.Debug("LLM 推理文本",
					zap.String("challenge", ch.Title),
					zap.Int("round", round),
					zap.String("content", truncate(c, 400)))
			}

			if toolCallCount > f.maxToolCalls {
				break
			}

		// ── 监督反思（逐轮真信号，听风 2026-10-25 第二/三/四刀）──────
		// 预算=轮数；候选=工具输出实际提取数（硬信号，累积）；信心=模型
		// 自评（缺失=中性 0.5）；进展口径诚实化：整轮全是错误调用才算
		// 错误步，不再「非空=有进展」。
		// 规则②（低信心+连续无进展→SWITCH）由此可达；规则① 经第四刀走 token 口径
		// 后，在「token 先耗尽、步数未到 85%」的零候选场景抢在 ⑥ 前收口（不再被遮蔽）。
		obs := roundObs.String()
		candSeen += len(extractFlagCandidates(obs))
		// 防御：工具返回里若含 flag（如 python print(flag)），跨轮累积，避免"模型算出但没停手"被漏抓
		for _, fc := range extractFlagCandidates(obs) {
			if !bestCandSeen[fc] {
				bestCandSeen[fc] = true
				bestCandidates = append(bestCandidates, fc)
			}
		}
		// 防御②：模型算对但没包裹 flag{} —— 常产出"大整数 / 字节序列"形式的答案
		// （如 DAC 网表把 flag 二进制位重建为巨整数、或 reverse 题打印 flag 字节序列）。
		// 归一化为 dice{...} 候选，交由真 submit 校验（isCorrect 兜底，错候选只算一次 miss）。
		for _, rc := range extractRawAnswerCandidates(obs) {
			if !bestCandSeen[rc] {
				bestCandSeen[rc] = true
				bestCandidates = append(bestCandidates, rc)
			}
		}
		step := ctfplatform.SupervisionStep{Observation: truncate(obs, 200)}
		if callsThisRound > 0 && allErr {
			step.ErrCategory = "tool_error"
		}
		supSteps = append(supSteps, step)
		confArg := (*float64)(nil)
		if haveConf {
			confArg = &conf // 至少解析到一次自评信心才传入；否则诚实保持中性
		}
		st := ctfplatform.SupervisionState{
			BudgetTotal: f.maxRounds, BudgetUsed: round + 1,
			Candidates: &candSeen, Challenge: ch.Title,
		}
		if tokenBudget > 0 && usedTokens > 0 {
			tr := float64(usedTokens) / float64(tokenBudget)
			st.TokenRatio = &tr
		}
		if dec := ctfplatform.ReflectSupervision(st, supSteps, confArg); dec.Decision == ctfplatform.DecisionAbandon {
				f.logger.Info("监督 ABANDON：LLM 循环提前收口（省剩余轮次 token）",
					zap.String("challenge", ch.Title),
					zap.Int("round_used", round+1), zap.Int("budget", f.maxRounds),
					zap.Int("candidates_seen", candSeen),
					zap.Float64("confidence", conf),
					zap.String("reason", dec.Reason))
				return nil, nil
			} else if dec.Decision == ctfplatform.DecisionSwitch {
				f.logger.Info("监督 SWITCH：建议换策略（暂无备选策略面，留痕）",
					zap.String("challenge", ch.Title),
					zap.Float64("confidence", conf),
					zap.String("reason", dec.Reason))
			}

			// 继续下一轮（工具结果已经追加）
			continue
		}

		// 无工具调用 → LLM 直接输出文本
		if len(resp.Content) == 0 {
			return nil, nil
		}

		raw := strings.TrimSpace(resp.Content)
		if strings.Contains(raw, "NO_SOLUTION") {
			return nil, nil
		}

		candidates := extractFlagCandidates(raw)
		if len(candidates) == 0 {
			f.logger.Debug("LLM 输出里没找到 flag 格式",
				zap.String("challenge", ch.Title),
				zap.String("raw", truncate(raw, 200)))
			return nil, nil
		}

		// P0-3 ②：反幻觉闸门 —— 声称访问过某文件却没有对应工具记录 → 打回。
		// 为什么必须打回：D-CIPHER VI-B 日志显示「幻觉文件/函数/服务端」是工程失败主因；
		// 让幻觉 flag 进入提交链，等于把一次误判记成得分（还会污染后续统计）。
		if unbacked := extractUnbackedFileClaims(raw, facts); len(unbacked) > 0 {
			// 归因记账：这批候选确实存在过、只是被判为不可信。不计入则会被
			// 归因成"零候选"，把"该补幻觉抑制"误读成"该补能力"。
			noteDropped(candidates)
			f.logger.Warn("P0-3 反幻觉：LLM 声称的文件无工具记录 → 打回（不提交）",
				zap.String("challenge", ch.Title),
				zap.Strings("unbacked_paths", unbacked),
				zap.Int("facts_recorded", facts.count()),
				zap.Int("suppressed_candidates", len(candidates)),
				zap.String("raw", truncate(raw, 200)))
			return nil, nil
		}

		f.logger.Info("Layer 3 LLM fallback 命中",
			zap.String("challenge", ch.Title),
			zap.String("category", ch.Category),
			zap.Int("tool_calls_used", toolCallCount),
			zap.Strings("candidates", candidates))

		return candidates, nil
	}

	f.logger.Debug("LLM fallback 达到轮数上限",
		zap.String("challenge", ch.Title),
		zap.Int("rounds", f.maxRounds),
		zap.Int("tool_calls", toolCallCount))
	// 轮数耗尽：若跨轮曾捕获到候选（含工具返回里的 flag），best-effort 返回，
	// 交由上层真 submit 校验（isCorrect 兜底，错候选只算一次 miss）。
	//
	// ⚠️ 口径开关（2026-11-01）：该行为**默认关闭**，须 RUNNER_LLM_BEST_EFFORT=true 显式开启。
	// 理由：这是"模型自己没收口、我们替它把中途出现过的候选当答案交上去"，属于**放宽判分口径**，
	// 而 KPI 是「LLM 真题解出数」——默认开启会让一条半成品答案在统计上与真命中同列。
	// 交由用户/上层显式选择：要 recall 就开，要干净口径就保持默认。
	// 关闭时恢复既有的提交语义：轮数耗尽且无终局命中 ⇒ nil（既有 llm_solver_test.go 锁死）。
	if envBool("RUNNER_LLM_BEST_EFFORT", false) && len(bestCandidates) > 0 {
		f.logger.Info("LLM fallback 达到轮数上限，返回 best-effort 候选（跨轮累积，RUNNER_LLM_BEST_EFFORT=true）",
			zap.String("challenge", ch.Title),
			zap.Int("rounds", f.maxRounds),
			zap.Strings("candidates", bestCandidates))
		return bestCandidates, nil
	}
	return nil, nil
}

// ── 工具定义 ────────────────────────────────────────────────

// buildToolDefs 构造工具列表。pyBridge nil 时跳过 execute_python。
func (f *LLMFallback) buildToolDefs() []*schema.ToolInfo {
	var tools []*schema.ToolInfo

	if f.pyBridge != nil {
		tools = append(tools, &schema.ToolInfo{
			Name: "execute_python",
			Desc: strings.TrimSpace(`
执行 Python 解题 skill（angr/pwntools 真跑）。当题目属于 reverse/pwn/crypto/misc 且需要动态执行二进制或利用 Python 生态工具时调用。
`+skillCatalogDesc(f.pyBridge)+`
- crypto 数学模板（ctf_sage_*，纯 Python 自包含，P0-1 接入；数学参数必须经 params 传入，
  返回值含中间量如小根/私钥/明文，由你决定后续怎么用）：
  ctf_sage_t1_coppersmith  → params: {"modulus":N,"poly":[a0..ad],"X":可选,"beta":"1"|"0.5","candidates":可选}
  ctf_sage_t2_ecdsa_hnp    → params: {"mode":"nonce_reuse","n":N,"r":r,"s1":s1,"z1":z1,"s2":s2,"z2":z2}
                              或 {"mode":"hnp","n":N,"nonce_bits":k,"sigs":[{"r":..,"s":..,"z":..},...]}
  ctf_sage_t3_truncated_lfsr → params: {"mode":"full","outputs":[...],"width":w,"predict_count":k}
                              或 {"mode":"truncated","outputs":[...],"width":w,"known_high":k,"taps":[...]}
  ctf_sage_t4_boneh_durfee → params: {"n":N,"e":e,"c":可选,"delta":0.26}
  ctf_sage_t5_dlp_bsgs_ph  → params: {"g":g,"h":h,"p":p,"order":可选}
  ctf_sage_t6_hastad_broadcast → params: {"e":e,"pairs":[[n1,c1],...]}
参数中 skill_name 必填，params 选填（JSON 对象，skill 的特殊参数）。`),
			ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
				"skill_name": {
					Type:     schema.String,
					Desc:     "skill 名称（见 desc 中可选值列表）",
					Required: true,
				},
				"params": {
					Type: schema.String,
					Desc: "JSON 字符串格式的额外参数（选填）",
				},
			}),
		})
	}

	tools = append(tools, &schema.ToolInfo{
		Name: "read_attachment",
		Desc: strings.TrimSpace(`
下载题目附件（二进制/PCAP/ZIP/内存镜像等），保存到临时目录后返回：
1. 文件本地路径
2. 文件大小（字节）和 MIME 类型
3. strings 输出前 80 行（文本类附件直接给内容，二进制类给可打印字符串）
如果附件是 ELF/PE 等二进制，你拿到路径后可以再决定用 execute_python 调 angr 或 pwntools 分析。`),
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
			"attachment_url": {
				Type:     schema.String,
				Desc:     "附件下载 URL（从题目信息里获取）",
				Required: true,
			},
		}),
	})

	// P1-2：有状态 Python 会话。变量/import/cwd/打开的文件句柄**跨调用保持**，
	// 故多步推导不必把中间结果写回文本再重述（独白式漂移的主要来源）。
	tools = append(tools, &schema.ToolInfo{
		Name: "python_session",
		Desc: strings.TrimSpace(`
在**有状态**的 Python 会话里执行代码：变量、import、当前目录、已打开的文件句柄
在后续调用里仍然存在（与 execute_python 的一次性 skill 调用不同）。
适合需要多步推导/反复试算的题目：先取数据 → 存进变量 → 逐步变换 → 验证。
约定：
- 需要带出结果时把它赋给 _ （下划线），会话会回显 repr(_)；
- 用 print() 输出中间过程；
- reset=true 会清空用户变量（保留当前目录）；
- 单条命令 120s 超时；超时会销毁会话，此时**状态丢失**，需重新计算（工具会明说）。`),
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
			"code": {
				Type:     schema.String,
				Desc:     "要执行的 Python 代码（可多行）",
				Required: true,
			},
			"reset": {
				Type: schema.String,
				Desc: "是否清空变量（\"true\"/\"false\"，选填；默认 false，保留 cwd）",
			},
		}),
	})

	return tools
}

// executeTool 根据 ToolCall 的 Function.Name 路由到对应实现。
// 统一返回文本结果（LLM 读 ToolMessage.Content）。
//
// P0-3：①先过 schema 强校验（工具名/必填/未知参数），非法调用不执行、直接回错误；
// ②成功后把工具返回里的环境事实（如附件真实落盘路径）记进 factLedger ——
// 事实源只认工具返回，模型复述不算。
// skillCatalogDesc 把 bridge 的**真实** skill 清单渲染成 execute_python 的 Desc 段。
//
// 绝不回退到硬编码名（2026-11-01 P0：旧 Desc 手写 16 个名字，15 个不存在，
// 模型照单调 factor_integer，79 个真 skill 全程零使用）。bridge 未实现
// SkillCatalogProvider 时给一句保守提示，让模型知道不能瞎猜。
func skillCatalogDesc(b SkillRunner) string {
	p, ok := b.(SkillCatalogProvider)
	if !ok {
		return "（本通道未提供 skill 清单：不要编造 skill 名，拿不准就用 python_session 自己写代码）\n"
	}
	cat := p.SkillCatalog()
	if len(cat) == 0 {
		return "（当前无可用 skill：直接用 python_session 自己写代码）\n"
	}
	// 固定顺序渲染，保证 Desc 逐字节稳定（顺序抖动会让上游 prompt 缓存全部失效）。
	order := []string{"crypto", "reverse", "pwn", "misc", "web"}
	seen := make(map[string]bool, len(order))
	// 参数契约（可选）：模型光知道名字不够，还得知道这个 skill 读哪些 params 键。
	contracts := map[string]string(nil)
	if cp, ok2 := b.(SkillContractProvider); ok2 {
		contracts = cp.SkillContracts()
	}
	var sb strings.Builder
	sb.WriteString("skill_name 可选值（**只能从这里挑；未列出的名字一律不存在，不要编造**）：\n")
	dump := func(c string, names []string) {
		sb.WriteString("- " + c + ": ")
		for i, n := range names {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(n)
			if k, ok3 := contracts[n]; ok3 && k != "" {
				sb.WriteString("(" + k + ")")
			}
		}
		sb.WriteString("\n")
	}
	for _, c := range order {
		if len(cat[c]) == 0 {
			continue
		}
		seen[c] = true
		dump(c, cat[c])
	}
	rest := make([]string, 0, len(cat))
	for c := range cat {
		if !seen[c] {
			rest = append(rest, c)
		}
	}
	sort.Strings(rest)
	for _, c := range rest {
		dump(c, cat[c])
	}
	if len(contracts) > 0 {
		sb.WriteString("括号内是该 skill 从 params 读取的键名（缺一个就会 KeyError）。" +
			"从附件里先把这些值算出来/读出来，再按同名键以 JSON 传入 params。\n")
	}
	return sb.String()
}

func (f *LLMFallback) executeTool(ctx context.Context, tc schema.ToolCall, ch *ctfplatform.Challenge, facts *factLedger, sess *pySessionMgr) string {
	// 解析参数 JSON
	var args map[string]any
	if tc.Function.Arguments != "" {
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			return fmt.Sprintf("[工具 %s 参数解析失败] %v", tc.Function.Name, err)
		}
	}

	// P0-3 ①：schema 强校验（含未知工具名 —— 旧实现只在 switch default 兜底，
	// 未登记参数会静默放行）
	if err := validateToolCall(tc.Function.Name, args); err != nil {
		return toolCallRejectText(tc.Function.Name, err)
	}

	var result string
	switch tc.Function.Name {
	case "execute_python":
		result = f.toolExecutePython(ctx, args, ch)
	case "read_attachment":
		result = f.toolReadAttachment(ctx, args)
	case "python_session":
		result = f.toolPythonSession(ctx, args, sess)
	default:
		return fmt.Sprintf("[未知工具: %s]", tc.Function.Name)
	}

	// P0-3 ②：成功才记事实（错误返回里没有可信路径）
	if !isToolError(result) {
		facts.recordFactsFromToolResult(tc.Function.Name, result)
	}
	return result
}

// toolExecutePython 调 pyBridge.RunSkill（subprocess 执行 Python skill）。
// 硬限：120s 子进程超时（由 ctx 控制 + bridge 自身 timeout）。
// P0-1：params 透传 + 富结果路径见下方 if rich 块与 parseExtraParams。
func (f *LLMFallback) toolExecutePython(ctx context.Context, args map[string]any, ch *ctfplatform.Challenge) string {
	if f.pyBridge == nil {
		return "[execute_python 不可用：pyBridge 未初始化]"
	}

	skillName, _ := args["skill_name"].(string)
	if skillName == "" {
		return "[execute_python 缺少 skill_name]"
	}
	// 第二道围栏（2026-11-01）：skill_name 会被桥接层拼进 Python 源码
	// `import <name> as s`，非标识符输入等于代码注入；params 里的绝对路径
	// 会被 skill 当 path 直接读，绕开 python_session 的围栏。两道都过
	// 同一条 pathFence 口径（详见 llm_hardconstraint.go 该段注释）。
	if err := validateSkillName(skillName); err != nil {
		return fmt.Sprintf("[execute_python 拒绝执行] %v", err)
	}
	extra := parseExtraParams(args["params"])
	if bad := paramPathViolations(extra); len(bad) > 0 {
		return fmt.Sprintf("[execute_python 拒绝执行] params 引用了本题工作区之外的路径 %v；"+
			"允许范围与 python_session 相同（本题工作目录 + 附件收件箱 + 只读系统路径）。"+
			"要用附件请先 read_attachment，它会落到收件箱并把真实路径给你",
			bad)
	}

	// 120s subprocess 硬超时
	execCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// P0-1（2026-10-25）：args["params"] 透传。工具描述一直承诺可传 skill 特殊
	// 参数，旧实现直接忽略——ctf_sage 数学模板（需要 n/e/c/f_coeffs 等入参）
	// 因此在 L3 不可用。RichSkillRunner + 非空 params 双条件才走富结果路径，
	// 否则逐字节保持旧行为（现有 fake 与生产零变化）。
	if rich, ok := f.pyBridge.(RichSkillRunner); ok {
		if extra != nil {
			text, ran := rich.RunSkillRich(execCtx, skillName, ch, extra)
			if !ran {
				return fmt.Sprintf("[execute_python skill 执行失败或无依赖] skill=%s", skillName)
			}
			if strings.TrimSpace(text) == "" {
				return fmt.Sprintf("[execute_python skill 执行成功但无输出] skill=%s", skillName)
			}
			return fmt.Sprintf("[execute_python 成功] skill=%s → %s", skillName, truncate(text, 4000))
		}
	}

	flags, ok := f.pyBridge.RunSkill(execCtx, skillName, ch)
	if !ok {
		return fmt.Sprintf("[execute_python skill 执行失败或无依赖] skill=%s", skillName)
	}

	if len(flags) == 0 {
		return fmt.Sprintf("[execute_python skill 执行成功但无 flag 输出] skill=%s", skillName)
	}

	return fmt.Sprintf("[execute_python 成功] skill=%s → flags: %s", skillName, strings.Join(flags, ", "))
}

// toolPythonSession 在**有状态会话**里执行代码（P1-2）。
// 与 execute_python（一次性 skill 子进程）的区别：变量/import/cwd/文件句柄跨步保持，
// 模型不必把中间结果写回文本再重述 —— 治独白与上下文漂移（失败模式 ⑨⑪）。
func (f *LLMFallback) toolPythonSession(ctx context.Context, args map[string]any, sess *pySessionMgr) string {
	if sess == nil {
		return "[python_session 不可用：本轮未创建会话]"
	}
	code, _ := args["code"].(string)
	if strings.TrimSpace(code) == "" {
		return "[python_session 缺少 code]"
	}
	reset := false
	switch v := args["reset"].(type) {
	case bool:
		reset = v
	case string:
		reset = strings.EqualFold(strings.TrimSpace(v), "true")
	}

	// 单条命令硬超时 120s（与 execute_python 同口径）
	execCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	out, err := sess.Exec(execCtx, code, reset)
	if err != nil {
		return fmt.Sprintf("[python_session 失败] %v", err)
	}
	return out
}

// parseExtraParams 解析 execute_python 的 params 参数。
// 容错两种形态：JSON 字符串（工具契约写法）或已解析的 object（部分模型直发）。
// 空/缺失/解析失败 → nil（调用方回落到 flag 契约，不制造新失败模式）。
func parseExtraParams(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			return nil
		}
		return t
	case string:
		s := strings.TrimSpace(t)
		if s == "" || s == "{}" {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil || len(m) == 0 {
			return nil
		}
		return m
	}
	return nil
}

// airgapBlockedHosts 在 RUNNER_LLM_AIRGAP=1 时拒绝到这些主机的出口 HTTP 请求，
// 用于受控实验：隔离"检索公开 flag（如 github 上的 flag.txt）"与"真求解"。
// 仅影响 read_attachment 的下载客户端；练习场附件（ctf2 等其他 host）不受影响。
var airgapBlockedHosts = map[string]bool{
	"github.com":                true,
	"www.github.com":            true,
	"raw.githubusercontent.com": true,
	"api.github.com":            true,
	"gist.github.com":           true,
}

type airgapTransport struct{ rt http.RoundTripper }

func (t *airgapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if airgapBlockedHosts[host] {
		return nil, fmt.Errorf("airgap: egress to %s blocked (RUNNER_LLM_AIRGAP=1)", host)
	}
	return t.rt.RoundTrip(req)
}

// attachmentHTTPClient 返回 read_attachment 使用的 HTTP 客户端。
// 默认 http.DefaultClient；RUNNER_LLM_AIRGAP=1 时注入拒绝 GitHub 的 transport。
var attachmentHTTPClient = func() *http.Client {
	if os.Getenv("RUNNER_LLM_AIRGAP") == "1" {
		return &http.Client{Transport: &airgapTransport{rt: http.DefaultTransport}}
	}
	return http.DefaultClient
}()

// toolReadAttachment 下载附件到 /tmp，返回路径 + 文件信息 + strings 前 80 行。
// 硬限：30s 下载超时。
func (f *LLMFallback) toolReadAttachment(ctx context.Context, args map[string]any) string {
	attURL, _ := args["attachment_url"].(string)
	if attURL == "" {
		return "[read_attachment 缺少 attachment_url]"
	}

	// 30s 下载超时
	dlCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 解析 URL，取文件名
	parsed, err := url.Parse(attURL)
	if err != nil {
		return fmt.Sprintf("[read_attachment URL 解析失败] %v", err)
	}
	fileName := filepath.Base(parsed.Path)
	if fileName == "" || fileName == "/" {
		fileName = "attachment"
	}

	// 下载到**附件收件箱**（不是临时目录根）：收件箱是 python_session 围栏唯一
	// 额外放行的目录，落在 /tmp 根下会被自己的围栏挡回去（详见 attachment_inbox.go）。
	localPath := filepath.Join(attachmentInboxDir(), sanitize(fileName))

	req, err := http.NewRequestWithContext(dlCtx, "GET", attURL, nil)
	if err != nil {
		return fmt.Sprintf("[read_attachment 请求构造失败] %v", err)
	}

	resp, err := attachmentHTTPClient.Do(req)
	if err != nil {
		return fmt.Sprintf("[read_attachment 下载失败] %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("[read_attachment HTTP %d] url=%s", resp.StatusCode, attURL)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50MB 上限防大文件
	if err != nil {
		return fmt.Sprintf("[read_attachment 读取失败] %v", err)
	}

	if err := os.WriteFile(localPath, data, 0644); err != nil {
		return fmt.Sprintf("[read_attachment 落盘失败] %v", err)
	}

	// 判断文件类型（简化版）
	mime := resp.Header.Get("Content-Type")
	if mime == "" {
		mime = "application/octet-stream"
	}

	// strings 前 80 行
	stringsOut := runStrings(localPath, 80)

	// 回给模型的是 POSIX 形态（`/` 分隔）：它要拿去在 python_session 里写代码，
	// Windows 反斜杠在 Python 字符串里是转义符，直接给原生路径会引出无谓的报错。
	// 事实账本记录的也是这个形态（模型复述的就是它）。
	displayPath := filepath.ToSlash(localPath)

	return fmt.Sprintf("附件下载成功:\n路径: %s\n大小: %d bytes\nMIME: %s\n--- strings 前 80 行 ---\n%s",
		displayPath, len(data), mime, stringsOut)
}

// runStrings 执行 strings 命令取前 N 行可打印字符串。
// strings 不存在时 fallback 到文件直接读取前 4096 字节。
func runStrings(path string, lines int) string {
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeout, "strings", "-n", "4", path)
	out, err := cmd.Output()
	if err != nil {
		// fallback: 直接读文件前 4096 字节
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return "[strings 命令不可用且读文件失败]"
		}
		return extractPrintable(string(data[:min(len(data), 4096)]))
	}

	content := string(out)
	// 按行截断
	allLines := strings.Split(strings.TrimSpace(content), "\n")
	end := min(lines, len(allLines))
	return strings.Join(allLines[:end], "\n")
}

func extractPrintable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' {
			b.WriteRune(r)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

func sanitize(name string) string {
	re := regexp.MustCompile(`[^\w\-\.]`)
	return re.ReplaceAllString(name, "_")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Prompt / 提取 helper ──────────────────────────────────

func (f *LLMFallback) buildSystemPrompt() string {
	tools := f.buildToolDefs()
	var toolNames []string
	for _, t := range tools {
		toolNames = append(toolNames, t.Name)
	}

	system := `你是一个 CTF 解题助手，拥有以下工具：` + strings.Join(toolNames, ", ") + `

解题流程（按题类别选策略）：
- reverse: 先用 read_attachment 下载二进制，再用 execute_python(angr_decompile 或 angr_symbolic) 做反编译/符号执行
- pwn: read_attachment → execute_python(pwn_checksec) 查保护 → pwn_ret2libc/ret2win 打利用
- crypto: 优先 execute_python 调 ctf_sage_* 数学模板（t1 Coppersmith 小根 / t2 ECDSA-HNP /
  t3 截断 LFSR / t4 Boneh-Durfee / t5 DLP / t6 Håstad 广播）——先从题干提取数学参数
  （n/e/c/签名序列/输出序列）经 params 传入；模板返回 not_applicable = 前提不满足，
  换攻击路或换模板。**当没有模板适用时，必须用 execute_python 编写并运行自定义解题脚本**
  （可直接调用 sage / sympy / pow / 现成库，**无需从零实现格基约化等底层原语**）：
  已注入 ctf_crypto 模块，可直接 import ctf_crypto as C 调用即用原语
  （RSA 攻击套件 rsa_wiener/rsa_common_modulus/rsa_fermat/rsa_broadcast、
  ECC 点运算 ECPoint、AES/DES 加解密、纯 Python LLL 规约、哈希识别 identify_hash、
  数论 modinv/crt/factor/iroot 等）。优先复用这些原语，不要重复造轮子。
  边读题面与附件、边写脚本、边运行、边按输出调整，直到拿到 flag。写并运行代码是 crypto
  解题的常态核心动作，不要只用自然语言"推理"或只读文件。
- web: 纯人工推理（SQLi/XSS/反序列化），不需要工具
- misc: 看附件类型选工具（PCAP→pcap_analyze，图片→image_steg，压缩包→zip_crack）

规则：
1. 【最重要】一旦你通过工具或推理确信已得到 flag，必须立即停止调用任何工具，单独输出该 flag（格式为 flag{...} 或 dice{...}，多个候选每行一个）。不要"再跑一轮确认"——你已经算出来了就是完成。若你已算出结果却只输出了过程文本，本轮视为未完成，必须补一句只含 flag 的输出。若你得到的是字节序列/数字序列，先将其还原为可读字符串（flag 内容），再用 dice{...} 或 flag{...} 包裹输出，绝对不要只输出裸字节或裸数字。
2. 如果用了工具，把工具结果融合进推理
3. 如果实在没思路，直接输出 NO_SOLUTION
4. 解题过程中请用 execute_python 编写并运行解题/攻击脚本——写并运行代码是 crypto / pwn
  解题的核心动作，不是"输出代码"。当你确信已得到 flag 时，停止调用任何工具，单独输出
  该 flag 或 NO_SOLUTION（终局轮不要只贴代码而不给 flag）。
5. 每轮回复末尾输出一行 CONFIDENCE: 0.x（0~1，一位小数），表示你对
   当前路径最终解出此题的信心。工具调用轮也要带（写在文本部分）。
   该数值是预算监督信号：低信心+连续无进展会被提前收口/要求换策略，
   高信心会保住预算。不许虚报——虚报高信心烧的是你自己的预算。`

	return system
}

// toolErrorPrefixes executeTool 错误返回的已知前缀（bracket 约定的精确枚举，
// 不用泛 IsPrefix("[")——skill 正常输出可能以 "[" 开头如 JSON 数组，会误判）。
var toolErrorPrefixes = []string{
	// P1-2：python_session 的错误返回同样必须被监督计为错误步（漏登记会让
	// 会话失败被当成"有进展"，规则⑥收口就被架空 —— 由 TestPythonSessionToolRouting 锁住）。
	"[未知工具:", "[工具 ", "[execute_python", "[read_attachment", "[python_session 失败", "[python_session 缺少", "[python_session 不可用",
}

// isToolError 按 executeTool 的错误返回约定判定该步是否为错误步。
// 错误步不算进展（进展口径诚实化：非空 ≠ 有进展）。
func isToolError(result string) bool {
	s := strings.TrimSpace(result)
	for _, p := range toolErrorPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// confRe 自评信心解析（听风第三刀）：LLM 每轮按契约输出 CONFIDENCE: 0.x。
var confRe = regexp.MustCompile(`(?i)confidence\s*[:：]\s*([0-9]*\.?[0-9]+)`)

// parseConfidence 从模型回复中解析自评信心。缺省/非法 → ok=false（调用方
// 保持 nil = 中性 0.5，不伪造信号）。越界值 clamp 到 [0,1]。
func parseConfidence(text string) (float64, bool) {
	m := confRe.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	var v float64
	if _, err := fmt.Sscanf(m[1], "%g", &v); err != nil {
		return 0, false
	}
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	return v, true
}

func (f *LLMFallback) buildUserPrompt(ch *ctfplatform.Challenge) string {
	var b strings.Builder
	b.WriteString("题目：")
	b.WriteString(ch.Title)
	b.WriteString("\n类别：")
	b.WriteString(ch.Category)

	if len(ch.AttachmentURLs) > 0 {
		b.WriteString("\n附件 URL 列表（可用 read_attachment 下载）：\n")
		for i, url := range ch.AttachmentURLs {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, url)
		}
	}

	// 本地工件清单（2026-11-01）：read_attachment 只认 URL，本地工件走不到
	// AttachmentURLs ⇒ 不注入的话模型完全不知道 cwd 里有附件可用（ycb2026 跑批
	// 零工具调用的成因）。详见 internal/runnerl3/local_artifacts.go 文件头。
	if hint := localArtifactHint(); hint != "" {
		b.WriteString("\n")
		b.WriteString(hint)
	}

	b.WriteString("\n题目描述：\n")
	b.WriteString(truncate(ch.Description, 8000))

	// P1-1 攻击向量编排层：把题面线索编排成结构化攻击假设，随题面注入。
	// 治失败模式①②（不读题面盲扫 / 选错攻击面）—— 假设来自**本题**线索并带证据与排序，
	// 与"在 prompt 里罗列攻击类型表"本质不同（罗列式已被基线实证会首项锁死）。
	desc := ch.Description
	if ch.Category != "" {
		desc = ch.Title + "\n" + ch.Description
	}
	if hs := ctfplatform.BuildAttackHypotheses(desc, ctfplatform.ParseWebHints(desc)); len(hs) > 0 {
		b.WriteString("\n\n")
		b.WriteString(ctfplatform.RenderAttackHypotheses(hs))
	}
	return b.String()
}

// extractFlagCandidates 从文本里提取所有 flag{...} 格式的候选。
// defaultWholeSolveTimeoutSec 是 RUNNER_LLM_TIMEOUT_SEC 的默认值 —— **整题**总预算。
// 取值依据见 Solve 内的注释（2026-10-29 服务器真机实测）。
// 🔴 这个数不是"顺手填的"：把它改回 60 会把正在解题的题系统性地判成 MISS。
const defaultWholeSolveTimeoutSec = 300

// flagCandRe 与 scripts/experiments/flag_util.py::FLAG_RE **同口径**（2026-10-29 对齐）。
//
// 为什么必须换成正则，不能再做 `strings.Index(lower, "flag{")` 字面量查找：
//   前缀 `flag{}` 只是**一种**约定，不是全部。2026-10-29 服务器真机冒烟实锤：
//   pico2024_interencdec 题，step-5-preview 已输出正确解
//   `picoCTF{contract_fixture_9f2a}`（原题真值已脱敏并改由 `flag_sha256` 判分，
//   此处仅复现「带非 flag 前缀」形态），旧实现因为找不到字面量 `flag{`
//   判为「LLM 输出里没找到 flag 格式」→ **候选 0 → 不提交 → 记 MISS**。
//   真实题库里 picoCTF{} / sdctf{} / CBCV{} / wctf{} / grodno{} / DASCTF{} /
//   BZHCTF{} 等前缀普遍存在，旧实现对它们**逐道系统性判死**。
//   这是「答案对了但系统判没解」的冤案，直接压低真实解题数 —— 属五宗罪「伪造分数」的反面同源。
//
// 形态约束（与 Python 侧逐字一致，勿各自演化）：
//   - 前缀：字母开头，后跟 0~14 个字母/数字/下划线（覆盖 picoCTF 这类长前缀）；
//   - 内容：`{` `}` 之间 1~200 个非括号非换行字符；
//   - 必须有闭合 `}`，避免把半截文本当候选。
//
// 放宽后的假阳性由**下游 sha256 判分**兜住（判分只认 flag_sha256），
// 不会把噪声算成命中；而漏召回是**不可逆丢分**，故宁宽勿窄。
var flagCandRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_]{0,14}\{[^{}\n]{1,200}\}`)

func extractFlagCandidates(text string) []string {
	var flags []string
	seen := make(map[string]bool)

	for _, raw := range flagCandRe.FindAllString(text, -1) {
		f := strings.TrimSpace(raw)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		flags = append(flags, f)
	}

	return flags
}

// rawIntRe 匹配"可能编码了 flag 的长纯数字串"（如 DAC 网表把 flag 二进制位重建为
// 十进制巨整数）。阈值 20 位，避免误抓普通计数值；flag 通常 30+ 字节 → 70+ 位十进制。
var rawIntRe = regexp.MustCompile(`\d{20,}`)

// extractRawAnswerCandidates 捕获"模型算对但没包裹 flag{}"的答案：把工具返回里的长纯
// 数字串当作 flag 的 ASCII 码拼接（或字节序列的数值），尝试 int→bytes（大端/小端）还原，
// 若还原结果整体可打印 ASCII 则包成 dice{...} 候选。错候选交由真 submit 的 isCorrect 兜底
// （平台判错只算一次 miss），不会虚高分数。
func extractRawAnswerCandidates(text string) []string {
	var out []string
	seen := make(map[string]bool)

	for _, m := range rawIntRe.FindAllString(text, -1) {
		bi := new(big.Int)
		if _, ok := bi.SetString(m, 10); !ok {
			continue
		}
		if bi.BitLen() < 32 { // 太短，不像 flag（<4 字节）
			continue
		}
		be := bi.Bytes() // 大端：最高字节在前
		le := make([]byte, len(be))
		for i := range be { // 小端：最低字节（flag 首字符）在前
			le[i] = be[len(be)-1-i]
		}
		for _, b := range [][]byte{be, le} {
			if len(b) == 0 || !isPrintableASCII(b) {
				continue
			}
			cand := "dice{" + string(b) + "}"
			if !seen[cand] {
				seen[cand] = true
				out = append(out, cand)
			}
		}
	}
	return out
}

// isPrintableASCII 判断字节切片是否整体为可打印 ASCII（含空格/常见标点），
// 用于过滤 int→bytes 还原出的乱码，只对"看起来像 flag 正文"的结果发射候选。
func isPrintableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(截断)"
}
