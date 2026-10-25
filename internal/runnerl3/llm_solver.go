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
//   RUNNER_LLM_TIMEOUT_SEC  默认 60
//   RUNNER_LLM_MAX_TOKENS   默认 2048
//   RUNNER_LLM_MAX_TOOL_CALLS 默认 12（每题工具调用上限）
//   RUNNER_LLM_MAX_ROUNDS   默认 12（LLM 对话轮数上限 = 监督步数预算）
//   RUNNER_LLM_FAILOVER     默认 true —— 通道 failover（P0-4）；false = 退回单通道
//   RUNNER_LLM_FAILOVER_CHANNELS     逗号分隔通道 ID 顺序；空 = 内置优先级（见 llmchannel）
//   RUNNER_LLM_FAILOVER_COOLDOWN_SEC 单通道失败冷却秒数，默认 300
package runnerl3

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
func (f *LLMFallback) Solve(ctx context.Context, ch *ctfplatform.Challenge) ([]string, error) {
	if !f.Enabled || f.model == nil {
		return nil, nil
	}

	timeout := time.Duration(envInt("RUNNER_LLM_TIMEOUT_SEC", 60)) * time.Second
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
	var supSteps []ctfplatform.SupervisionStep // 监督进展信号（逐轮累积）
	candSeen := 0                             // 工具输出中实际提取到的候选 flag 数（不可自欺硬信号）
	var conf float64                          // 模型自评信心（听风第三刀）；nil 语义 = 中性 0.5
	haveConf := false                         // 是否解析到过自评信心（没解析到 = 无信号）

	tokenBudget := f.maxRounds * envInt("RUNNER_LLM_MAX_TOKENS", 2048)
	usedTokens := 0 // 累计 token 用量（听风第四刀：喂监督 TokenRatio，走真实预算口径）

	for round := 0; round < f.maxRounds; round++ {
		opts := []model.Option{}
		if len(tools) > 0 {
			opts = append(opts, model.WithTools(tools))
		}

		resp, err := f.model.Generate(callCtx, msgs, opts...)
		if err != nil {
			f.logger.Warn("LLM fallback 调用失败",
				zap.String("challenge", ch.Title),
				zap.Int("round", round), zap.Error(err))
			return nil, nil
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
				roundObs.WriteString(result)
				roundObs.WriteString("\n")
				if !isToolError(result) {
					allErr = false
				}
				callsThisRound++
				msgs = append(msgs, schema.ToolMessage(result, tc.ID))
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
			f.logger.Warn("P0-3 反幻觉：LLM 声称的文件无工具记录 → 打回（不提交）",
				zap.String("challenge", ch.Title),
				zap.Strings("unbacked_paths", unbacked),
				zap.Int("facts_recorded", facts.count()),
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
skill_name 可选值（按题目类别选）：
- reverse: angr_decompile, angr_symbolic, ghidra_analyze, objdump_disasm
- pwn: pwn_checksec, pwn_ret2libc, pwn_ret2win, pwn_ret2dlresolve, pwn_canary_bruteforce
- crypto: factor_integer, rsa_wiener_attack, rsa_hastad_attack, xor_bruteforce
- misc: zip_crack, image_steg, pcap_analyze
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

	// 120s subprocess 硬超时
	execCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// P0-1（2026-10-25）：args["params"] 透传。工具描述一直承诺可传 skill 特殊
	// 参数，旧实现直接忽略——ctf_sage 数学模板（需要 n/e/c/f_coeffs 等入参）
	// 因此在 L3 不可用。RichSkillRunner + 非空 params 双条件才走富结果路径，
	// 否则逐字节保持旧行为（现有 fake 与生产零变化）。
	if rich, ok := f.pyBridge.(RichSkillRunner); ok {
		if extra := parseExtraParams(args["params"]); extra != nil {
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

	// 下载到临时目录
	tmpDir := os.TempDir()
	localPath := filepath.Join(tmpDir, "secautomind_att_"+sanitize(fileName))

	req, err := http.NewRequestWithContext(dlCtx, "GET", attURL, nil)
	if err != nil {
		return fmt.Sprintf("[read_attachment 请求构造失败] %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
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

	return fmt.Sprintf("附件下载成功:\n路径: %s\n大小: %d bytes\nMIME: %s\n--- strings 前 80 行 ---\n%s",
		localPath, len(data), mime, stringsOut)
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
  换攻击路或换模板；人工推理只用于模板库不适用的题。禁止从零推格攻击或重写 LLL。
- web: 纯人工推理（SQLi/XSS/反序列化），不需要工具
- misc: 看附件类型选工具（PCAP→pcap_analyze，图片→image_steg，压缩包→zip_crack）

规则：
1. 最终输出必须是 flag{...} 格式（或多个候选，每行一个）
2. 如果用了工具，把工具结果融合进推理
3. 如果实在没思路，直接输出 NO_SOLUTION
4. 不要输出推理过程、不要输出代码，只输出 flag 或 NO_SOLUTION
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

	b.WriteString("\n题目描述：\n")
	b.WriteString(truncate(ch.Description, 8000))
	return b.String()
}

// extractFlagCandidates 从文本里提取所有 flag{...} 格式的候选。
func extractFlagCandidates(text string) []string {
	var flags []string
	seen := make(map[string]bool)

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if idx := strings.Index(lower, "flag{"); idx >= 0 {
			end := strings.Index(line[idx:], "}")
			if end > 0 {
				f := strings.TrimSpace(line[idx : idx+end+1])
				f = strings.TrimPrefix(f, "flag: ")
				f = strings.TrimPrefix(f, "FLAG: ")
				if !seen[f] {
					seen[f] = true
					flags = append(flags, f)
				}
			}
		}
	}

	return flags
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(截断)"
}
