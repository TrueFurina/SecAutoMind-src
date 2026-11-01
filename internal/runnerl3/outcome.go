package runnerl3

import (
	"sync"

	"go.uber.org/zap"
)

// ── 未命中归因（2026-11-01）─────────────────────────────
//
// 存在原因（真机事故）：
//   reports 里 `cand=0` 同时代表两种**处置方向相反**的情况 ——
//     ① 模型从头到尾没产出任何 flag 形态 → 该补能力（提示/工具/预算）；
//     ② 模型产出了候选，但被反幻觉闸门打回、或轮数耗尽而 best-effort 关闭
//        → 该补幻觉抑制与收口策略，且**绝不能再往提交链接**。
//
// 2026-11-01 的 6 题对照里，5 道 miss 的收口原因是 3 道「监督 ABANDON」+
// 2 道「轮数耗尽」，全都是 ②；其中 Primes 在第 10 轮自造了 CTF{YkDOLI...}
// （sha256 与真值不符），报告里与「一句话没说」完全同形。
//
// 因此这里把"归因"从**日志里的人肉判读**提升为**结构化字段**：
// Solve 退出时统一记一次，跑批工具据此在报告里区分 cand=0 的两种含义。
// 分类逻辑抽成纯函数 classifyMiss，便于单测与变异验证（不允许"看起来对"）。

// solveTally 是归因所需的计数（全部来自 Solve 内部的真信号）。
type solveTally struct {
	// CandSeen 跨轮从工具观测里提取到的候选**出现次数**（含重复）。
	CandSeen int
	// Distinct 去重后的候选数 —— "模型真的给过几个不同答案"。
	Distinct int
	// Suppressed 模型自己产出的候选里，被**反幻觉闸门**当场丢弃的个数。
	//
	// 为什么要单列：这批候选不进 Distinct（它们进不了提交链），若不计入，
	// 闸门打回就会被归因成"零候选=模型不行"，方向正好相反。
	Suppressed int
	// ToolCalls 本题实际执行的工具调用数（=0 说明它连工具都没动过）。
	ToolCalls int
	// Truncated 因输出预算耗尽被截断的轮次数（finish_reason=="length"）。
	//
	// 为什么要单列：推理模型的 reasoning_content 与正文共用 max_tokens，
	// 预算不足时"想一半被掐断"，content 为空或半截 JSON。这种题的
	// 报告表现是 cand=0，与"模型不会"同形，但修法相反（抬预算 vs 补能力）。
	// **>0 时该题的"零候选"不能作为能力证据**，这是分母诚实性的一部分。
	Truncated int
}

// SolveOutcome 是一次 Solve 的收口归因快照。
type SolveOutcome struct {
	// Reason 取值为本文件定义的 Reason* 常量，供报告/日志直接判读。
	Reason string `json:"reason"`
	// Returned 实际交出的候选数（>0 才算"命中候选"，仍须 sha256 校验）。
	Returned   int `json:"returned"`
	solveTally     // 内嵌：CandSeen / Distinct / Suppressed / ToolCalls
}

// Reason* 是归因的唯一真值来源（勿在别处硬编码字符串）。
const (
	// ReasonAnswered 交出了至少一个候选（判分仍看 sha256，这里只表示"有东西可判"）。
	//
	// ⚠️ 刻意不用 "solved" 这个词：Solve 层看不到 sha256，无法断言"解出"。
	// 用 solved 会让报告出现「miss_reason: solved」这种自相矛盾的字段。
	ReasonAnswered = "answered"
	// ReasonAnswerWrong 是**报告层**对 ReasonAnswered 的细化：确认 sha256 未命中后，
	// 含义才变成"答了但答错"。Solve 层不得使用（它没有判分能力）。
	ReasonAnswerWrong = "answer_wrong"
	// ReasonCandidatesSuppressed 模型产出过候选，但最终一个都没交出。
	// 成因：反幻觉闸门打回 / 监督 ABANDON / 轮数耗尽且 best-effort 关闭。
	// ⚠️ 这一类包含**幻觉 flag**（Primes 案），是最需要人看的一类。
	ReasonCandidatesSuppressed = "candidates_suppressed"
	// ReasonNoCandidate 全程零候选：模型没产出任何 flag 形态。属能力/提示问题。
	ReasonNoCandidate = "no_candidate"
	// ReasonLLMUnavailable 通道全不可用（基础设施失效，非能力问题）。
	ReasonLLMUnavailable = "llm_unavailable"
	// ReasonDisabled 未启用（无 key / RUNNER_LLM_FALLBACK 关）。
	ReasonDisabled = "disabled"
)

// outcomeBox 给 LLMFallback 挂一个零值可用的归因槽。
//
// 零值可用是刻意的：NewLLMFallback 有多条 return 路径（未启用/缺 key/正常），
// 若在每个分支都初始化就必然漏一条 —— 本项目已有多次"漏初始化导致静默 nil"的先例。
type outcomeBox struct {
	mu sync.Mutex
	o  SolveOutcome
}

func (b *outcomeBox) set(o SolveOutcome) {
	b.mu.Lock()
	b.o = o
	b.mu.Unlock()
}

func (b *outcomeBox) get() SolveOutcome {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.o
}

// LastOutcome 返回最近一次 Solve 的归因快照（未跑过时为零值，Reason 为空串）。
// 跑批工具应当在每道题 Solve 返回后立即读取，避免多题之间互相覆盖。
func (f *LLMFallback) LastOutcome() SolveOutcome {
	if f == nil {
		return SolveOutcome{}
	}
	return f.outcome.get()
}

// classifyMiss 是归因的唯一判据（纯函数，无副作用、无 IO）。
//
// 判定顺序有讲究，不可交换：
//  1. 通道不可用优先 —— 它解释了一切，其它信号在这时都不可信；
//  2. 交出候选 = solved；
//  3. 曾产出候选却一个没交出 = suppressed（幻觉/未收口，最危险的一类）；
//  4. 其余才是真的零候选。
func classifyMiss(err error, returned int, t solveTally) string {
	if err != nil && err == ErrLLMUnavailable {
		return ReasonLLMUnavailable
	}
	if returned > 0 {
		return ReasonAnswered
	}
	if t.CandSeen > 0 || t.Distinct > 0 || t.Suppressed > 0 {
		return ReasonCandidatesSuppressed
	}
	return ReasonNoCandidate
}

// recordOutcome 在 Solve 退出时统一落一次归因（只在 defer 里调用）。
//
// 为什么要 defer：Solve 有 8 个以上 return 点，逐点手写必然漏（且以后新增
// return 也会漏）。defer 是唯一不会随 return 点增加而失效的写法。
func (f *LLMFallback) recordOutcome(err error, returned int, t solveTally) {
	o := SolveOutcome{
		Reason:     classifyMiss(err, returned, t),
		Returned:   returned,
		solveTally: t,
	}
	f.outcome.set(o)
	if f.logger == nil {
		return
	}
	// 用 Info 级：此前唯一能区分两种 cand=0 的日志（"没找到 flag 格式"）
	// 是 Debug 级，而跑批默认 Info ⇒ 那条在最需要的时候恰好不可见。
	f.logger.Info("LLM 收口归因",
		zap.String("reason", o.Reason),
		zap.Int("returned", o.Returned),
		zap.Int("cand_seen", o.CandSeen),
		zap.Int("distinct", o.Distinct),
		zap.Int("suppressed", o.Suppressed),
		zap.Int("tool_calls", o.ToolCalls),
		zap.Int("truncated", o.Truncated))
}
