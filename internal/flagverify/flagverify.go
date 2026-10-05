// Package flagverify 提供 flag 候选的**三态真值仲裁**与**真值源一致性检查**。
//
// 为什么需要（外部事故复盘，2026-09-19 西湖论剑 CTF-Agent 实测）：
//
//		评测校验器从**已退役的题库**取答案表，而被评测题目在另一个目录 → 主 Agent
//		解出的**正确** flag 一律被判成幻觉并丢弃，当日口径 1/10 实为冤案；修复后
//		同一协议 3~4/10，一次修复翻出 3 道真解。
//
//		该事故的通用形态是「验证器的真值来源 ≠ 被验证对象的真值来源」。静态读代码
//		看不出来（两边都"有哈希校验"），只有机器对账能发现。本包把两件事做成可复用原语：
//
//	 1. Truth：给定候选与题面真值（flag_sha256），返回三态而不是 bool。
//	    bool 会把「无真值无法判定」和「确定错误」混为一谈——这正是幻觉误报/漏报的
//	    根源。三态分别是：
//	    - Unknown：题面无可判定真值（或候选为空）→ 交回既有格式/证据门处理；
//	    - Match：与官方真值逐字匹配 → 最强证据，可立即早接受（省 token）；
//	    - Mismatch：与真值不符 → **确定性错误**，比"没有工具证据"更强，可直接拦截。
//
//	 2. Coherence：真值源一致性。同一题 id 在多个题集出现却带不同 flag_sha256，
//	    是"同一个题名、两套答案"的注水温床，静态审查几乎发现不了。
//
// 判定纪律：只认 SHA-256。禁止"看起来像 flag"即计命中。
package flagverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Verdict 是候选 flag 对真值的仲裁结果（三态，勿退化为 bool）。
type Verdict int

const (
	// Unknown 表示无法确定性判定：题面无可判定真值，或候选为空。
	// 调用方应落回既有的格式校验 / 工具证据门，不得据此判对或判错。
	Unknown Verdict = iota
	// Match 表示候选与真值逐字匹配（SHA-256 相等），是最强证据。
	Match
	// Mismatch 表示候选与真值确定不符，属确定性幻觉/错误答案。
	Mismatch
)

func (v Verdict) String() string {
	switch v {
	case Match:
		return "match"
	case Mismatch:
		return "mismatch"
	default:
		return "unknown"
	}
}

var (
	hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// innerRe 取出 flag{...} 的内文。题库存在两种登记口径（全串哈希 / 内文哈希），
	// 因此两种形态都要比对，否则会误判"正确答案为错"。
	innerRe = regexp.MustCompile(`(?s)\{(.+)\}`)
)

// SHA256Hex 返回 s 的 SHA-256 小写十六进制。
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Truth 对候选 flag 与题面真值做三态仲裁。
//
// 支持两种真值登记口径：全串 "flag{X}" 的哈希，或仅内文 "X" 的哈希——
// 求解器常只吐内文，两种都比对才不会出现"对了被判错"。
func Truth(candidate, truthSHA256 string) Verdict {
	cand := strings.TrimSpace(candidate)
	if cand == "" {
		return Unknown
	}
	truth := strings.ToLower(strings.TrimSpace(truthSHA256))
	if truth == "" {
		return Unknown // 无真值：不可确定性判定，禁判对也禁判错
	}
	if !hex64Re.MatchString(truth) {
		return Unknown // 真值格式非法：按"不可判定"处理，绝不因为格式怪就判错
	}
	if SHA256Hex(cand) == truth {
		return Match
	}
	if m := innerRe.FindStringSubmatch(cand); m != nil {
		if SHA256Hex(m[1]) == truth {
			return Match
		}
	}
	return Mismatch
}

// Problem 是真值源一致性检查的输入单元。
type Problem struct {
	ID         string // 题目 id
	File       string // 来源文件（相对路径即可），用于报告定位
	FlagSHA256 string // 题面登记的真值；空串视为不可判定
}

// FindingKind 是一致性检查的发现类型。
type FindingKind string

const (
	// FindingMissingTruth：题目没有可判定的真值 → 无法机器验真伪。
	FindingMissingTruth FindingKind = "missing_truth"
	// FindingInvalidTruth：真值不是 64 位十六进制 → 格式非法。
	FindingInvalidTruth FindingKind = "invalid_truth"
	// FindingTruthDivergence：同一 id 在多文件出现，真值不一致 → 注水温床。
	FindingTruthDivergence FindingKind = "truth_divergence"
)

// Finding 是一条一致性发现。
type Finding struct {
	Kind   FindingKind
	ID     string
	Detail string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] id=%s: %s", f.Kind, f.ID, f.Detail)
}

// Coherence 检查**单个题集内**的真值可判定性：每题真值必须存在且为 64 位十六进制。
// 跨文件"同 id 不同真值"的检查见 CoherenceAcross（map 形态按 id 去重，看不到重复登记）。
//
// 输入 problems 的 key 必须为题目 id；File 仅用于报告。
func Coherence(problems map[string]Problem) []Finding {
	var findings []Finding

	ids := make([]string, 0, len(problems))
	for id := range problems {
		ids = append(ids, id)
	}
	sort.Strings(ids) // 报告稳定可复现

	for _, id := range ids {
		p := problems[id]
		truth := strings.ToLower(strings.TrimSpace(p.FlagSHA256))
		switch {
		case truth == "":
			findings = append(findings, Finding{Kind: FindingMissingTruth, ID: id,
				Detail: "题面无 flag_sha256，无法机器判定真伪"})
		case !hex64Re.MatchString(truth):
			findings = append(findings, Finding{Kind: FindingInvalidTruth, ID: id,
				Detail: fmt.Sprintf("真值非 64 位十六进制（前 16 位 %q）", truncate(truth, 16))})
		}
	}
	return findings
}

// CoherenceAcross 是真实调用入口：把**多个题集文件里的所有题目**汇总后做一致性对账。
// 跨文件聚合后才能发现"同一题 id 在两处登记了不同真值"——这是 map 形态的 Coherence
// 看不到的注水温床（map 会按 id 去重，把重复登记悄悄吃掉）。
func CoherenceAcross(occurrences []Problem) []Finding {
	byID := map[string][]Problem{}
	for _, p := range occurrences {
		id := strings.TrimSpace(p.ID)
		if id == "" {
			id = "(empty-id)"
		}
		byID[id] = append(byID[id], p)
	}
	// 构造给 Coherence 的输入：把"缺真值/格式非法"也一并检出
	flattened := make(map[string]Problem, len(occurrences))
	for id, list := range byID {
		flattened[id] = list[0]
	}
	findings := Coherence(flattened)
	// 跨文件真值分裂（同一 id 多条登记且真值不一致）
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		byTruth := map[string][]string{}
		for _, p := range byID[id] {
			truth := strings.ToLower(strings.TrimSpace(p.FlagSHA256))
			if !hex64Re.MatchString(truth) {
				continue
			}
			byTruth[truth] = append(byTruth[truth], p.File)
		}
		if len(byTruth) <= 1 {
			continue
		}
		var parts []string
		for truth, files := range byTruth {
			sort.Strings(files)
			parts = append(parts, fmt.Sprintf("%s…@%s", truncate(truth, 12), strings.Join(files, ",")))
		}
		sort.Strings(parts)
		findings = append(findings, Finding{Kind: FindingTruthDivergence, ID: id,
			Detail: "同一题 id 在多个位置出现不同真值：" + strings.Join(parts, " / ")})
	}
	return findings
}

// HasRedLine 判断发现集合里是否存在必须阻断的问题。
// 当前口径：真值分裂、缺真值、真值格式非法均为红线。
func HasRedLine(findings []Finding) bool { return len(findings) > 0 }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
