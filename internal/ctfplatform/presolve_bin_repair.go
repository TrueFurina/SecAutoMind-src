// presolve_bin_repair.go —— 二进制附件 flag 修复扫描（2026-10-24 融合 P1 补齐）。
//
// 背景：西湖论剑 A 库 real_reverse_upx 实证——flag 明文嵌在 UPX 壳二进制里，
// 但被打包垃圾字节打断（`flag{bffab77df5cea3\x91\xe6\xff\xff53e...}`）。
// flagRegexPresolve 能扫到该命中，但 isPrintableFlagCandidate 把含控制字节的
// 脏候选判为 likeness=1 拒绝——A 库同场景靠「sha256 仲裁的候选修复」解出，
// B 库此前无等效能力（阶段 1 同卷立尺 reverse 2 题全 miss 的根因之一）。
//
// 本求解器对齐 A 库行为，诚实边界如下：
//  1. 只对**二进制附件值**工作（值内含非打印字节才触发；纯文本附件不启用，
//     避免与 flag_scan 重复劳动、扩大误报面）。
//  2. 修复变体是**猜测**（剥除垃圾字节），不是推导：只生成三种保守变体
//     （hex-only / alnum-only / printable-only），全部要求完整 flag 形态 + 干净可打印。
//  3. 变体仅在「原始 flag{...} 命中存在」时生成（二进制内存在 flag 结构本身就是强信号）。
//  4. 最终对错由下游把关：crossbench/answer check 的 flag_sha256 校验，生产链的
//     平台提交验证。引擎名带 _repair 后缀，诚实标注修复产物身份。
package ctfplatform

import (
	"context"
	"regexp"
	"strings"
)

// binRepairMaxBytes 单个附件值参与修复扫描的长度上限（防御超大二进制）。
const binRepairMaxBytes = 4 << 20

// binRepairFlagShape 修复变体必须满足的完整 flag 形态（品牌前缀 + 花括号体）。
var binRepairFlagShape = regexp.MustCompile(`(?i)^(?:flag|ctf|dasctf|n1ctf|vnctf|hgame|[a-z0-9_]{2,12}ctf)\{[^}]{4,100}\}$`)

// hasBinaryBytes 值内是否含非打印 ASCII 字节（\t\n\r 之外的 <0x20 或 >=0x7f）。
// 只采样首 64KB 判定，避免大文件全量扫描成本。
func hasBinaryBytes(s string) bool {
	n := len(s)
	if n > 65536 {
		n = 65536
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c >= 0x7f {
			return true
		}
	}
	return false
}

// repairFlagCandidates 对一个原始命中（可能含垃圾字节）生成保守修复变体。
// 返回空切片 = 无法生成任何干净完整形态的变体。
func repairFlagCandidates(match string) []string {
	open := strings.IndexByte(match, '{')
	if open <= 0 || !strings.HasSuffix(match, "}") {
		return nil
	}
	brand := match[:open] // 含品牌前缀（flag/ctf/dasctf...，正则已保证）
	inner := match[open+1 : len(match)-1]
	if len(inner) < 4 || len(inner) > 120 {
		return nil
	}
	keep := func(allowed func(byte) bool) string {
		var b strings.Builder
		b.Grow(len(inner))
		for i := 0; i < len(inner); i++ {
			if allowed(inner[i]) {
				b.WriteByte(inner[i])
			}
		}
		return b.String()
	}
	hexOnly := func(c byte) bool { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }
	alnum := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	printable := func(c byte) bool { return c >= 0x20 && c < 0x7f }

	var out []string
	seen := map[string]bool{}
	for _, v := range []string{keep(hexOnly), keep(alnum), keep(printable)} {
		if len(v) < 4 || len(v) > 100 {
			continue
		}
		cand := brand + "{" + v + "}"
		// 三重门：完整形态 + 干净可打印 + 去重
		if !binRepairFlagShape.MatchString(cand) || !isPrintableFlagCandidate(cand) || seen[cand] {
			continue
		}
		seen[cand] = true
		out = append(out, cand)
	}
	return out
}

// tryBinaryFlagRepair 扫二进制附件值：flagRegex 命中（允许体内垃圾字节）→ 修复变体。
// 注册表与硬编码 Presolve 共用本入口。
func tryBinaryFlagRepair(text string, attachments map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(cands []string) {
		for _, c := range cands {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	for _, v := range attachments {
		if len(v) == 0 || len(v) > binRepairMaxBytes {
			continue
		}
		if !hasBinaryBytes(v) {
			continue // 纯文本附件：flag_scan 已覆盖，不重复不误报
		}
		for _, m := range flagRegexPresolve.FindAllString(v, 8) {
			add(repairFlagCandidates(m))
		}
	}
	return out
}

// tryBinaryFlagConcat 分离前缀+花括号拼接（2026-10-24 融合，对齐 A 库
// core/fallbacks.py「省赛 reverse_2 经验」）。
//
// 场景：逆向题把 printf("flag") 与 {xxx} 作为**两个独立字符串**存放在 .data
// ——直接正则永远扫不到完整 flag（real_reverse_sheng 实锤：strings 里只有
// 独立的 "flag" 与 "{hacking_for_fun}"）。本路提取仅花括号串与独立品牌前缀串，
// 拼接为候选；对错由下游 sha256/平台提交把关（与 A 库仲裁语义一致）。
func tryBinaryFlagConcat(text string, attachments map[string]string) []string {
	strRe := regexp.MustCompile(`[\x20-\x7e]{4,}`)
	braceFull := regexp.MustCompile(`\{[^}\s]{3,100}\}`)
	prefixFull := regexp.MustCompile(`(?i)^(?:flag|ctf|dasctf|n1ctf|vnctf)$`)
	var braces, prefixes []string
	seenB := map[string]bool{}
	seenP := map[string]bool{}
	for _, v := range attachments {
		if len(v) == 0 || len(v) > binRepairMaxBytes || !hasBinaryBytes(v) {
			continue
		}
		for _, m := range strRe.FindAllString(v, -1) {
			s := strings.TrimSpace(m)
			if len(s) > 3 && strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
				if braceFull.MatchString(s) && !seenB[s] && len(braces) < 32 {
					seenB[s] = true
					braces = append(braces, s)
				}
				continue
			}
			if prefixFull.MatchString(s) && !seenP[strings.ToLower(s)] && len(prefixes) < 8 {
				seenP[strings.ToLower(s)] = true
				prefixes = append(prefixes, s)
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, b := range braces {
		for _, p := range prefixes {
			cand := p + b
			if !isPrintableFlagCandidate(cand) || seen[cand] {
				continue
			}
			seen[cand] = true
			out = append(out, cand)
		}
	}
	return out
}

func init() {
	RegisterSolver(SolverEntry{
		Name:     "bin_flag_repair",
		Category: CategoryMiscS, // 全题型兜底位：二进制 flag 嵌入多见于 reverse/misc
		Priority: 13,            // 低于 flag_scan(12)：修复产物可信度再降一档
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryBinaryFlagRepair(text, attachments)
		},
	})
	RegisterSolver(SolverEntry{
		Name:     "bin_flag_concat",
		Category: CategoryMiscS, // 同上：reverse .data 分离串题型兜底
		Priority: 14,            // 拼接产物可信度再降一档（两串拼接=两层猜测）
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return tryBinaryFlagConcat(text, attachments)
		},
	})
}
