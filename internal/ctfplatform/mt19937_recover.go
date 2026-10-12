package ctfplatform

// Mersenne Twister MT19937 状态恢复攻击（"预测随机数生成器"）
//
// 经典且极常见的密码学/CTF 题型：服务端用 MT19937 生成"随机"值（token、IV、验证码…），
// 但泄露了前 624 个连续 32-bit 输出。由于 MT19937 的状态就是 624 个 32-bit 字，且
// 输出 = temper(state[i]) 是可逆的双射，攻击者可以：
//
//	state[i] = untemper(output[i])            // 由输出反解内部状态（无需种子）
//	state'    = twist(state)                  // 推进一轮（与生成器内部完全一致）
//	next      = temper(state'[0])             // 预测第 625 个输出 = 下一个"随机"值
//
// 全程无需种子、无需任何外部依赖，纯位运算。这正是 MT19937 用作"不可预测"场合时的
// 致命缺陷：一旦泄露 624 个连续完整输出，后续所有输出都可被确定性预测。
//
// 本求解器从题目描述中解析 624 个连续 32-bit 输出（十进制或 0x 十六进制，置于列表
// 字面量 [... ] 中），恢复状态并预测下一个输出，返回 flag{<next>}。
//
// 说明（诚实）：仅实现"完整 32-bit 输出"恢复这一最常见、确定性、可机器校验的形态。
// "只泄露低 k 位"的截断恢复需要 z3/SAT 或 GF(2) 线性方程组求解（2 万变量），超出
// 本仓库 GOPROXY=off 零依赖约束，不在本求解器范围内。

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

const (
	mtN       = 624
	mtM       = 397
	mtMatrixA = 0x9908b0df
	mtUpper   = 0x80000000
	mtLower   = 0x7fffffff
)

var (
	// 强信号：随机散文中几乎不会出现，作为反误报首道闸门。
	mtSignalRe = regexp.MustCompile(`(?i)\b(mersenne[_\s-]?twister|mt[_\s-]?19937|mt19937)\b`)
	mtIntRe    = regexp.MustCompile(`0x[0-9a-fA-F]+|\d+`)
)

// mtTemper MT19937 输出扰乱函数。
func mtTemper(y uint32) uint32 {
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	return y
}

// mtUntemper 是 mtTemper 的逆，采用位级递推（解析法，精确无迭代）：
//
// temper 的四步左右移位异或均可写成 o[p] = x[p] ^ (mask[p]? x[p-shift] : 0)。
// 由 o 反解 x：x[p] = o[p] ^ (mask[p]? x[p-shift] : 0)，自低位向高位递推即可，
// 因为 x[p-shift] 在算到 p 时已经求得。右移位步骤 mask 为全 1，左移位步骤用各自掩码。
func mtUntemper(y uint32) uint32 {
	y = undoRShift(y, 18)
	y = undoLShift(y, 15, 0xefc60000)
	y = undoLShift(y, 7, 0x9d2c5680)
	y = undoRShift(y, 11)
	return y
}

// undoRShift 反解 y ^= (y >> shift) （mask 为全 1）。
// 前向 o[p] = x[p] ^ x[p+shift]，故 x[p] = o[p] ^ x[p+shift]，自高位向低位递推
// （x[p+shift] 在更高位，先算）。p+shift >= 32 时按 0 处理。
func undoRShift(y uint32, shift uint) uint32 {
	var x uint32
	for p := 31; p >= 0; p-- {
		bit := (y >> uint(p)) & 1
		if int(p)+int(shift) < 32 {
			bit ^= (x >> uint(int(p)+int(shift))) & 1
		}
		if bit == 1 {
			x |= 1 << uint(p)
		}
	}
	return x
}

// undoLShift 反解 y ^= (y << shift) & mask。
func undoLShift(y uint32, shift uint, mask uint32) uint32 {
	var x uint32
	for p := 0; p < 32; p++ {
		bit := (y >> uint(p)) & 1
		if ((mask>>uint(p))&1) == 1 && int(p) >= int(shift) {
			bit ^= (x >> uint(p-int(shift))) & 1
		}
		if bit == 1 {
			x |= 1 << uint(p)
		}
	}
	return x
}

// mtTwist 原地执行 MT19937 的 twist 步骤（与生成器内部完全一致）。
func mtTwist(s []uint32) {
	for i := 0; i < mtN; i++ {
		y := (s[i] & mtUpper) | (s[(i+1)%mtN] & mtLower)
		s[i] = s[(i+mtM)%mtN] ^ (y >> 1)
		if y&1 == 1 {
			s[i] ^= mtMatrixA
		}
	}
}

// mtPredictNext 由 624 个连续输出恢复状态并预测第 625 个输出。
// 输出不足 624 个时返回 (0, false)。
func mtPredictNext(outputs []uint32) (uint32, bool) {
	if len(outputs) < mtN {
		return 0, false
	}
	state := make([]uint32, mtN)
	for i := 0; i < mtN; i++ {
		state[i] = mtUntemper(outputs[i])
	}
	mtTwist(state)
	return mtTemper(state[0]), true
}

// parseUint32s 从文本中解析全部非负 32-bit 整数（十进制或 0x 十六进制）。
func parseUint32s(s string) []uint32 {
	matches := mtIntRe.FindAllString(s, -1)
	out := make([]uint32, 0, len(matches))
	for _, m := range matches {
		var v uint64
		var err error
		if strings.HasPrefix(m, "0x") || strings.HasPrefix(m, "0X") {
			v, err = strconv.ParseUint(m[2:], 16, 64)
		} else {
			v, err = strconv.ParseUint(m, 10, 64)
		}
		if err != nil || v > 0xFFFFFFFF {
			continue
		}
		out = append(out, uint32(v))
	}
	return out
}

// extractMTOutputs 从题目描述中抽取 624+ 连续输出：优先解析列表字面量 [...]，
// 否则（信号已命中前提下）取全文所有整数。
func extractMTOutputs(text string) []uint32 {
	if i := strings.Index(text, "["); i >= 0 {
		j := strings.Index(text[i:], "]")
		if j > 0 {
			seg := text[i+1 : i+j]
			if ints := parseUint32s(seg); len(ints) >= mtN {
				return ints
			}
		}
	}
	return parseUint32s(text)
}

// tryMT19937 入口：解析 624 个连续输出并预测下一个，返回 []string{"flag{<next>}"}
// 或 nil（未命中/信号缺失/输出不足）。
func tryMT19937(text string, attachments map[string]string) []string {
	full := text
	for _, v := range attachments {
		full += "\n" + v
	}
	if !mtSignalRe.MatchString(full) {
		return nil
	}
	outputs := extractMTOutputs(full)
	if len(outputs) < mtN {
		return nil
	}
	next, ok := mtPredictNext(outputs)
	if !ok {
		return nil
	}
	return []string{"flag{" + strconv.FormatUint(uint64(next), 10) + "}"}
}

func solveMT19937(ctx context.Context, text string, attachments map[string]string) []string {
	return tryMT19937(text, attachments)
}
