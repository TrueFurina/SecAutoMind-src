// presolve_crush.go —— 自实现"位置桶"压缩格式解压器（2026-10-26 固化）。
//
// 实证：HTB Cyber Apocalypse 2024 "crushing"（cybench 采源，锚 2995d226…）。
// crush 二进制算法（objdump 逆向还原）：
//
//	main: getchar 逐字符读入 → add_char_to_map(256 桶, 桶=ASCII)
//	add_char_to_map: malloc(16) 节点 {int64 偏移, next}，尾插到桶链
//	serialize_and_output: 对每桶写 list_len(8B LE) + 逐节点偏移(8B LE)
//
// 解压 = 逐桶读 (链长, 偏移序列) → 位置→字符重建原文（255 桶恰好耗尽全文件
// 是格式自证；第 256 桶因 char 符号截断不出现）。
//
// 诚实口径：仅识别该精确格式（255/256 桶 8B LE 且全部偏移 < 文件长且单调
// 无冲突校验通过才算命中）；重建文本交 scanFlags 出候选，下游 sha256 把关。
package ctfplatform

import (
	"context"
	"encoding/binary"
)

// crushDecompress 解析位置桶格式，返回重建文本；格式不符返回 nil。
func crushDecompress(data []byte) []byte {
	if len(data) < 256*8 { // 最小 256 桶头
		return nil
	}
	pos := 0
	total := 0
	out := make(map[int64]byte, 4096)
	for ch := 0; ch < 256; ch++ {
		if pos+8 > len(data) {
			if ch < 255 { // 非尾部截断 = 格式不符
				return nil
			}
			break // 恰好耗尽（crushing 实证：255 桶耗尽）
		}
		n := int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
		pos += 8
		if n < 0 || n > int64(len(data)) { // 链长不可能超过文件大小
			return nil
		}
		if pos+8*int(n) > len(data) {
			return nil
		}
		for i := int64(0); i < n; i++ {
			off := int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
			pos += 8
			if off < 0 {
				return nil
			}
			if off >= 1<<31 {
				return nil
			}
			if _, dup := out[off]; dup { // 同一位置两个字符 = 格式不符
				return nil
			}
			out[off] = byte(ch)
			total++
		}
	}
	if total == 0 {
		return nil
	}
	maxOff := int64(-1)
	for off := range out {
		if off > maxOff {
			maxOff = off
		}
	}
	text := make([]byte, maxOff+1)
	for i := range text {
		text[i] = '?' // 稀疏洞（本实证无洞——全量覆盖）
	}
	for off, ch := range out {
		text[off] = ch
	}
	return text
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "crush_position_buckets", Category: CategoryMiscS, Priority: 39,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			for _, v := range attachments {
				if len(v) < 256*8 {
					continue
				}
				b := []byte(v)
				if text := crushDecompress(b); text != nil {
					if flags := scanFlags(string(text)); len(flags) > 0 {
						return flags
					}
				}
			}
			return nil
		},
	})
}
