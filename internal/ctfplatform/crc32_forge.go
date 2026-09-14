package ctfplatform

// CRC32 伪造攻击（CRC 是线性校验，不是 MAC）
//
// CRC32 对消息是 GF(2) 线性函数：把消息看作比特向量，CRC 寄存器状态随消息线性变化。
// 因此攻击者只要知道消息 m，就能在其尾部追加恰好 4 字节 X，使
//
//	crc32(m‖X) = 任意目标值 T
//
// 推导（标准 CRC32，反射多项式 0xEDB88320，init/final xor 均为 0xFFFFFFFF）：
//
//	crc32(m‖X) = crc32(m‖0000) ⊕ L(X)
//
// 其中 L(X) 表示"从寄存器 0 出发处理这 4 个字节得到的状态"（纯线性、与 m 无关）。
// 于是令 d = crc32(m‖0000) ⊕ T，只需解 32×32 GF(2) 线性方程组 L(X) = d 即得唯一 X。
//
// 这是"校验和 ≠ 认证码"的经典真攻，纯标准库实现，无外部依赖。

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
)

// crc32Table 反射多项式 0xEDB88320（IEEE 802.3）。
var crc32Table = func() [256]uint32 {
	var t [256]uint32
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}()

// crc32Reg 单字节寄存器更新（与标准 CRC32 同款）：r' = (r>>8) ^ T[(r^b)&0xff]。
func crc32Reg(r uint32, b byte) uint32 {
	return (r >> 8) ^ crc32Table[byte(r)^b]
}

// crc32Std 等价于 hash/crc32.ChecksumIEEE（init/final xor 抵消后同一结果）。
func crc32Std(data []byte) uint32 {
	r := ^uint32(0)
	for _, b := range data {
		r = crc32Reg(r, b)
	}
	return ^r
}

// crc32ForgeSuffix 求 4 字节后缀 X，使 crc32(msg‖X) == target。
// 返回 (X, ok)；理论上唯一解，若线性方程无解返回 ok=false。
func crc32ForgeSuffix(msg []byte, target uint32) ([]byte, bool) {
	base := crc32Std(append(append([]byte{}, msg...), 0, 0, 0, 0))
	d := base ^ target

	// 32 个基向量：第 i 个字节的第 b 位为 1，其余为 0 → L(·)。
	cols := make([]uint32, 0, 32)
	for i := 0; i < 4; i++ {
		for b := 0; b < 8; b++ {
			var buf [4]byte
			buf[i] = byte(1 << uint(b))
			var r uint32
			for _, by := range buf {
				r = crc32Reg(r, by)
			}
			cols = append(cols, r)
		}
	}

	// 组装 32 行 × 33 列（bit32 为增广列）的 GF(2) 方程组。
	rows := make([]uint64, 32)
	for bit := 0; bit < 32; bit++ {
		var row uint64
		for j, v := range cols {
			if (v>>uint(bit))&1 == 1 {
				row |= 1 << uint(j)
			}
		}
		if (d>>uint(bit))&1 == 1 {
			row |= 1 << 32
		}
		rows[bit] = row
	}

	// 高斯消元（列主元）。
	pivotOf := make([]int, 32)
	for i := range pivotOf {
		pivotOf[i] = -1
	}
	row := 0
	for col := 0; col < 32 && row < 32; col++ {
		sel := -1
		for r := row; r < 32; r++ {
			if (rows[r]>>uint(col))&1 == 1 {
				sel = r
				break
			}
		}
		if sel < 0 {
			continue
		}
		rows[row], rows[sel] = rows[sel], rows[row]
		for r := 0; r < 32; r++ {
			if r != row && (rows[r]>>uint(col))&1 == 1 {
				rows[r] ^= rows[row]
			}
		}
		pivotOf[col] = row
		row++
	}
	for r := row; r < 32; r++ {
		if rows[r] == (uint64(1) << 32) { // 0 = 1，无解
			return nil, false
		}
	}

	var x uint32
	for col := 0; col < 32; col++ {
		if pr := pivotOf[col]; pr >= 0 && (rows[pr]>>32)&1 == 1 {
			x |= 1 << uint(col)
		}
	}
	out := []byte{byte(x), byte(x >> 8), byte(x >> 16), byte(x >> 24)}

	// 真值校验：伪造后的整条消息 CRC32 必须命中目标。
	full := append(append([]byte{}, msg...), out...)
	if crc32Std(full) != target {
		return nil, false
	}
	return out, true
}

var (
	// 强信号：crc32。
	crc32SignalRe = regexp.MustCompile(`(?i)\bcrc[-_]?32\b`)
	// 消息（十六进制）：message (hex) = <hex>
	crc32MsgHexRe = regexp.MustCompile(`(?i)message\s*(?:\(hex\))?\s*[:=]\s*([0-9a-fA-F]{2,})`)
	// 目标校验值：target = <8 hex>
	crc32TargetRe = regexp.MustCompile(`(?i)target\s*(?:crc32)?\s*(?:value)?\s*[:=]\s*(?:0x)?([0-9a-fA-F]{8})`)
)

// solveCRC32Forge 解析题目：消息(hex) + 目标 CRC32，伪造 4 字节后缀。
// 返回 flag{<8 hex>}。
func solveCRC32Forge(ctx context.Context, text string, attachments map[string]string) []string {
	if !crc32SignalRe.MatchString(text) {
		return nil
	}
	mm := crc32MsgHexRe.FindStringSubmatch(text)
	tm := crc32TargetRe.FindStringSubmatch(text)
	if mm == nil || tm == nil {
		return nil
	}
	msg, err := hex.DecodeString(mm[1])
	if err != nil || len(msg) == 0 {
		return nil
	}
	tv, err := strconv.ParseUint(tm[1], 16, 32)
	if err != nil {
		return nil
	}
	suffix, ok := crc32ForgeSuffix(msg, uint32(tv))
	if !ok {
		return nil
	}
	return []string{fmt.Sprintf("flag{%s}", hex.EncodeToString(suffix))}
}
