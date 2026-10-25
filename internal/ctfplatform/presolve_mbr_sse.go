package ctfplatform

// presolve_mbr_sse.go —— MBR 内 SSE（andps+psadbw）字节校验链反推
// （xhlj_legacy skills/mbr_sse_verify.py Go 化，刀锋账本 #4；
// CSAW-Quals 2017 rev realism，512B MBR，题面要求 qemu-system-i386）。
//
// 校验结构：实模式开 SSE，输入 20 字节存低内存；前 4 字节须 "flag"；
// body 16 字节经 pshufd 置换后，8 轮 andps 掩码（每轮清零第 k-1/k+7 位）
// + 链式 psadbw（上轮结果作本轮第一操作数）与 8 项 u32 期望表比对。
// 解法：自动提取初值/期望表/置换立即数 → 拆两个独立 8 字节子系统
// （shuf 低半只进 lo 方程、高半只进 hi 方程）→ 逐轮递推 + 总和约束 →
// SAD 非单射时以「可打印 ASCII」域约束消歧 → 完整 psadbw 链仿真复核。
//
// 诚实口径：仅覆盖「单表 andps 掩码 + 链式 psadbw + 常量期望表」子集；
// 命中属 presolve 静态直出，不计 LLM 自主解题率。

import (
	"bytes"
	"encoding/binary"
)

const mbrBase = 0x7C00

var (
	mbrAndps  = []byte{0x0F, 0x54}
	mbrPsadbw = []byte{0x0F, 0xF6}
	mbrPshufd = []byte{0x66, 0x0F, 0x70}
	mbrCmpEdx = []byte{0x66, 0x67, 0x3B}
)

// isMbrSseVerify 廉价判据：512B + 55AA + 三件套指令。
func isMbrSseVerify(data []byte) bool {
	if len(data) != 512 || data[510] != 0x55 || data[511] != 0xAA {
		return false
	}
	return bytes.Contains(data, mbrAndps) && bytes.Contains(data, mbrPsadbw) && bytes.Contains(data, mbrPshufd)
}

type mbrExt struct {
	init16    []byte
	exp       []uint32 // 8 项，si=1..8 顺序
	pshufdImm byte
	maskAddr  int
	expAddr   int
}

func mbrExtract(data []byte) *mbrExt {
	ia := bytes.Index(data, mbrAndps)
	if ia < 0 || ia+5 > len(data) {
		return nil
	}
	maskAddr := int(binary.LittleEndian.Uint16(data[ia+3:]))
	ic := bytes.Index(data, mbrCmpEdx)
	if ic < 0 || ic+8 > len(data) {
		return nil
	}
	expAddr := int(binary.LittleEndian.Uint32(data[ic+4:]))
	ip := bytes.Index(data, mbrPshufd)
	if ip < 0 || ip+5 > len(data) {
		return nil
	}
	imm := data[ip+4]
	exp := make([]uint32, 8)
	for si := 1; si <= 8; si++ {
		o := expAddr + (si-1)*4 - mbrBase
		if o < 0 || o+4 > len(data) {
			return nil
		}
		exp[si-1] = binary.LittleEndian.Uint32(data[o:])
	}
	return &mbrExt{init16: append([]byte(nil), data[0:16]...), exp: exp, pshufdImm: imm, maskAddr: maskAddr, expAddr: expAddr}
}

// mbrCheckMask 校验掩码表为「逐轮移位单字节清零」结构：第 k 轮窗口
// data[mask_addr+si : +16] 每字节 ∈ {00,FF}，且 0x00 恰在 k-1 与 k+7。
func mbrCheckMask(data []byte, maskAddr int) bool {
	for k := 1; k <= 8; k++ {
		si := 9 - k
		o := maskAddr + si - mbrBase
		if o < 0 || o+16 > len(data) {
			return false
		}
		zeros := map[int]bool{}
		for i, b := range data[o : o+16] {
			if b == 0x00 {
				zeros[i] = true
			} else if b != 0xFF {
				return false
			}
		}
		if len(zeros) != 2 || !zeros[k-1] || !zeros[k+7] {
			return false
		}
	}
	return true
}

// mbrSolveHalf 核心递推：解一个 8 字节子系统（tgt[k-1] = 第 k 轮目标 SAD）。
// 返回全部满足的 8 字节解（SAD 非单射——多解可能）。
func mbrSolveHalf(init8 []byte, tgt []uint32) [][]byte {
	c := init8
	lo1lo, lo1hi := int(tgt[0]&0xFF), int(tgt[0]>>8)
	var sols [][]byte
	for X0 := 0; X0 < 256; X0++ {
		// 第 2 轮方程直出总和 T
		T := int(tgt[1]) - lo1hi - absInt(lo1lo-X0)
		if T < 0 {
			continue
		}
		for X1 := 0; X1 < 256; X1++ {
			X := []int{X0, X1, -1, -1, -1, -1, -1, -1}
			prev := int(tgt[1])
			ok := true
			for k := 3; k <= 8; k++ {
				Xk := absInt(prev&0xFF-X0) + absInt(prev>>8-X1) + T - int(tgt[k-1])
				if Xk < 0 || Xk > 255 {
					ok = false
					break
				}
				X[k-1] = Xk
				prev = int(tgt[k-1])
			}
			if !ok {
				continue
			}
			s := 0
			for _, v := range X[2:8] {
				s += v
			}
			if s != T {
				continue
			}
			// 第 1 轮：对初值 8 字节的 SAD（第 0 位被清零）
			lhs := absInt(int(c[0])) // abs(c[0] - 0)
			for i := 1; i < 8; i++ {
				lhs += absInt(int(c[i]) - X[i])
			}
			if lhs != int(tgt[0]) {
				continue
			}
			sol := make([]byte, 8)
			for i, v := range X {
				sol[i] = byte(v)
			}
			sols = append(sols, sol)
		}
	}
	return sols
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// mbrPick SAD 非单射消歧：唯一候选直取；多候选取唯一可打印者；仍不唯一 → nil。
func mbrPick(cands [][]byte) []byte {
	if len(cands) == 0 {
		return nil
	}
	if len(cands) == 1 {
		return cands[0]
	}
	var pr [][]byte
	for _, c := range cands {
		printable := true
		for _, b := range c {
			if b < 0x20 || b > 0x7E {
				printable = false
				break
			}
		}
		if printable {
			pr = append(pr, c)
		}
	}
	if len(pr) == 1 {
		return pr[0]
	}
	return nil
}

// mbrPshufdInverse dst dword 索引 → src dword 索引。
func mbrPshufdInverse(imm byte) []int {
	inv := make([]int, 4)
	for i := 0; i < 4; i++ {
		inv[i] = int(imm>>(2*i)) & 3
	}
	return inv
}

// solveMbrSse 主求解；无法唯一确定 → nil（保持诚实）。
func solveMbrSse(data []byte) []byte {
	ext := mbrExtract(data)
	if ext == nil || !mbrCheckMask(data, ext.maskAddr) {
		return nil
	}
	// edi = (lo<<16)|hi → 高 16 位为 lo，低 16 位为 hi
	loT := make([]uint32, 8)
	hiT := make([]uint32, 8)
	for k := 1; k <= 8; k++ {
		loT[k-1] = ext.exp[8-k] >> 16
		hiT[k-1] = ext.exp[8-k] & 0xFFFF
	}
	Hset := mbrSolveHalf(ext.init16[0:8], loT)
	Lset := mbrSolveHalf(ext.init16[8:16], hiT)
	H := mbrPick(Hset)
	L := mbrPick(Lset)
	if H == nil || L == nil {
		return nil
	}
	shuf := append(append([]byte{}, H...), L...) // shuf = [d2,d3,d1,d0] 语义
	inv := mbrPshufdInverse(ext.pshufdImm)
	for _, s := range inv {
		if s < 0 || s > 3 {
			return nil
		}
	}
	// pshufd 须为置换（有重复源 → 不可逆）
	seen := map[int]bool{}
	for _, s := range inv {
		if seen[s] {
			return nil
		}
		seen[s] = true
	}
	src := make([][]byte, 4)
	for i, s := range inv {
		src[s] = shuf[4*i : 4*i+4]
	}
	body := bytes.Join(src, nil)
	return append([]byte("flag"), body...)
}

// simulateMbrSse 完整 psadbw 链仿真复核（自检/测试用）。
func simulateMbrSse(data []byte, flag []byte) bool {
	ext := mbrExtract(data)
	if ext == nil {
		return false
	}
	if len(flag) != 20 || string(flag[:4]) != "flag" {
		return false
	}
	body := flag[4:20]
	inv := mbrPshufdInverse(ext.pshufdImm)
	shuf := make([]byte, 16)
	for i := 0; i < 4; i++ {
		copy(shuf[4*i:], body[4*inv[i]:4*inv[i]+4])
	}
	xmm5 := append([]byte{}, ext.init16...)
	for k := 1; k <= 8; k++ {
		M := append([]byte{}, shuf...)
		M[k-1] = 0
		M[k+7] = 0
		lo, hi := 0, 0
		for j := 0; j < 8; j++ {
			lo += absInt(int(xmm5[j]) - int(M[j]))
			hi += absInt(int(xmm5[j+8]) - int(M[j+8]))
		}
		xmm5 = []byte{byte(lo), byte(lo >> 8), 0, 0, 0, 0, 0, 0,
			byte(hi), byte(hi >> 8), 0, 0, 0, 0, 0, 0}
		if int(lo)<<16|int(hi) != int(ext.exp[8-k]) {
			return false
		}
	}
	return true
}

// tryMbrSse 注册表入口：512B MBR 触发门。
func tryMbrSse(text string, attachments map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range attachments {
		if !isMbrSseVerify([]byte(raw)) {
			continue
		}
		flag := solveMbrSse([]byte(raw))
		if flag == nil {
			continue
		}
		if !seen[string(flag)] {
			seen[string(flag)] = true
			out = append(out, string(flag))
		}
	}
	return out
}
