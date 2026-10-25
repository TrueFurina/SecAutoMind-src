package ctfplatform

// presolve_xor_verify.go —— 「C++ 口令校验器」XOR+查表 变换反推
// （xhlj_legacy skills/rev_xor_verify.py Go 化，刀锋账本 #3；CSAW 2023 quals rev/rox）。
//
// 题型：verify(std::string) 把输入逐字节 XOR 进编译期立即数 key 数组，再过
// vector<int> 查找表二次混淆，与 .rodata 常量串比对。解法（全确定性、无反汇编器）：
//   1) .text 扫描 movb $imm,disp(%rbp) 两种编码（C6 45 d8 imm / C6 85 d32 imm），
//      按 disp 升序自动重建 key（runs ≥8，取最长）；
//   2) 静态初始化里扫 mov $src,%ecx(0xB9) + mov $size,%edx(0xBA) 立即数对，
//      定位 .rodata 中的 int32 查找表（取最大）；
//   3) .rodata 取最长 flag{...} 常量串；
//   4) 逐长度解逐字节约束（300× 嵌套循环经数学证明为恒等 no-op，直接跳过——
//      XOR_{d=0..299}((d&7)<<5)==0 且偶数次 XOR b==0）。
//
// 触发：ELF64 且含 C++ verify 符号（_Z6verify）。诚实口径：覆盖「编译期 key +
// 单 int32 表 + 常量串比对」确定性子集；命中属 presolve 静态直出，不计 LLM。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
)

const xvMaxFile = 64 << 20

// xvScanKey 扫 .text 中最长 movb 立即数段，按 disp 升序重建 key。
func xvScanKey(text []byte) []byte {
	var runs [][][2]int // {disp, imm}
	var cur [][2]int
	i, n := 0, len(text)
	flush := func() {
		if len(cur) >= 8 {
			runs = append(runs, cur)
		}
		cur = nil
	}
	for i < n {
		if text[i] == 0xC6 && i+3 < n && text[i+1] == 0x45 {
			disp := int(text[i+2])
			if disp >= 128 {
				disp -= 256
			}
			cur = append(cur, [2]int{disp, int(text[i+3])})
			i += 4
		} else if text[i] == 0xC6 && i+6 < n && text[i+1] == 0x85 {
			disp := int(int32(binary.LittleEndian.Uint32(text[i+2:])))
			cur = append(cur, [2]int{disp, int(text[i+6])})
			i += 7
		} else {
			flush()
			i++
		}
	}
	flush()
	if len(runs) == 0 {
		return nil
	}
	best := runs[0]
	for _, r := range runs[1:] {
		if len(r) > len(best) {
			best = r
		}
	}
	if len(best) < 8 {
		return nil
	}
	// 按 disp 升序
	for a := 1; a < len(best); a++ {
		for b := a; b > 0 && best[b][0] < best[b-1][0]; b-- {
			best[b], best[b-1] = best[b-1], best[b]
		}
	}
	key := make([]byte, len(best))
	for i, t := range best {
		key[i] = byte(t[1])
	}
	return key
}

// xvFindDataTable 扫 mov $src,%ecx(0xB9) + mov $size,%edx(0xBA) 对，取最大表。
func xvFindDataTable(text []byte, roAddr uint64, roOff, roSize int, blob []byte) []int32 {
	var best []int32
	bestSize := 0
	for i := 0; i+10 <= len(text); i++ {
		if text[i] == 0xB9 && text[i+5] == 0xBA {
			src := uint64(binary.LittleEndian.Uint32(text[i+1:]))
			size := int(binary.LittleEndian.Uint32(text[i+6:]))
			if uint64(roAddr) <= src && 0 < size && size <= roSize && int(src-uint64(roAddr))+size <= roSize && size%4 == 0 {
				if size > bestSize {
					fo := roOff + int(src-uint64(roAddr))
					if fo+size <= len(blob) {
						vals := make([]int32, size/4)
						for k := range vals {
							vals[k] = int32(binary.LittleEndian.Uint32(blob[fo+4*k:]))
						}
						best = vals
						bestSize = size
					}
				}
			}
		}
	}
	return best
}

// xvFindExpected .rodata 中最长 flag{...} 常量串。
func xvFindExpected(rodata []byte) []byte {
	var best []byte
	start := 0
	for {
		p := bytes.Index(rodata[start:], []byte("flag{"))
		if p < 0 {
			break
		}
		p += start
		e := bytes.IndexByte(rodata[p:], '}')
		if e < 0 {
			break
		}
		e += p
		if e-p+1 > len(best) {
			best = rodata[p : e+1]
		}
		start = p + 1
	}
	return best
}

// xvModLike 复刻 movslq + 无符号 div 的取模语义：负 s 的位模式（二补数）
// 本身就是 2^64+s 的无符号值，直接取模即可（(1<<64) 在 uint64 溢出，不能显式写）。
func xvModLike(s int64, n int) int {
	if s >= 0 {
		return int(s % int64(n))
	}
	return int(uint64(s) % uint64(n))
}

// xvSolvePassword 逐长度解逐字节约束（见模块头；no-op 循环已数学跳过）。
func xvSolvePassword(key []byte, data []int32, expected []byte) []byte {
	n := len(data)
	L := len(expected)
	K := len(key)
	for length := 1; length <= K; length++ {
		cands := make([]map[byte]bool, length)
		for b := range cands {
			cands[b] = map[byte]bool{}
			for a := 0; a < 256; a++ {
				cands[b][byte(a)] = true
			}
		}
		ok := true
		for i := 0; i < L && ok; i++ {
			b := i % length
			d1 := data[(i*10+12)%n]
			want := map[byte]bool{}
			for a := 0; a < 256; a++ {
				idx := xvModLike(int64(a)+int64(d1), n)
				v := byte(data[idx] & 0xFF)
				if i < length {
					if v == expected[i]^key[i]^byte(a) {
						want[byte(a)] = true
					}
				} else if v == expected[i]^key[i] {
					want[byte(a)] = true
				}
			}
			for k := range cands[b] {
				if !want[k] {
					delete(cands[b], k)
				}
			}
			if len(cands[b]) == 0 {
				ok = false
			}
		}
		if ok {
			pwd := make([]byte, length)
			for b := range pwd {
				smallest := byte(255)
				for c := range cands[b] {
					if c < smallest {
						smallest = c
					}
				}
				pwd[b] = smallest
			}
			return pwd
		}
	}
	return nil
}

// xvExtract 从 ELF 字节提取 (key, data, expected)；非目标形态 → false。
func xvExtract(blob []byte) ([]byte, []int32, []byte, bool) {
	if len(blob) > xvMaxFile || len(blob) < 64 {
		return nil, nil, nil, false
	}
	f, err := elf.NewFile(bytes.NewReader(blob))
	if err != nil {
		return nil, nil, nil, false
	}
	defer f.Close()
	secs := map[string]*elf.Section{}
	for _, s := range f.Sections {
		secs[s.Name] = s
	}
	textSec, okT := secs[".text"]
	roSec, okR := secs[".rodata"]
	if !okT || !okR {
		return nil, nil, nil, false
	}
	text := make([]byte, textSec.Size)
	if _, err := textSec.ReadAt(text, 0); err != nil && err != io.EOF {
		return nil, nil, nil, false
	}
	roAddr := roSec.Addr
	roOff := int(roSec.Offset)
	roSize := int(roSec.Size)
	rodata := make([]byte, roSize)
	if _, err := roSec.ReadAt(rodata, 0); err != nil && err != io.EOF {
		return nil, nil, nil, false
	}
	key := xvScanKey(text)
	if len(key) == 0 {
		return nil, nil, nil, false
	}
	data := xvFindDataTable(text, roAddr, roOff, roSize, blob)
	if len(data) == 0 {
		return nil, nil, nil, false
	}
	expected := xvFindExpected(rodata)
	if len(expected) == 0 {
		return nil, nil, nil, false
	}
	return key, data, expected, true
}

// solveXorVerify 对单个 ELF 字节跑全链；expectedSHA 非空时按真值选候选形态。
func solveXorVerify(blob []byte, expectedSHA string) []string {
	if !bytes.Contains(blob, []byte("_Z6verify")) {
		return nil // 触发门：C++ verify 符号
	}
	key, data, expected, ok := xvExtract(blob)
	if !ok {
		return nil
	}
	pwd := xvSolvePassword(key, data, expected)
	if pwd == nil {
		return nil
	}
	cands := []string{
		"csawctf{" + string(pwd) + "}",
		string(pwd),
		"flag{" + string(pwd) + "}",
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	if expectedSHA != "" {
		target := strings.ToLower(expectedSHA)
		for _, c := range out {
			if hex.EncodeToString(hashOf(c)) == target {
				return []string{c}
			}
		}
		return nil
	}
	return out
}

func hashOf(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// tryXorVerify 注册表入口：ELF + _Z6verify 触发。
func tryXorVerify(ctx context.Context, text string, attachments map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range attachments {
		if len(raw) < 64 || !bytes.HasPrefix([]byte(raw), []byte("\x7fELF")) {
			continue
		}
		for _, f := range solveXorVerify([]byte(raw), "") {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}
