package ctfplatform

// presolve_deflate_stego.go —— DEFLATE 动态 Huffman 树隐码确定性求解器
// （西湖论剑 misc_deflate_huffman_flag 链 Go 化，吞并路线图 P1 备选→本账本 #1）。
//
// 参考：data/ctf_benchmark/xhlj_legacy/skills/misc_deflate_huffman_flag.py
// （Google CTF 2021「David and the Tree」lipogram 形态）+ 同名 python 测试
// （合成夹具 _synth_zip，testdata/xhlj_deflate_stego.zip 即其产物）。
//
// 链：ZIP → 逐条目 raw deflate → RFC 1951 动态块头（HLIT/HDIST/HCLEN → CLCL →
// 码长 Huffman → litlen 码长）→ 符号 69('E') 的规范码 → &0xFF + 8 位逆序 → 字符。
// 防误报双守卫（缺一不可，fail-closed）：lipogram E 占比 ≤1e-3 + E 码长 ≤9。
//
// Go 侧无 compress/flate 的码表暴露，故位级解析自实现（纯 stdlib）。

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"strings"
)


const (
	deflESymbol    = 69   // 隐写符号 'E'
	deflERatioMax  = 1e-3 // lipogram 判定：解压文本 E 占比上限
	deflECodeMax   = 9    // E 码长上限（人工树指纹）
	deflMinEntries = 4    // flag 至少 4 字符
	deflMaxZip     = 32 << 20
)

// deflBitReader DEFLATE 位流：每字节 LSB first（RFC 1951 §3.1.1）。
type deflBitReader struct {
	data []byte
	pos  uint
}

func (b *deflBitReader) read(n uint) int {
	v := 0
	for i := uint(0); i < n; i++ {
		if b.pos>>3 >= uint(len(b.data)) {
			return 0 // 越界按 0 读（fail-closed 由上层结构校验兜底）
		}
		v |= int((b.data[b.pos>>3]>>(b.pos&7))&1) << i
		b.pos++
	}
	return v
}

// deflBuildCodes RFC 1951 §3.2.2 规范码分配（lengths[sym]=0 表示无码）。
func deflBuildCodes(lengths []int) []int {
	maxLen := 0
	for _, l := range lengths {
		if l > maxLen {
			maxLen = l
		}
	}
	blCount := make([]int, maxLen+1)
	for _, l := range lengths {
		if l > 0 {
			blCount[l]++
		}
	}
	nextCode := make([]int, maxLen+2)
	code := 0
	for bits := 1; bits <= maxLen; bits++ {
		code = (code + blCount[bits-1]) << 1
		nextCode[bits] = code
	}
	codes := make([]int, len(lengths))
	for s, l := range lengths {
		if l > 0 {
			codes[s] = nextCode[l]
			nextCode[l]++
		}
	}
	return codes
}

// deflDecodeSymbol 逐位读入匹配规范码；16 位内不中 → 流损坏。
func deflDecodeSymbol(br *deflBitReader, table map[[2]int]int) int {
	code := 0
	for l := 1; l < 16; l++ {
		code |= br.read(1)
		if hit, ok := table[[2]int{l, code}]; ok {
			return hit
		}
		code <<= 1
	}
	return -1
}

var deflCLCLOrder = [19]int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

// deflParseDynamicLitlen 解析动态块头，返回 litlen 码长表（截去 dist 段）。
func deflParseDynamicLitlen(br *deflBitReader) ([]int, bool) {
	hlit := br.read(5) + 257
	hdist := br.read(5) + 1
	hclen := br.read(4) + 4
	clLen := make([]int, 19)
	for i := 0; i < hclen; i++ {
		clLen[deflCLCLOrder[i]] = br.read(3)
	}
	clTable := map[[2]int]int{}
	for s, l := range clLen {
		if l > 0 {
			clTable[[2]int{l, deflBuildCodes(clLen)[s]}] = s
		}
	}
	lengths := make([]int, 0, hlit+hdist)
	need := hlit + hdist
	for len(lengths) < need {
		sym := deflDecodeSymbol(br, clTable)
		if sym < 0 {
			return nil, false
		}
		switch {
		case sym < 16:
			lengths = append(lengths, sym)
		case sym == 16:
			if len(lengths) == 0 {
				return nil, false
			}
			rep := 3 + br.read(2)
			for i := 0; i < rep; i++ {
				lengths = append(lengths, lengths[len(lengths)-1])
			}
		case sym == 17:
			lengths = append(lengths, make([]int, 3+br.read(3))...)
		default: // 18
			lengths = append(lengths, make([]int, 11+br.read(7))...)
		}
		if len(lengths) > need+138 {
			return nil, false // 病态膨胀保护
		}
	}
	return lengths[:hlit], true
}

func deflReverse8(v int) int {
	r := 0
	for i := 0; i < 8; i++ {
		r = (r << 1) | (v & 1)
		v >>= 1
	}
	return r
}

// deflECharFromDeflate 从一条 deflate 流提取隐写字符；非动态块/无 E 码 → 0。
func deflECharFromDeflate(deflate []byte) int {
	br := &deflBitReader{data: deflate}
	for {
		bfinal := br.read(1)
		btype := br.read(2)
		switch btype {
		case 2:
			litlen, ok := deflParseDynamicLitlen(br)
			if !ok || len(litlen) <= deflESymbol {
				return 0
			}
			if l := litlen[deflESymbol]; l > 0 && l <= deflECodeMax {
				return deflReverse8(deflBuildCodes(litlen)[deflESymbol] & 0xFF)
			}
			return 0
		case 0:
			br.pos = (br.pos + 7) &^ 7 // 跳到字节边界
			ln := br.read(16)
			br.read(16) // NLEN（宽松跳过）
			br.pos += 8 * uint(ln)
		default:
			return 0 // fixed 块无法跳过
		}
		if bfinal != 0 || (br.pos>>3) >= uint(len(deflate)) {
			return 0
		}
	}
}

func deflERatio(text []byte) float64 {
	if len(text) == 0 {
		return 0
	}
	e := 0
	for _, b := range text {
		if b == 'E' || b == 'e' {
			e++
		}
	}
	return float64(e) / float64(len(text))
}

// deflZipStreams ZIP → 逐条目 raw deflate（EOCD → 中央目录权威，对 bit-3
// data descriptor 形态稳健）。任何结构不一致 → nil（fail-closed）。
func deflZipStreams(data []byte) [][]byte {
	eocd := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if eocd < 0 || eocd+22 > len(data) {
		return nil
	}
	ntot := int(binary.LittleEndian.Uint16(data[eocd+10:]))
	cdOff := int(binary.LittleEndian.Uint32(data[eocd+16:]))
	if ntot == 0 || cdOff <= 0 || cdOff >= len(data) {
		return nil
	}
	out := make([][]byte, 0, ntot)
	off := cdOff
	for i := 0; i < ntot; i++ {
		if off+46 > len(data) || string(data[off:off+4]) != "PK\x01\x02" {
			return nil
		}
		method := binary.LittleEndian.Uint16(data[off+10:])
		csz := int(binary.LittleEndian.Uint32(data[off+20:]))
		nlen := int(binary.LittleEndian.Uint16(data[off+28:]))
		elen := int(binary.LittleEndian.Uint16(data[off+30:]))
		clen := int(binary.LittleEndian.Uint16(data[off+32:]))
		lh := int(binary.LittleEndian.Uint32(data[off+42:]))
		off += 46 + nlen + elen + clen
		if method != 8 || csz == 0 {
			return nil // 拼装语义：每条目都须承载码
		}
		if lh+30 > len(data) || string(data[lh:lh+4]) != "PK\x03\x04" {
			return nil
		}
		lnlen := int(binary.LittleEndian.Uint16(data[lh+26:]))
		lelen := int(binary.LittleEndian.Uint16(data[lh+28:]))
		start := lh + 30 + lnlen + lelen
		if start+csz > len(data) {
			return nil
		}
		out = append(out, data[start:start+csz])
	}
	return out
}

// solveDeflateStego ZIP 字节 → flag 字符串；非目标形态 → nil（不崩不谎报）。
func solveDeflateStego(data []byte) string {
	if len(data) < 4 || len(data) > deflMaxZip {
		return ""
	}
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) && !bytes.HasPrefix(data, []byte("PK\x05\x06")) {
		return ""
	}
	entries := deflZipStreams(data)
	if len(entries) < deflMinEntries {
		return ""
	}
	var sb strings.Builder
	for _, ds := range entries {
		// 守卫①：lipogram（raw deflate 无 zlib 头 → flate.NewReader 即 raw 口径）
		fr := flate.NewReader(bytes.NewReader(ds))
		text, err := io.ReadAll(fr)
		fr.Close()
		if err != nil || deflERatio(text) > deflERatioMax {
			return ""
		}
		// 守卫② + 提取：E 码须存在且为人工短码
		ch := deflECharFromDeflate(ds)
		if ch < 0x20 || ch > 0x7E {
			return ""
		}
		sb.WriteByte(byte(ch))
	}
	flag := sb.String()
	if len(flag) < deflMinEntries {
		return ""
	}
	return flag
}

// tryDeflateStego 求解器入口：附件为 ZIP 且过双守卫时返回隐写 flag。
// 形态把关在下游（真值锚/答案校验）——合成口径 flag 形态各异（SCF{…} 等），
// 此处不做 flag 正则门（与 python 版 solve 一致）。
func tryDeflateStego(text string, attachments map[string]string) []string {
	for _, raw := range attachments {
		if len(raw) < 4 || (!strings.HasPrefix(raw, "PK\x03\x04") && !strings.HasPrefix(raw, "PK\x05\x06")) {
			continue
		}
		if flag := solveDeflateStego([]byte(raw)); flag != "" {
			return []string{flag}
		}
	}
	return nil
}
