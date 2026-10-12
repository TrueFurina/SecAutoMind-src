// forensics_binary.go —— 真实二进制取证引擎（Binary Forensics eXtractor, bfx）
//
// 背景（诚实化纪律）：既有 presolve_forensics.go 里的 14 个「取证求解器」实际
// 只是关键词检测——看到描述里出现 "lsb"/"pcap"/"volatility" 就返回一句诊断提示
// （形如 "LSB 隐写：最低有效位隐写…"），并不解析任何字节。这类输出在
// flagLikeness 裁决下只得 1 分，不会造成假命中，但也意味着**零真实取证能力**。
//
// 本文件补齐真实能力层：直接对附件原始字节做解析与提取，且只返回
// flag 形状的命中（不像旧壳子那样返回诊断文本），可机验、可对齐 Python 侧。
//
// 覆盖：strings/编码变体、PNG LSB、PNG 文本块与尾部附加、JPEG 段、pcap(ng)
// HTTP 流量、ZIP 内层、文件雕刻（carving）、重复密钥 XOR 已知明文恢复。
//
// 安全与成本：单附件 8 MiB 上限、LSB 像素上限、XOR 爆破窗口上限，
// 全部只读、无外部命令、无网络。
package ctfplatform

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"image"
	"image/draw"
	"image/png"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	// bfxMaxBlobBytes 单个附件参与解析的体积上限（8 MiB）。
	bfxMaxBlobBytes = 8 << 20
	// bfxLSBMaxPixels LSB 提取的像素上限（超大图只取前 N 像素，flag 通常在前部）。
	bfxLSBMaxPixels = 400000
	// bfxLSBScanBytes LSB 位流重组后参与扫描的字节数上限。
	bfxLSBScanBytes = 8192
	// bfxXorCribMaxBytes XOR 已知明文爆破的输入上限。
	bfxXorCribMaxBytes = 1 << 18
	// bfxXorCribMaxOffset 明文起始偏移搜索上限（flag 一般在密文头部）。
	bfxXorCribMaxOffset = 256
	// bfxXorPlainWindow 解密后参与扫描的窗口。
	bfxXorPlainWindow = 4096
	// bfxInnerFileMaxBytes ZIP 内层单文件读取上限。
	bfxInnerFileMaxBytes = 4 << 20
)

// ─────────────────────────── 基础扫描与编码变体 ───────────────────────────

// bfxDedup 去重保序。
func bfxDedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// bfxScanRaw 在原始字节上直接匹配 flag 正则（等价于 scanFlags 的字节版）。
func bfxScanRaw(data []byte) []string {
	var out []string
	for _, m := range flagRegexPresolve.FindAll(data, -1) {
		if s := string(m); bfxCandidateClean(s) {
			out = append(out, s)
		}
	}
	for _, m := range flagRegexUppercase.FindAll(data, -1) {
		if s := string(m); bfxCandidateClean(s) {
			out = append(out, s)
		}
	}
	return bfxDedup(out)
}

// bfxCandidateClean 判断一个 flag 候选是否「干净」：不含任何控制字符
// （含 NUL/换行/TAB/DEL 及 0x80+ 非 ASCII）。随机解码字节抽出的
// 大写串{二进制} 外形必含控制字节，由此被丢弃，杜绝把噪声当 flag。
// 真 flag（flag{...} / FLAG{...} / picoCTF{...}）内容全程可打印，不受影响。
func bfxCandidateClean(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c >= 0x80 {
			return false
		}
	}
	return true
}

// bfxPrintableRuns 提取连续可打印串（长度≥minLen），模拟 strings 命令。
func bfxPrintableRuns(data []byte, minLen int) [][]byte {
	var runs [][]byte
	start := -1
	for i := 0; i <= len(data); i++ {
		ok := i < len(data) && data[i] >= 0x20 && data[i] < 0x7f
		switch {
		case ok && start < 0:
			start = i
		case !ok && start >= 0:
			if i-start >= minLen {
				runs = append(runs, data[start:i])
			}
			start = -1
		}
	}
	return runs
}

// bfxUTF16Variants 抽取 UTF-16LE/BE 宽字符串（等价 strings -e l / -e b）。
//
// 关键设计：不做「整块解码 + 比例判定」——那样一旦附件里混入随机字节
// （非 ASCII 码元过半）就会被整体否决，实测把真实的 UTF-16 flag 一起丢掉。
// 改为扫描 ASCII+NUL 交错区（宽字符特征），只把连续可打印区拼成文本。
func bfxUTF16Variants(data []byte) [][]byte {
	if len(data) < 8 {
		return nil
	}
	var out [][]byte
	out = append(out, bfxUTF16Runs(data, false)...)
	out = append(out, bfxUTF16Runs(data, true)...)
	return out
}

const bfxUTF16MinRun = 12

func bfxUTF16Runs(data []byte, bigEndian bool) [][]byte {
	var out [][]byte
	start := -1
	n := len(data) - 1
	for i := 0; i < n; i += 2 {
		var ascii byte
		if bigEndian {
			if data[i] == 0 {
				ascii = data[i+1]
			}
		} else {
			if data[i+1] == 0 {
				ascii = data[i]
			}
		}
		ok := ascii >= 0x20 && ascii < 0x7f
		switch {
		case ok && start < 0:
			start = i
		case !ok && start >= 0:
			if i-start >= bfxUTF16MinRun {
				out = append(out, bfxUTF16Collect(data[start:i], bigEndian))
			}
			start = -1
		}
	}
	if start >= 0 && n-start >= bfxUTF16MinRun {
		out = append(out, bfxUTF16Collect(data[start:n], bigEndian))
	}
	return out
}

func bfxUTF16Collect(d []byte, bigEndian bool) []byte {
	buf := make([]byte, 0, len(d)/2+1)
	for i := 0; i+1 < len(d); i += 2 {
		if bigEndian {
			buf = append(buf, d[i+1])
		} else {
			buf = append(buf, d[i])
		}
	}
	return buf
}

var (
	bfxB64Re = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)
	bfxHexRe = regexp.MustCompile(`(?:0x)?[0-9a-fA-F]{16,}`)
)

// bfxB64Decoded 从字节流中挑出 base64 令牌并解码（Std/URL/Raw 变体）。
func bfxB64Decoded(data []byte) [][]byte {
	var out [][]byte
	for _, m := range bfxB64Re.FindAll(data, 64) {
		s := strings.TrimRight(string(m), "=")
		if len(s) < 16 {
			continue
		}
		encs := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding}
		if len(s)%4 != 0 {
			encs = []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding}
		}
		for _, enc := range encs {
			if d, err := enc.DecodeString(s); err == nil && len(d) > 0 {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// bfxHexDecoded 从字节流中挑出 hex 令牌并解码。
func bfxHexDecoded(data []byte) [][]byte {
	var out [][]byte
	for _, m := range bfxHexRe.FindAll(data, 32) {
		s := strings.TrimPrefix(string(m), "0x")
		s = strings.TrimPrefix(s, "0X")
		if len(s)%2 != 0 {
			s = s[:len(s)-1]
		}
		if d, err := hex.DecodeString(s); err == nil && len(d) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// bfxScanVariants 对一段字节做「原始 + UTF-16 + base64 + hex + 逆序」全变体扫描。
func bfxScanVariants(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var out []string
	out = append(out, bfxScanRaw(data)...)
	for _, v := range bfxUTF16Variants(data) {
		out = append(out, bfxScanRaw(v)...)
	}
	for _, d := range bfxB64Decoded(data) {
		out = append(out, bfxScanRaw(d)...)
	}
	for _, d := range bfxHexDecoded(data) {
		out = append(out, bfxScanRaw(d)...)
	}
	// URL/百分号解码变体：HTTP 流量、日志、表单里的 flag 常被百分号编码
	// （如 flag%7B...%7D），不解码则正则永远扫不到。
	if bytes.Contains(data, []byte("%")) {
		if dec, err := url.QueryUnescape(string(data)); err == nil && dec != string(data) {
			out = append(out, bfxScanRaw([]byte(dec))...)
		}
	}
	if len(data) <= 1<<20 {
		rev := make([]byte, len(data))
		for i := range data {
			rev[i] = data[len(data)-1-i]
		}
		out = append(out, bfxScanRaw(rev)...)
	}
	return bfxDedup(out)
}

// bfxMostlyPrintable 判断明文窗口是否 Mostly 可打印（用于 XOR 爆破结果筛选）。
func bfxMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := len(b)
	if n > 512 {
		n = 512
	}
	ok := 0
	for i := 0; i < n; i++ {
		c := b[i]
		if c == 0x09 || c == 0x0a || c == 0x0d || (c >= 0x20 && c < 0x7f) {
			ok++
		}
	}
	return ok*10 >= n*9
}

// ─────────────────────────── PNG：LSB / 文本块 / 尾部 ───────────────────────────

type bfxLSBMode struct {
	chans    []int
	msbFirst bool
}

// bfxPNGLsb 真实 PNG LSB 隐写提取：解码像素、按多种位序/通道组合重组位流后扫 flag。
func bfxPNGLsb(data []byte) []string {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	b := img.Bounds()
	rgba, ok := img.(*image.RGBA)
	if !ok {
		rgba = image.NewRGBA(b)
		draw.Draw(rgba, b, img, b.Min, draw.Src)
	}
	px := rgba.Pix
	total := b.Dx() * b.Dy()
	if total > bfxLSBMaxPixels {
		total = bfxLSBMaxPixels
	}
	modes := []bfxLSBMode{
		{[]int{0, 1, 2}, true},
		{[]int{0, 1, 2}, false},
		{[]int{0}, true},
		{[]int{0}, false},
		{[]int{0, 1, 2, 3}, true},
		{[]int{3}, true},
	}
	var out []string
	wantBits := bfxLSBScanBytes * 8
	for _, m := range modes {
		avail := total * len(m.chans)
		nb := avail
		if nb > wantBits {
			nb = wantBits
		}
		if nb < 64 {
			continue
		}
		buf := make([]byte, (nb+7)/8)
		k := 0
	outer:
		for i := 0; i < total; i++ {
			base := i * 4
			for _, c := range m.chans {
				if k >= nb {
					break outer
				}
				bit := px[base+c] & 1
				if m.msbFirst {
					buf[k/8] |= bit << (7 - uint(k%8))
				} else {
					buf[k/8] |= bit << uint(k%8)
				}
				k++
			}
		}
		out = append(out, bfxScanVariants(buf)...)
	}
	return bfxDedup(out)
}

// bfxPNGMeta 解析 PNG 块：tEXt/iTXt/zTXt 元数据 + IEND 之后的尾部附加数据。
func bfxPNGMeta(data []byte) []string {
	if len(data) < 8 || !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		return nil
	}
	var out []string
	var texts []byte
	pos := 8
	for pos+12 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[pos:]))
		typ := string(data[pos+4 : pos+8])
		if length < 0 || length > len(data)-pos-12 {
			break
		}
		body := data[pos+8 : pos+8+length]
		switch typ {
		case "tEXt", "iTXt":
			texts = append(texts, body...)
			texts = append(texts, '\n')
		case "zTXt":
			if i := bytes.IndexByte(body, 0); i >= 0 && i+2 <= len(body) {
				if zr, err := zlib.NewReader(bytes.NewReader(body[i+2:])); err == nil {
					dec, _ := io.ReadAll(io.LimitReader(zr, 1<<20))
					_ = zr.Close()
					texts = append(texts, dec...)
					texts = append(texts, '\n')
				}
			}
		}
		pos += 12 + length
		if typ == "IEND" {
			if pos < len(data) {
				out = append(out, bfxScanVariants(data[pos:])...)
			}
			break
		}
	}
	if len(texts) > 0 {
		out = append(out, bfxScanVariants(texts)...)
	}
	return bfxDedup(out)
}

// bfxJPEGMeta 扫描 JPEG 注释段（COM/APPn）与 FFD9 之后的尾部附加数据。
func bfxJPEGMeta(data []byte) []string {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil
	}
	var out []string
	var texts []byte
	i := 2
	for i+4 <= len(data) {
		if data[i] != 0xFF {
			break
		}
		marker := data[i+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			i += 2
			continue
		}
		if marker == 0xD9 {
			if i+2 < len(data) {
				out = append(out, bfxScanVariants(data[i+2:])...)
			}
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[i+2:]))
		if segLen < 2 || i+2+segLen > len(data) {
			break
		}
		if marker == 0xFE || (marker >= 0xE0 && marker <= 0xEF) {
			texts = append(texts, data[i+4:i+2+segLen]...)
			texts = append(texts, '\n')
		}
		i += 2 + segLen
	}
	if len(texts) > 0 {
		out = append(out, bfxScanVariants(texts)...)
	}
	return bfxDedup(out)
}

// ─────────────────────────── pcap / pcapng 流量解析 ───────────────────────────

// bfxTCPPayload 按链路类型剥离 Ethernet/VLAN/RawIP/SLL/Loopback 与 IPv4+TCP 头，
// 返回 TCP 载荷。解析失败返回 nil。
func bfxTCPPayload(pkt []byte, link int) []byte {
	var ipOff int
	switch link {
	case 1: // Ethernet
		if len(pkt) < 14 {
			return nil
		}
		ethType := binary.BigEndian.Uint16(pkt[12:14])
		if ethType == 0x8100 { // VLAN
			if len(pkt) < 18 {
				return nil
			}
			if binary.BigEndian.Uint16(pkt[16:18]) != 0x0800 {
				return nil
			}
			ipOff = 18
		} else if ethType == 0x0800 {
			ipOff = 14
		} else {
			return nil
		}
	case 101, 228, 12, 14: // RAW IP
		ipOff = 0
	case 113: // Linux cooked capture
		ipOff = 16
	case 0: // NULL / loopback
		ipOff = 4
	default:
		ipOff = 14
	}
	if ipOff+20 > len(pkt) {
		return nil
	}
	ip := pkt[ipOff:]
	if ip[0]>>4 != 4 {
		return nil
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ip[9] != 6 {
		return nil // 仅处理 TCP
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	tcp := ip[ihl:]
	if totalLen >= 20 && totalLen-ihl < len(ip) {
		tcp = ip[ihl:totalLen]
	}
	if len(tcp) < 20 {
		return nil
	}
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return nil
	}
	return tcp[doff:]
}

// bfxPcapHTTP 解析 pcap / pcapng，抽取 TCP 载荷（HTTP 请求行/头/体）后扫 flag。
func bfxPcapHTTP(data []byte) []string {
	var out []string
	// ── pcap ──
	if len(data) >= 24 {
		magic := binary.BigEndian.Uint32(data[:4])
		le := binary.LittleEndian.Uint32(data[:4]) == 0xa1b2c3d4
		if magic == 0xa1b2c3d4 || le {
			var order binary.ByteOrder = binary.BigEndian
			if le {
				order = binary.LittleEndian
			}
			link := int(order.Uint32(data[20:24]))
			pos := 24
			for pos+16 <= len(data) {
				incl := int(order.Uint32(data[pos+8 : pos+12]))
				pos += 16
				if incl <= 0 || incl > len(data)-pos {
					break
				}
				pkt := data[pos : pos+incl]
				pos += incl
				if pl := bfxTCPPayload(pkt, link); len(pl) > 0 {
					out = append(out, bfxScanVariants(pl)...)
				}
			}
		}
	}
	// ── pcapng ──
	if len(data) >= 12 && binary.BigEndian.Uint32(data[:4]) == 0x0a0d0d0a {
		pos := 0
		linkByIface := map[uint32]int{}
		ifaceIdx := uint32(0)
		for pos+12 <= len(data) {
			btype := binary.LittleEndian.Uint32(data[pos : pos+4])
			blen := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
			if blen < 12 || pos+blen > len(data) {
				break
			}
			switch btype {
			case 0x00000001: // Interface Description Block
				if blen >= 12 {
					linkByIface[ifaceIdx] = int(binary.LittleEndian.Uint16(data[pos+8 : pos+10]))
					ifaceIdx++
				}
			case 0x00000006: // Enhanced Packet Block
				if blen >= 32 {
					ifID := binary.LittleEndian.Uint32(data[pos+8 : pos+12])
					capLen := int(binary.LittleEndian.Uint32(data[pos+20 : pos+24]))
					start := pos + 28
					if capLen > 0 && start+capLen <= pos+blen {
						pkt := data[start : start+capLen]
						link := 1
						if v, ok := linkByIface[ifID]; ok {
							link = v
						}
						if pl := bfxTCPPayload(pkt, link); len(pl) > 0 {
							out = append(out, bfxScanVariants(pl)...)
						}
					}
				}
			}
			pos += blen
		}
	}
	return bfxDedup(out)
}

// ─────────────────────────── ZIP 内层与文件雕刻 ───────────────────────────

// bfxZipInner 打开 ZIP 附件，逐个读取内层文件并扫描（支持嵌套一层）。
func bfxZipInner(data []byte, depth int) []string {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || depth > 2 {
		return nil
	}
	var out []string
	for _, f := range zr.File {
		if len(out) > 32 {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			out = append(out, bfxScanRaw([]byte(f.Name))...)
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, bfxInnerFileMaxBytes))
		rc.Close()
		if err != nil {
			continue
		}
		out = append(out, bfxScanVariants(content)...)
		out = append(out, bfxScanRaw([]byte(f.Name))...)
		lower := strings.ToLower(f.Name)
		if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".apk") || strings.HasSuffix(lower, ".docx") {
			out = append(out, bfxZipInner(content, depth+1)...)
		}
	}
	return bfxDedup(out)
}

// bfxCarveMagics 常见文件魔数（用于雕刻嵌入文件）。
var bfxCarveMagics = []struct {
	sig  []byte
	kind string
}{
	{[]byte("PK\x03\x04"), "zip"},
	{[]byte("\x89PNG\r\n\x1a\n"), "png"},
	{[]byte("\xff\xd8\xff"), "jpeg"},
	{[]byte("GIF87a"), "raw"},
	{[]byte("GIF89a"), "raw"},
	{[]byte("%PDF-"), "raw"},
	{[]byte("\x1f\x8b\x08"), "gzip"},
	{[]byte("Rar!\x1a\x07"), "raw"},
	{[]byte("7z\xbc\xaf\x27\x1c"), "raw"},
}

// bfxCarve 在字节流中搜索嵌入文件魔数并解析（offset 0 跳过——主文件由对应求解器处理）。
func bfxCarve(data []byte) []string {
	if len(data) < 32 {
		return nil
	}
	var out []string
	for _, m := range bfxCarveMagics {
		from := 1
		found := 0
		for found < 4 {
			idx := bytes.Index(data[from:], m.sig)
			if idx < 0 {
				break
			}
			off := from + idx
			from = off + len(m.sig)
			found++
			rest := data[off:]
			if len(rest) > bfxMaxBlobBytes {
				rest = rest[:bfxMaxBlobBytes]
			}
			switch m.kind {
			case "zip":
				out = append(out, bfxZipInner(rest, 1)...)
			case "png":
				out = append(out, bfxPNGMeta(rest)...)
				out = append(out, bfxScanVariants(rest[:min(len(rest), 1<<20)])...)
			case "jpeg":
				out = append(out, bfxJPEGMeta(rest)...)
			default:
				out = append(out, bfxScanVariants(rest[:min(len(rest), 1<<20)])...)
			}
		}
	}
	return bfxDedup(out)
}

// ─────────────────────────── XOR 已知明文密钥恢复 ───────────────────────────

// bfxXorCrib 对重复密钥 XOR 做已知明文（crib）密钥恢复：
// 用 "flag{" 等前缀在若干偏移上推导周期 1..8 的密钥，解出明文后扫 flag。
// 说明：一次性随机密钥（密钥长度=明文长度）数学上不可恢复，本函数不覆盖，
// 这与 wolvctf2024_xor 的诚实结论一致，不做任何注水。
func bfxXorCrib(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	if len(data) > bfxXorCribMaxBytes {
		data = data[:bfxXorCribMaxBytes]
	}
	cribs := []string{"flag{", "picoCTF{", "ctf{", "CTF{", "FLAG{"}
	var out []string
	maxOffset := bfxXorCribMaxOffset
	if maxOffset > len(data) {
		maxOffset = len(data)
	}
	for period := 1; period <= 8; period++ {
		for _, crib := range cribs {
			cb := []byte(crib)
			// 周期长于已知明文时无法唯一确定密钥（且会读越界），直接跳过。
			if period > len(cb) {
				continue
			}
			for off := 0; off < maxOffset; off++ {
				if off+len(cb) > len(data) {
					break
				}
				key := make([]byte, period)
				for i := 0; i < period; i++ {
					key[i] = data[off+i] ^ cb[i%len(cb)]
				}
				ok := true
				for i := period; i < len(cb); i++ {
					if data[off+i]^key[i%period] != cb[i] {
						ok = false
						break
					}
				}
				if !ok {
					continue
				}
				n := len(data) - off
				if n > bfxXorPlainWindow {
					n = bfxXorPlainWindow
				}
				plain := make([]byte, n)
				for i := 0; i < n; i++ {
					plain[i] = data[off+i] ^ key[i%period]
				}
				if !bfxMostlyPrintable(plain) {
					continue
				}
				out = append(out, bfxScanVariants(plain)...)
			}
		}
	}
	return bfxDedup(out)
}

// ─────────────────────────── 附件驱动与求解器注册 ───────────────────────────

// bfxRun 遍历附件（确定性排序），对每个附件执行 fn，汇总去重后的 flag 命中。
func bfxRun(attachments map[string]string, fn func(name string, data []byte) []string) []string {
	if len(attachments) == 0 {
		return nil
	}
	names := make([]string, 0, len(attachments))
	for n := range attachments {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		raw := attachments[n]
		if len(raw) == 0 || len(raw) > bfxMaxBlobBytes {
			continue
		}
		if r := fn(n, []byte(raw)); len(r) > 0 {
			out = append(out, r...)
		}
	}
	return bfxDedup(out)
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "bin_strings", Category: CategoryMiscS, Priority: 30,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return bfxRun(attachments, func(_ string, d []byte) []string {
				return bfxScanVariants(d)
			})
		},
	})
	RegisterSolver(SolverEntry{
		Name: "bin_png_lsb", Category: CategoryMiscS, Priority: 31,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return bfxRun(attachments, func(_ string, d []byte) []string {
				return bfxPNGLsb(d)
			})
		},
	})
	RegisterSolver(SolverEntry{
		Name: "bin_png_meta", Category: CategoryMiscS, Priority: 32,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return bfxRun(attachments, func(_ string, d []byte) []string {
				var out []string
				out = append(out, bfxPNGMeta(d)...)
				out = append(out, bfxJPEGMeta(d)...)
				return bfxDedup(out)
			})
		},
	})
	RegisterSolver(SolverEntry{
		Name: "bin_pcap_http", Category: CategoryMiscS, Priority: 33,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return bfxRun(attachments, func(_ string, d []byte) []string {
				return bfxPcapHTTP(d)
			})
		},
	})
	RegisterSolver(SolverEntry{
		Name: "bin_zip_inner", Category: CategoryMiscS, Priority: 34,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return bfxRun(attachments, func(_ string, d []byte) []string {
				return bfxZipInner(d, 0)
			})
		},
	})
	RegisterSolver(SolverEntry{
		Name: "bin_carve", Category: CategoryMiscS, Priority: 35,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return bfxRun(attachments, func(_ string, d []byte) []string {
				return bfxCarve(d)
			})
		},
	})
	RegisterSolver(SolverEntry{
		Name: "bin_xor_crib", Category: CategoryCryptoS, Priority: 36,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			return bfxRun(attachments, func(_ string, d []byte) []string {
				return bfxXorCrib(d)
			})
		},
	})
}
