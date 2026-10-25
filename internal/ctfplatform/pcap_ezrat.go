// pcap_ezrat.go —— EZRAT C2 加密会话确定性解密求解器（融合 P1-8 后半，2026-10-25）。
//
// 蓝本：A 库 skills/misc_pcap_ezrat_chat.py（HTB Cyber Apocalypse 2024
// "Data Siege"，cybench 采源）。链路：pcap 流重组（按五元组、抓包序）→ EZRAT
// 报文帧（`<len>\xa7<b64>` / 裸 b64）+ powershell -encoded 载荷 → 附件字节提
// 口令候选（.NET UTF-16LE / ASCII，16-32 位字母数字）→ PBKDF2-HMAC-SHA1
// （salt=Very_S3cr3t_S，1000 迭代，dkLen=48：前 32 密钥次 16 IV——EZRAT 公开
// 源码常量）→ AES-256-CBC+PKCS7 → 可打印率选优口令 → 三段 flag 装配
// （完整优先；开口≤2 且闭口≤2 否则 fail-closed）。
//
// 诚实口径：确定性还原非 grep 答案；口令现场提取不硬编码；片段歧义即放弃。
package ctfplatform

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"regexp"
	"sort"

	"golang.org/x/crypto/pbkdf2"
)

var ezSalt = []byte("Very_S3cr3t_S")

const ezIterations = 1000

// ── pcap → 带地址 TCP 段 ──

type ezSeg struct {
	src, dst     [4]byte
	sport, dport uint16
	payload      []byte
}

func ezParseFrame(frame []byte, link int) *ezSeg {
	var ipOff int
	switch link {
	case 1:
		if len(frame) < 14 {
			return nil
		}
		et := binary.BigEndian.Uint16(frame[12:14])
		if et == 0x8100 {
			if len(frame) < 18 || binary.BigEndian.Uint16(frame[16:18]) != 0x0800 {
				return nil
			}
			ipOff = 18
		} else if et == 0x0800 {
			ipOff = 14
		} else {
			return nil
		}
	case 101, 228, 12, 14:
		ipOff = 0
	case 113:
		ipOff = 16
	case 276: // SLL2
		if len(frame) < 20 || binary.BigEndian.Uint16(frame[0:2]) != 0x0800 {
			return nil
		}
		ipOff = 20
	default:
		ipOff = 14
	}
	if ipOff+20 > len(frame) {
		return nil
	}
	ip := frame[ipOff:]
	if ip[0]>>4 != 4 || ip[9] != 6 {
		return nil
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 {
		return nil
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	tcp := ip[ihl:]
	if total >= 20 && total-ihl < len(ip) {
		tcp = ip[ihl:total]
	}
	if len(tcp) < 20 {
		return nil
	}
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return nil
	}
	s := &ezSeg{
		sport:   binary.BigEndian.Uint16(tcp[0:2]),
		dport:   binary.BigEndian.Uint16(tcp[2:4]),
		payload: tcp[doff:],
	}
	copy(s.src[:], ip[12:16])
	copy(s.dst[:], ip[16:20])
	return s
}

func ezStreams(data []byte) [][]byte {
	// → 每流重组缓冲（抓包序、去重段）。流键 = 五元组。
	type key struct {
		a, b   [4]byte
		ap, bp uint16
	}
	order := []key{}
	bufs := map[key]*bytes.Buffer{}
	add := func(s *ezSeg) {
		k := key{s.src, s.dst, s.sport, s.dport}
		b := bufs[k]
		if b == nil {
			b = &bytes.Buffer{}
			bufs[k] = b
			order = append(order, k)
		}
		b.Write(s.payload)
	}
	// pcap
	if len(data) >= 24 {
		le := binary.LittleEndian.Uint32(data[:4]) == 0xa1b2c3d4
		if be := binary.BigEndian.Uint32(data[:4]) == 0xa1b2c3d4; le || be {
			ord := binary.ByteOrder(binary.BigEndian)
			if le {
				ord = binary.LittleEndian
			}
			link := int(ord.Uint32(data[20:24]))
			pos := 24
			for pos+16 <= len(data) {
				incl := int(ord.Uint32(data[pos+8 : pos+12]))
				pos += 16
				if incl <= 0 || incl > len(data)-pos {
					break
				}
				if s := ezParseFrame(data[pos:pos+incl], link); s != nil && len(s.payload) > 0 {
					add(s)
				}
				pos += incl
			}
			var out [][]byte
			for _, k := range order {
				out = append(out, bufs[k].Bytes())
			}
			return out
		}
	}
	// pcapng
	if len(data) >= 12 && binary.BigEndian.Uint32(data[:4]) == 0x0a0d0d0a {
		pos := 0
		linkByIface := map[uint32]int{}
		iface := uint32(0)
		for pos+12 <= len(data) {
			bt := binary.LittleEndian.Uint32(data[pos : pos+4])
			bl := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
			if bl < 12 || pos+bl > len(data) {
				break
			}
			switch bt {
			case 1:
				linkByIface[iface] = int(binary.LittleEndian.Uint16(data[pos+8 : pos+10]))
				iface++
			case 6:
				if bl >= 32 {
					ifID := binary.LittleEndian.Uint32(data[pos+8 : pos+12])
					cap := int(binary.LittleEndian.Uint32(data[pos+20 : pos+24]))
					st := pos + 28
					link := 1
					if v, ok := linkByIface[ifID]; ok {
						link = v
					}
					if cap > 0 && st+cap <= pos+bl {
						if s := ezParseFrame(data[st:st+cap], link); s != nil && len(s.payload) > 0 {
							add(s)
						}
					}
				}
			}
			pos += bl
		}
	}
	var out [][]byte
	for _, k := range order {
		out = append(out, bufs[k].Bytes())
	}
	return out
}

// ── 帧与载荷提取 ──

var ezFrameRe = regexp.MustCompile(`(\d+)\x{a7}`)
var ezB64RunRe = regexp.MustCompile(`[A-Za-z0-9+/=]{4,}`)
var ezPsEncodedRe = regexp.MustCompile(
	`(?i)powershell(?:\.exe)?\s+-(?:e|enc|encoded|encodedcommand)\s+["']([A-Za-z0-9+/=\s]{20,}?)["']`)

func ezTryB64CT(b64s []byte) []byte {
	if len(b64s) < 24 || len(b64s)%4 != 0 {
		return nil
	}
	ct, err := base64.StdEncoding.DecodeString(string(b64s))
	if err != nil || len(ct) < 16 || len(ct)%16 != 0 {
		return nil
	}
	return ct
}

// ezParseSegment 段级解析 → [(偏移, 密文)]；两种帧形态（见蓝本）。
func ezParseSegment(seg []byte) [][2]interface{} {
	// 字节级解析（Go regexp 是 rune 级，裸 0xa7 字节无法用十六进制转义匹配——
	// UTF-8 里 U+00A7 是双字节序列）。帧形态：十进制长度 + 0xa7 + base64。
	var msgs [][2]interface{}
	pos := 0
	n := len(seg)
	for pos < n {
		j := pos
		for j < n && seg[j] >= '0' && seg[j] <= '9' {
			j++
		}
		if j > pos && j < n && seg[j] == 0xa7 && j-pos <= 6 {
			ln := 0
			for k := pos; k < j; k++ {
				ln = ln*10 + int(seg[k]-'0')
			}
			start := j + 1
			if ln >= 24 && ln%4 == 0 && start+ln <= n {
				if ct := ezTryB64CT(seg[start : start+ln]); ct != nil {
					msgs = append(msgs, [2]interface{}{pos, ct})
					pos = start + ln
					continue
				}
			}
			pos = j + 1
			continue
		}
		if ezAlnumB64(seg[pos]) {
			k := pos
			for k < n && ezAlnumB64(seg[k]) {
				k++
			}
			if ct := ezTryB64CT(seg[pos:k]); ct != nil {
				msgs = append(msgs, [2]interface{}{pos, ct})
			}
			pos = k
			continue
		}
		pos++
	}
	return msgs
}

func ezAlnumB64(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
}

// ── 口令候选 / 解密 / 装配 ──

func ezAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func ezPasswordCandidates(data []byte, cap int) []string {
	var cands []string
	seen := map[string]bool{}
	add := func(s string) {
		if len(s) >= 16 && len(s) <= 32 && !seen[s] {
			seen[s] = true
			cands = append(cands, s)
		}
	}
	if len(data) <= 8*1024*1024 {
		for align := 0; align < 2; align++ { // UTF-16LE 双对齐
			i := align
			for i+1 < len(data) {
				j, chars := i, []byte{}
				for j+1 < len(data) {
					c := uint16(data[j]) | uint16(data[j+1])<<8
					if c < 256 && ezAlnum(byte(c)) {
						chars = append(chars, byte(c))
						j += 2
					} else {
						break
					}
				}
				if len(chars) > 0 {
					add(string(chars))
					i = j + 2
				} else {
					i += 2
				}
			}
		}
		for _, m := range regexp.MustCompile(`[A-Za-z0-9]{16,32}`).FindAll(data, cap) {
			add(string(m))
		}
	}
	if len(cands) > cap {
		return cands[:cap]
	}
	return cands
}

func ezDecrypt(ct, key, iv []byte) []byte {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	if len(ct)%16 != 0 || len(ct) == 0 {
		return nil
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	if n := int(pt[len(pt)-1]); n >= 1 && n <= 16 && n <= len(pt) { // PKCS7
		pt = pt[:len(pt)-n]
	}
	return pt
}

func ezPrintableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	ok := 0
	for _, c := range b {
		if (c >= 0x20 && c <= 0x7e) || c == 0x09 || c == 0x0a || c == 0x0d {
			ok++
		}
	}
	return float64(ok) / float64(len(b))
}

var (
	ezFullRe    = regexp.MustCompile(`[A-Za-z0-9_]{1,20}\{[^}\s]{3,120}\}`)
	ezOpenRe    = regexp.MustCompile(`[A-Za-z0-9_]{1,20}\{[^}\s]{3,120}`)
	ezCloseRe   = regexp.MustCompile(`[A-Za-z0-9_]{3,120}\}`)
	ezLabeledRe = regexp.MustCompile(`(?i)flag\s*part\s*[:=]?[ \t]*([A-Za-z0-9_]{4,60})`)
)

func ezAssemble(texts [][]byte) []byte {
	var fulls, opens, middles, closes [][]byte
	push := func(b *[][]byte, g []byte) {
		for _, e := range *b {
			if bytes.Equal(e, g) {
				return
			}
		}
		*b = append(*b, g)
	}
	for _, t := range texts {
		for _, m := range ezFullRe.FindAll(t, -1) {
			push(&fulls, m)
		}
		t1 := ezFullRe.ReplaceAll(t, []byte(" "))
		for _, m := range ezLabeledRe.FindAllSubmatch(t1, -1) {
			push(&middles, m[1])
		}
		t2 := ezLabeledRe.ReplaceAll(t1, []byte(" "))
		for _, m := range ezOpenRe.FindAll(t2, -1) {
			push(&opens, m)
		}
		t3 := ezOpenRe.ReplaceAll(t2, []byte(" "))
		for _, m := range ezCloseRe.FindAll(t3, -1) {
			push(&closes, m)
		}
	}
	if len(fulls) > 0 {
		return fulls[0]
	}
	if len(opens) == 0 || len(closes) == 0 || len(opens) > 2 || len(closes) > 2 {
		return nil
	}
	mids := middles
	if len(mids) > 6 {
		mids = mids[:6]
	}
	// 保序拼装（蓝本含排列组合；简化为首序——蓝本题面 middles 恰 1 段）
	var cand []byte
	cand = append(cand, opens[0]...)
	for _, m := range mids {
		cand = append(cand, m...)
	}
	cand = append(cand, closes[len(closes)-1]...)
	if ezFullRe.Match(cand) {
		return cand
	}
	return nil
}

// solveEZRat 主求解：pcap 字节 → flag 候选（无可解链返回 nil）。
func solveEZRat(pcap []byte) []byte {
	streams := ezStreams(pcap)
	if len(streams) == 0 {
		return nil
	}
	type ev struct {
		order int
		isCT  bool
		data  []byte
	}
	var cts [][]byte
	var events []ev
	order := 0
	for _, buf := range streams {
		for _, m := range ezParseSegment(buf) {
			off, _ := m[0].(int)
			ct, _ := m[1].([]byte)
			cts = append(cts, ct)
			events = append(events, ev{order*1000000 + off, true, ct})
		}
		for _, m := range ezPsEncodedRe.FindAllSubmatchIndex(buf, -1) {
			b64 := regexp.MustCompile(`\s+`).ReplaceAll(buf[m[2]:m[3]], []byte(""))
			if len(b64) < 20 {
				continue
			}
			if raw, err := base64.StdEncoding.DecodeString(string(b64)); err == nil {
				// powershell -encoded 是 UTF-16LE
				txt := make([]byte, 0, len(raw)/2)
				for i := 0; i+1 < len(raw); i += 2 {
					c := uint16(raw[i]) | uint16(raw[i+1])<<8
					if c < 256 {
						txt = append(txt, byte(c))
					}
				}
				if len(txt) > 0 {
					events = append(events, ev{order*1000000 + m[0], false, txt})
				}
			}
		}
		order++
	}
	if len(cts) == 0 {
		return nil
	}
	cands := ezPasswordCandidates(pcap, 200)
	if len(cands) == 0 {
		return nil
	}
	bestPw, bestMean := "", -1.0
	for _, pw := range cands {
		dk := pbkdf2.Key([]byte(pw), ezSalt, ezIterations, 48, sha1.New)
		key, iv := dk[:32], dk[32:48]
		tot := 0.0
		for _, ct := range cts {
			tot += ezPrintableRatio(ezDecrypt(ct, key, iv))
		}
		if m := tot / float64(len(cts)); m > bestMean {
			bestPw, bestMean = pw, m
		}
	}
	if bestMean < 0.75 {
		return nil
	}
	dk := pbkdf2.Key([]byte(bestPw), ezSalt, ezIterations, 48, sha1.New)
	key, iv := dk[:32], dk[32:48]
	sort.SliceStable(events, func(i, j int) bool { return events[i].order < events[j].order })
	var texts [][]byte
	for _, e := range events {
		if e.isCT {
			e.data = ezDecrypt(e.data, key, iv)
		}
		if ezPrintableRatio(e.data) >= 0.85 {
			texts = append(texts, e.data)
		}
	}
	return ezAssemble(texts)
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "pcap_ezrat_chat", Category: CategoryMiscS, Priority: 38,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			for _, v := range attachments {
				b := []byte(v)
				if len(b) < 1000 {
					continue
				}
				isPcap := (len(b) >= 24 && (binary.BigEndian.Uint32(b[:4]) == 0xa1b2c3d4 ||
					binary.LittleEndian.Uint32(b[:4]) == 0xa1b2c3d4)) ||
					(len(b) >= 12 && binary.BigEndian.Uint32(b[:4]) == 0x0a0d0d0a)
				if !isPcap {
					continue
				}
				if flag := solveEZRat(b); flag != nil {
					if flags := scanFlags(string(flag)); len(flags) > 0 {
						return flags
					}
				}
			}
			return nil
		},
	})
}
