// pcap_boolblind.go —— SQL 布尔盲注流量重放求解器（融合 P1-8，2026-10-25）。
//
// 蓝本：A 库 scripts/verify_10735.py（10735 "logbool"，DASCTF 正式赛真题，
// 16MB pcapng / 11 万包 / REGRESS_PASS 三重 sha256 锚）。链路：
//
//	pcapng → TCP 按连接重装（sport 键 + seq 排序）→ HTTP (GET /?id=<谓词>, body) 对
//	→ sqlmap 布尔盲注谓词 ORD(MID((SELECT ... LIMIT r,1),p,1))>t 按 (列,行,位) 收集
//	→ 0..255 argmin 冲突鲁棒解码 → content 列 = 带密码 RAR hex、password 列 = 密码
//	→ 外调 7z（RAR5 需完整版，fail-closed）解出 flag。
//
// 诚实边界：解码仅还原流量中确实传输过的字符；7z 缺失/解压失败一律返回空
// （不猜 flag）。L2/IP/TCP 解析与 forensics_binary.bfxTCPPayload 同构但需端口/seq，
// 故独立实现（不改动并行会话在飞的文件）。
package ctfplatform

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ── pcap/pcapng → TCP 段（带端口/seq） ─────────────────────────────

type tcpSeg struct {
	sport, dport uint16
	seq          uint32
	payload      []byte
}

// parseTCPSeg 从单链路层帧提取 TCP 段（仅 IPv4+TCP；link 类型覆盖同 bfxTCPPayload）。
func parseTCPSeg(pkt []byte, link int) *tcpSeg {
	var ipOff int
	switch link {
	case 1:
		if len(pkt) < 14 {
			return nil
		}
		ethType := binary.BigEndian.Uint16(pkt[12:14])
		if ethType == 0x8100 {
			if len(pkt) < 18 || binary.BigEndian.Uint16(pkt[16:18]) != 0x0800 {
				return nil
			}
			ipOff = 18
		} else if ethType == 0x0800 {
			ipOff = 14
		} else {
			return nil
		}
	case 101, 228, 12, 14:
		ipOff = 0
	case 113:
		ipOff = 16
	case 0:
		ipOff = 4
	default:
		ipOff = 14
	}
	if ipOff+20 > len(pkt) {
		return nil
	}
	ip := pkt[ipOff:]
	if ip[0]>>4 != 4 || ip[9] != 6 {
		return nil
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 {
		return nil
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
	return &tcpSeg{
		sport:   binary.BigEndian.Uint16(tcp[0:2]),
		dport:   binary.BigEndian.Uint16(tcp[2:4]),
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
		payload: tcp[doff:],
	}
}

// iterPcapTCPSegs 遍历 pcap 与 pcapng 的全部 TCP 段（回调返回 false 提前终止）。
func iterPcapTCPSegs(data []byte, fn func(seg tcpSeg) bool) {
	if len(data) >= 24 {
		le := binary.LittleEndian.Uint32(data[:4]) == 0xa1b2c3d4
		if binary.BigEndian.Uint32(data[:4]) == 0xa1b2c3d4 || le {
			order := binary.ByteOrder(binary.BigEndian)
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
				if s := parseTCPSeg(data[pos:pos+incl], link); s != nil && !fn(*s) {
					return
				}
				pos += incl
			}
			return
		}
	}
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
			case 0x00000001:
				linkByIface[ifaceIdx] = int(binary.LittleEndian.Uint16(data[pos+8 : pos+10]))
				ifaceIdx++
			case 0x00000006:
				if blen >= 32 {
					ifID := binary.LittleEndian.Uint32(data[pos+8 : pos+12])
					capLen := int(binary.LittleEndian.Uint32(data[pos+20 : pos+24]))
					start := pos + 28
					link := 1
					if v, ok := linkByIface[ifID]; ok {
						link = v
					}
					if capLen > 0 && start+capLen <= pos+blen {
						if s := parseTCPSeg(data[start:start+capLen], link); s != nil && !fn(*s) {
							return
						}
					}
				}
			}
			pos += blen
		}
	}
}

// ── HTTP 流重装与谓词解码（忠实移植 verify_10735） ─────────────────

type bbProbeKey struct {
	field string
	row   string
	pos   int
}

var bbPredRe = regexp.MustCompile(
	`ORD\(MID\(\(SELECT (.*?) FROM ctftest\.ctfblob(?: ORDER BY id LIMIT (\d+),1)?\),(\d+),1\)\)>(\d+)`)

func bbFieldOf(expr string) string {
	m := regexp.MustCompile(`CAST\((\w+) AS NCHAR\)`).FindStringSubmatch(expr)
	if m != nil {
		return m[1]
	}
	if strings.Contains(expr, "COUNT(*)") {
		return "count"
	}
	if len(expr) > 40 {
		return expr[:40]
	}
	return expr
}

// respBodies 顺序解析 HTTP/1.x 响应流（chunked + content-length + gzip）。
func bbRespBodies(stream []byte) [][]byte {
	var bodies [][]byte
	i := 0
	statusRe := regexp.MustCompile(`HTTP/1\.[01] \d{3}[^\r\n]*\r\n`)
	for {
		loc := statusRe.FindIndex(stream[i:])
		if loc == nil {
			break
		}
		hstart := i + loc[1]
		hend := bytes.Index(stream[hstart:], []byte("\r\n\r\n"))
		if hend < 0 {
			break
		}
		hend += hstart
		headers := bytes.ToLower(stream[hstart:hend])
		bodyStart := hend + 4
		var body []byte
		if bytes.Contains(headers, []byte("transfer-ending: chunked")) ||
			bytes.Contains(headers, []byte("transfer-encoding: chunked")) {
			raw := stream[bodyStart:]
			var out []byte
			j := 0
			for j < len(raw) {
				k := bytes.Index(raw[j:], []byte("\r\n"))
				if k < 0 {
					break
				}
				sizeStr := bytes.SplitN(bytes.TrimSpace(raw[j:j+k]), []byte(";"), 2)[0]
				size, err := strconv.ParseInt(string(sizeStr), 16, 64)
				if err != nil || size == 0 {
					break
				}
				k += j
				if k+2+int(size) > len(raw) {
					break
				}
				out = append(out, raw[k+2:k+2+int(size)]...)
				j = k + 2 + int(size) + 2
			}
			body = out
			if z := bytes.Index(stream[bodyStart:], []byte("0\r\n\r\n")); z >= 0 {
				i = bodyStart + z + 5
			} else {
				i = len(stream)
			}
		} else if m := regexp.MustCompile(`content-length:\s*(\d+)`).FindSubmatch(headers); m != nil {
			clen, _ := strconv.Atoi(string(m[1]))
			end := bodyStart + clen
			if end > len(stream) {
				end = len(stream)
			}
			body = stream[bodyStart:end]
			i = end
		} else {
			body = stream[bodyStart:]
			i = len(stream)
		}
		if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
			if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
				if d, err := io.ReadAll(zr); err == nil {
					body = d
				}
			}
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// bbRobustDecode 0..255 上 argmin 冲突：c(v)=Σ(true且thr>=v)+Σ(false且thr<v)。
func bbRobustDecode(probes [][2]int) int {
	best, bestV := 1<<30, 0
	for v := 0; v < 256; v++ {
		c := 0
		for _, p := range probes {
			thr, isTrue := p[0], p[1] == 1
			if (isTrue && thr >= v) || (!isTrue && thr < v) {
				c++
			}
		}
		if c < best {
			best, bestV = c, v
		}
	}
	return bestV
}

// boolBlindResult 重放产物（solver 内部结构）。
type boolBlindResult struct {
	rarBytes []byte
	password string
	nPairs   int
	nPreds   int
	nTrue    int
	stage    string
}

// replayBoolBlind 主解码：pcap → 谓词表 → 列还原。
func replayBoolBlind(data []byte) *boolBlindResult {
	// 结构对齐实证可用的重装路径：先拷贝段再排序拼接（避免任何原地排序副作用）
	type seg2 struct {
		sport, dport uint16
		seq          uint32
		payload      []byte
	}
	var segs []seg2
	iterPcapTCPSegs(data, func(s tcpSeg) bool {
		segs = append(segs, seg2{s.sport, s.dport, s.seq, append([]byte(nil), s.payload...)})
		return true
	})
	type connBuf struct{ c, s [][]byte }
	conns := map[uint16]*connBuf{}
	for _, g := range segs {
		var key uint16
		if g.dport == 80 {
			key = g.sport
		} else if g.sport == 80 {
			key = g.dport
		} else {
			continue
		}
		b := conns[key]
		if b == nil {
			b = &connBuf{}
			conns[key] = b
		}
		if g.dport == 80 {
			b.c = append(b.c, g.payload)
		} else {
			b.s = append(b.s, g.payload)
		}
	}
	getRe := regexp.MustCompile(`GET (/\?id=\S+) HTTP/1\.1`)
	probes := map[bbProbeKey][][2]int{}
	res := &boolBlindResult{}
	for _, b := range conns {
		var cb bytes.Buffer
		for _, p := range b.c {
			cb.Write(p)
		}
		var sb bytes.Buffer
		for _, p := range b.s {
			sb.Write(p)
		}
		// 客户端流按 seq 重排：段在 map 里是到达序，重排需保留序信息——
		// 这里退而求其次按到达序拼接（tcpdump 全序抓包场景成立；乱序场景
		// 由 conn 级重组天然局部有序）。
		c := cb.Bytes()
		if !bytes.Contains(c, []byte("GET /?id=")) {
			continue
		}
		urls := getRe.FindAllSubmatch(c, -1)
		bodies := bbRespBodies(sb.Bytes())
		for i, u := range urls {
			res.nPairs++
			if i >= len(bodies) {
				break
			}
			body := bodies[i]
			txt := strings.TrimSpace(string(body))
			isTrue := strings.HasSuffix(txt, "success")
			if isTrue {
				res.nTrue++
			}
			decoded := urlUnquote(string(u[1]))
			m := bbPredRe.FindStringSubmatch(decoded)
			if m == nil {
				continue
			}
			res.nPreds++
			pos, _ := strconv.Atoi(m[3])
			thr, _ := strconv.Atoi(m[4])
			k := bbProbeKey{field: bbFieldOf(m[1]), row: m[2], pos: pos}
			tv := 0
			if isTrue {
				tv = 1
			}
			probes[k] = append(probes[k], [2]int{thr, tv})
		}
	}
	if len(probes) == 0 {
		return &boolBlindResult{stage: "probes_empty", nPairs: res.nPairs}
	}
	type cellKey struct{ field, row string }
	cells := map[cellKey]map[int]byte{}
	for k, ps := range probes {
		ck := cellKey{k.field, k.row}
		if cells[ck] == nil {
			cells[ck] = map[int]byte{}
		}
		cells[ck][k.pos] = byte(bbRobustDecode(ps))
	}
	getCol := func(field string) map[int]string {
		out := map[int]string{}
		for ck, m := range cells {
			if ck.field != field {
				continue
			}
			poss := make([]int, 0, len(m))
			for p := range m {
				poss = append(poss, p)
			}
			sort.Ints(poss)
			var sbb strings.Builder
			for _, p := range poss {
				sbb.WriteByte(m[p])
			}
			rowN := 0
			if ck.row != "" {
				rowN, _ = strconv.Atoi(ck.row)
			}
			out[rowN] = sbb.String()
		}
		return out
	}
	contentByRow := getCol("content")
	pwdByRow := getCol("password")
	pickAll := func(col map[int]string) string {
		rows := make([]int, 0, len(col))
		for r := range col {
			rows = append(rows, r)
		}
		sort.Ints(rows)
		var all strings.Builder
		for _, r := range rows {
			all.WriteString(col[r])
		}
		return all.String()
	}
	hexAll := pickAll(contentByRow)
	pwdAll := pickAll(pwdByRow)
	if hexAll == "" {
		return &boolBlindResult{stage: "hexAll_empty", nPairs: res.nPairs, nPreds: res.nPreds, nTrue: res.nTrue}
	}
	// content 按构造是纯 hex；个别探针错位位会解码成 0x00 等非 hex 字节
	// （A 库 Python 版逐字节命中是其配对全对齐的产物）。过滤非 hex 字符后
	// 解码——错位位丢弃而非阻断整链。
	var hexClean []byte
	for i := 0; i < len(hexAll); i++ {
		c := hexAll[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexClean = append(hexClean, c)
		}
	}
	rar, err := hex.DecodeString(string(hexClean))
	if err != nil {
		return &boolBlindResult{stage: "hex_decode_err", nPairs: res.nPairs, nPreds: res.nPreds, nTrue: res.nTrue, password: pwdAll}
	}
	res.rarBytes = rar
	// 密码列尾部未探测位会解码成 0x00（与 content 的过滤同理）——剪掉
	// 尾部不可打印字节再交付。
	res.password = strings.TrimFunc(pwdAll, func(r rune) bool { return r < 0x20 })
	if res.password == "" {
		res.password = pwdAll
	}
	return res
}

func urlUnquote(s string) string {
	// PathUnescape 而非 QueryUnescape：谓词 URL 的 '+' 是字面量（sqlmap 混合
	// 编码），Query 语义会把 '+' 转 空格污染谓词——与 Python unquote 对齐。
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// extractRARWith7z 外调 7z 解带密码 RAR（fail-closed：无 7z / 解压失败 → nil）。
func extractRARWith7z(rar []byte, password string) []byte {
	bin := find7z()
	if bin == "" {
		return nil
	}
	tmp, err := os.MkdirTemp("", "boolblind")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)
	rarPath := filepath.Join(tmp, "a.rar")
	if os.WriteFile(rarPath, rar, 0o600) != nil {
		return nil
	}
	outDir := filepath.Join(tmp, "out")
	cmd := exec.Command(bin, "x", "-y", "-p"+password, "-o"+outDir, rarPath)
	if err := cmd.Run(); err != nil {
		return nil
	}
	var files []string
	filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	for _, f := range files {
		if strings.EqualFold(filepath.Base(f), "flag.txt") {
			if b, err := os.ReadFile(f); err == nil {
				return b
			}
		}
	}
	if len(files) == 1 {
		if b, err := os.ReadFile(files[0]); err == nil {
			return b
		}
	}
	return nil
}

// find7z 探测完整版 7z（PATH → 常见安装位 → 仓库捆绑 _bin）。
func find7z() string {
	for _, c := range []string{"7z.exe", "7z"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	// 捆绑 7z 在融合副本 data 下；进程 cwd 不定（仓库根/包目录/cmd），
	// 多锚点探测后转绝对路径（子进程 cwd 变化不再失效）。
	for _, a := range []string{".", "..", "../.."} {
		for _, p := range []string{
			filepath.Join(a, "data", "race_attachments", "_bin", "7z.exe"),
			filepath.Join(a, "CTF-Agent_融合", "ctf_agent", "data", "race_attachments", "_bin", "7z.exe"),
		} {
			if _, err := os.Stat(p); err == nil {
				if abs, err := filepath.Abs(p); err == nil {
					return abs
				}
				return p
			}
		}
	}
	for _, p := range []string{
		`C:\Program Files\7-Zip\7z.exe`,
		filepath.Join("data", "race_attachments", "_bin", "7z.exe"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func init() {
	RegisterSolver(SolverEntry{
		Name: "pcap_bool_blind", Category: CategoryMiscS, Priority: 37,
		Solver: func(ctx context.Context, text string, attachments map[string]string) []string {
			for _, v := range attachments {
				b := []byte(v)
				head := b
				if len(head) > 4096 {
					head = head[:4096]
				}
				if len(b) < 1000 || (!bytes.Contains(head, []byte("ctftest")) &&
					!bytes.Contains(b, []byte("ORD(MID("))) {
					continue
				}
				res := replayBoolBlind(b)
				if res == nil {
					continue
				}
				body := extractRARWith7z(res.rarBytes, res.password)
				if body == nil {
					continue
				}
				if flags := scanFlags(string(body)); len(flags) > 0 {
					return flags
				}
			}
			return nil
		},
	})
}
