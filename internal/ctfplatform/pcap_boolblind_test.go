package ctfplatform

// pcap_boolblind_test.go —— 布尔盲注流量重放求解器测试（融合 P1-8）。
// 合成夹具自建 pcap（不依赖真题附件）；真实 pcap 端到端为本地口径（附件
// gitignore，缺失即 Skip——CI 不依赖它）。

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ── 合成 pcap 构造 ──

func bbEthIPTCP(payload []byte, sport, dport uint16, seq uint32) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 0x50 // data offset 5
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6
	total := 40 + len(payload) // IP(20)+TCP(20)+payload
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	pkt := append(append(ip, tcp...), payload...)
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(eth, pkt...)
}

func bbPcapFile(pkts ...[]byte) []byte {
	var out bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(hdr[20:24], 1) // Ethernet
	out.Write(hdr)
	for _, p := range pkts {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p)))
		out.Write(rec)
		out.Write(p)
	}
	return out.Bytes()
}

// bbSynthPredicate 生成对 ch 的 (thr,truth) 探针请求+响应对。
func bbSynthPredicate(ch byte, pos int, seqBase uint32) (req, resp []byte) {
	thr := int(ch) - 1 // 单探针：thr=ch-1 时真
	q := "GET /?id=1%20AND%20ORD(MID((SELECT%20IFNULL(CAST(content%20AS%20NCHAR),0x20)%20FROM%20ctftest.ctfblob%20ORDER%20BY%20id%20LIMIT%200,1)," +
		itoa(pos) + ",1))>" + itoa(thr) + " HTTP/1.1\r\nHost: t\r\n\r\n"
	req = []byte(q)
	if int(ch) > thr {
		resp = []byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nxx</br></br>success")
	} else {
		resp = []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfalse")
	}
	return
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestPcapBoolBlindDecodeUnits(t *testing.T) {
	// 纯函数层：谓词正则 + 字段提取 + 鲁棒解码（端到端由真实 pcap 测试覆盖）
	url := "/?id=1%27%20AND%20ORD%28MID%28%28SELECT%20IFNULL%28CAST%28password%20AS%20NCHAR%29%2C0x20%29%20FROM%20ctftest.ctfblob%20ORDER%20BY%20id%20LIMIT%202%2C1%29%2C7%2C1%29%29%3E104"
	m := bbPredRe.FindStringSubmatch(urlUnquote(url))
	if m == nil {
		t.Fatal("谓词正则未命中")
	}
	if f := bbFieldOf(m[1]); f != "password" {
		t.Fatalf("字段提取 %q != password", f)
	}
	if m[2] != "2" || m[3] != "7" || m[4] != "104" {
		t.Fatalf("row/pos/thr 提取错: %v", m[2:])
	}
	// 104='h'：thr=103 真、thr=104 真、thr=105 假 → argmin=104
	if v := bbRobustDecode([][2]int{{103, 1}, {104, 1}, {105, 0}}); v != 105 {
		t.Fatalf("鲁棒解码 %d != 105", v)
	}
}

func TestPcapBoolBlindSolverRegistered(t *testing.T) {
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "pcap_bool_blind" {
			found = true
		}
	}
	if !found {
		t.Fatal("pcap_bool_blind 未注册")
	}
	// 非盲注附件不触发（快速短路）
	if flags := tryRegisteredByName("pcap_bool_blind", "", map[string]string{"a": "just some text"}); flags != nil {
		t.Fatalf("普通文本不应触发: %v", flags)
	}
}

func tryRegisteredByName(name, text string, atts map[string]string) []string {
	for _, s := range GetSolvers() {
		if s.Name == name {
			return s.Solver(nil, text, atts)
		}
	}
	return nil
}

// TestPcapBoolBlindReal10735 真实 pcap 端到端（本地口径：附件 gitignore，
// 缺失 Skip；需要 7z——探测不到同 Skip，不在 CI 强制）。
func TestPcapBoolBlindReal10735(t *testing.T) {
	p := filepath.Join("..", "..", "CTF-Agent_融合", "ctf_agent", "data", "race_attachments",
		"10735_logbool的附件", "tempdir", "MISC附件", "logbool.pcapng")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Skip("真题 pcap 本地缺失（gitignore 路径），CI 跳过")
	}
	if find7z() == "" {
		t.Skip("完整版 7z 不可用，RAR5 解压链无法端到端")
	}
	res := replayBoolBlind(data)
	if res == nil {
		t.Fatal("真实 pcap 解码失败")
	}
	t.Logf("pairs=%d preds=%d true=%d rar=%dB password_len=%d",
		res.nPairs, res.nPreds, res.nTrue, len(res.rarBytes), len(res.password))
	if res.nPreds < 2000 || res.nTrue < 500 {
		t.Fatalf("流量形态异常：preds=%d true=%d", res.nPreds, res.nTrue)
	}
	// RAR 魔数（RAR5: "Rar!\x1a\x07\x01\x00"）
	if !bytes.HasPrefix(res.rarBytes, []byte("Rar!\x1a\x07\x01\x00")) {
		t.Fatalf("content hex 非 RAR5：前 8 字节 % x", res.rarBytes[:8])
	}
	body := extractRARWith7z(res.rarBytes, res.password)
	if body == nil {
		t.Fatal("7z 解压失败（密码或工具问题）")
	}
	flags := scanFlags(string(body))
	if len(flags) == 0 {
		t.Fatalf("解压产物无 flag 形态: %q", string(body[:bbmin(80, len(body))]))
	}
	t.Logf("端到端命中（本地口径，不回显明文）: %d 候选", len(flags))
}

func bbmin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
