package ctfplatform

// pcap_ezrat_test.go —— EZRAT 求解器测试（融合 P1-8 后半）。
// 真实 capture.pcap 为本地口径（cybench 附件 gitignore，缺失即 Skip）。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPcapEzratRegistered(t *testing.T) {
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "pcap_ezrat_chat" {
			found = true
		}
	}
	if !found {
		t.Fatal("pcap_ezrat_chat 未注册")
	}
}

func TestEzratPrintableAndAssemble(t *testing.T) {
	if ezPrintableRatio([]byte("hello world")) != 1.0 {
		t.Fatal("全可打印应为 1.0")
	}
	// 完整 flag 优先
	if got := ezAssemble([][]byte{[]byte("xx HTB{full_flag_here} yy")}); string(got) != "HTB{full_flag_here}" {
		t.Fatalf("完整 flag 优先: %q", got)
	}
	// 开口+标签中段+闭口 装配（data_siege 三段形态）
	texts := [][]byte{
		[]byte("echo ssh-rsa AAAA... htb{gr4nd_"),
		[]byte("type credentials.txt -> 2nd flag part: c0mp0nent_"),
		[]byte("TaskName s1ege_0f_d4t4}"),
	}
	if got := ezAssemble(texts); got == nil || !ezFullRe.Match(got) {
		t.Fatalf("三段装配失败: %q", got)
	}
	// 片段歧义 fail-closed：3 个开口
	amb := [][]byte{[]byte("a{aaa1"), []byte("b{bbb2"), []byte("c{ccc3"), []byte("ddd}")}
	if got := ezAssemble(amb); got != nil {
		t.Fatalf("歧义应放弃: %q", got)
	}
}

func TestPcapEzratRealDataSiege(t *testing.T) {
	p := filepath.Join("..", "..", "CTF-Agent_融合", "ctf_agent", "data", "questions_ext_cybench",
		"_attachments", "forensics", "hackthebox_cyber_apocalypse_2024_forensics_medium_data_siege",
		"capture.pcap")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Skip("真题 capture.pcap 本地缺失（gitignore），CI 跳过")
	}
	flag := solveEZRat(data)
	if flag == nil {
		t.Fatal("真实 data_siege 端到端失败（口令/帧/解密/装配某环节未过）")
	}
	if len(scanFlags(string(flag))) == 0 {
		t.Fatalf("装配产物非 flag 形态: %q", string(flag))
	}
	t.Logf("端到端命中（本地口径，不回显明文）: %d 字节", len(flag))
}
