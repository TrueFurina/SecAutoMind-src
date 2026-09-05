package multiagent

import (
	"strings"
	"testing"
)

// context_budget_keysnippet_test.go —— 创新点「0-token 正则节选」单测：
// 工具输出超预算被截断时，flag/URL/凭证/端口等关键行必须保留。

func TestExtractKeySnippets_FlagAndPort(t *testing.T) {
	content := `Starting Nmap 7.94
Nmap scan report for 192.168.1.10
22/tcp   open     ssh
80/tcp   open     http
443/tcp  open     https
secret token = abcd1234efgh
恭喜解出 flag{h3llo_ctf_2026}
一些无关紧要的长行填充内容aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
	snips := extractKeySnippets(content, 2000)
	joined := strings.Join(snips, "\n")
	if !strings.Contains(joined, "flag{h3llo_ctf_2026}") {
		t.Errorf("正则节选未保留 flag 行: %v", snips)
	}
	if !strings.Contains(joined, "open") {
		t.Errorf("正则节选未保留端口行: %v", snips)
	}
	if !strings.Contains(joined, "abcd1234efgh") {
		t.Errorf("正则节选未保留凭证行: %v", snips)
	}
}

func TestTruncateToolContent_KeepsKeySnippet(t *testing.T) {
	// 构造超预算工具输出：关键 flag 藏在中间，纯字节截断会丢头尾
	noise := strings.Repeat("filler line with ordinary text\n", 200) // ~6000B
	content := "top line\n" + noise + "FLAG{captured_in_truncation}\n" + noise
	maxBytes := 1024
	out := truncateToolContentWithKeySnippets(content, maxBytes, "")
	// 必须保留 flag（截断后仍在）
	if !strings.Contains(out, "FLAG{captured_in_truncation}") {
		t.Errorf("截断后关键 flag 丢失:\n%.400s", out)
	}
	if len(out) > maxBytes+len(toolOutputTruncationMarker)+400 {
		t.Errorf("截断结果超预算: len=%d max=%d", len(out), maxBytes)
	}
}

func TestTruncateToolContent_NoSnippetFallsBackToPlain(t *testing.T) {
	content := strings.Repeat("plain ordinary line with no keyword inside at all\n", 300)
	out := truncateToolContentWithKeySnippets(content, 512, "")
	if !strings.Contains(out, "truncated") {
		t.Errorf("无关键行时应回退纯截断并带标记: %.200s", out)
	}
}

func TestExtractKeySnippets_BudgetCap(t *testing.T) {
	// 大量关键行时不得超过预算
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString("open 80/tcp line number with detail text\n")
	}
	snips := extractKeySnippets(sb.String(), 1024)
	total := 0
	for _, s := range snips {
		total += len(s) + 2
	}
	if total > 1024/3+500 { // 预算上限（含少许容差）
		t.Errorf("节选超预算: %d", total)
	}
}
