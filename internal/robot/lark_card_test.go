package robot

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLarkCardMarkdownHeadings(t *testing.T) {
	in := "## 一、基础信息\n### 子标题 ##\n正文段落"
	got := larkCardMarkdown(in)
	if !strings.Contains(got, "**一、基础信息**") {
		t.Fatalf("标题应转为加粗行, got: %q", got)
	}
	if !strings.Contains(got, "**子标题**") {
		t.Fatalf("带尾 # 的标题应转为加粗行, got: %q", got)
	}
	if strings.Contains(got, "##") {
		t.Fatalf("不应残留 # 字面量, got: %q", got)
	}
	if !strings.Contains(got, "正文段落") {
		t.Fatalf("正文应保留, got: %q", got)
	}
}

func TestLarkCardMarkdownTablesToFence(t *testing.T) {
	in := "前文\n\n| 项目 | 信息 |\n|---|---|\n| 端口 | 80/tcp |\n\n后文"
	got := larkCardMarkdown(in)
	if !strings.Contains(got, "```\n| 项目 | 信息 |\n|---|---|\n| 端口 | 80/tcp |\n```") {
		t.Fatalf("表格块应整体包进围栏代码块, got: %q", got)
	}
	if !strings.Contains(got, "前文") || !strings.Contains(got, "后文") {
		t.Fatalf("表格外内容应保留, got: %q", got)
	}
}

func TestLarkCardMarkdownTableInsideFenceUntouched(t *testing.T) {
	in := "```\n| a | b |\n| 1 | 2 |\n```"
	got := larkCardMarkdown(in)
	if strings.Count(got, "```") != 2 {
		t.Fatalf("围栏内表格不应被二次包裹, got: %q", got)
	}
	if got != in {
		t.Fatalf("围栏内容应原样保留, want: %q, got: %q", in, got)
	}
}

func TestLarkCardMarkdownDropsHRule(t *testing.T) {
	got := larkCardMarkdown("段落一\n---\n***\n段落二")
	if got != "段落一\n段落二" {
		t.Fatalf("独立水平线行应被丢弃, got: %q", got)
	}
	got2 := larkCardMarkdown("上---")
	if got2 != "上---" {
		t.Fatalf("正文中的连字符不是水平线, 应保留, got: %q", got2)
	}
}

func TestLarkCardMarkdownFenceInteriorUntouched(t *testing.T) {
	in := "```\n# 这不是标题\n---\n```"
	got := larkCardMarkdown(in)
	if got != in {
		t.Fatalf("围栏内部不应被转换, want: %q, got: %q", in, got)
	}
}

func TestLarkCardMarkdownEmptyAndCRLF(t *testing.T) {
	if got := larkCardMarkdown("   "); got != "   " {
		t.Fatalf("空白输入应原样返回, got: %q", got)
	}
	if got := larkCardMarkdown("## 标题\r\n正文"); !strings.Contains(got, "**标题**") {
		t.Fatalf("CRLF 应被归一后转换, got: %q", got)
	}
}

func TestLarkReplyPayloadCard(t *testing.T) {
	reply := "## 报告\n\n| 项目 | 信息 |\n|---|---|\n| 端口 | 80 |\n\n- 列表项\n"
	msgType, content := larkReplyPayload(reply)
	if msgType != "interactive" {
		t.Fatalf("应走 interactive 卡片, got: %q", msgType)
	}
	var card larkCard
	if err := json.Unmarshal([]byte(content), &card); err != nil {
		t.Fatalf("content 应为合法卡片 JSON: %v", err)
	}
	if len(card.Elements) != 1 || card.Elements[0].Tag != "markdown" {
		t.Fatalf("卡片应含单个 markdown 元素, got: %+v", card.Elements)
	}
	if !strings.Contains(card.Elements[0].Content, "**报告**") {
		t.Fatalf("卡片内容应含加粗标题, got: %q", card.Elements[0].Content)
	}
	if !strings.Contains(card.Elements[0].Content, "| 端口 | 80 |") {
		t.Fatalf("表格应保留在代码块内, got: %q", card.Elements[0].Content)
	}
}

func TestLarkReplyPayloadFallbackOversize(t *testing.T) {
	long := strings.Repeat("字", larkCardMaxContentRunes+10)
	msgType, content := larkReplyPayload(long)
	if msgType != "text" {
		t.Fatalf("超长回复应回退纯文本, got: %q", msgType)
	}
	var textContent larkTextContent
	if err := json.Unmarshal([]byte(content), &textContent); err != nil {
		t.Fatalf("回退 content 应为合法 text JSON: %v", err)
	}
	if textContent.Text != long {
		t.Fatalf("回退文本应与原回复一致")
	}
}

func TestLarkReplyPayloadEmpty(t *testing.T) {
	msgType, content := larkReplyPayload("   ")
	if msgType != "interactive" {
		t.Fatalf("空回复也应走卡片(内容为占位文本), got: %q", msgType)
	}
	var card larkCard
	if err := json.Unmarshal([]byte(content), &card); err != nil {
		t.Fatalf("content 应为合法卡片 JSON: %v", err)
	}
	if !strings.Contains(card.Elements[0].Content, "(空回复)") {
		t.Fatalf("空回复应有占位内容, got: %q", card.Elements[0].Content)
	}
}
