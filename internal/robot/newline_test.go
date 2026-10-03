package robot

import (
	"strings"
	"testing"
)

// ── IM 换行展开（钉钉/微信 markdown 渲染：单 \n 不换行，必须 \n\n）──────────
//
// 用户实证：机器人发出的【SecAutoMind 机器人命令】在钉钉/微信里连成一片没有换行，
// 但把同一段文本复制出来粘贴到别的输入框却能看到换行——即文本里确实有 \n，
// 是渲染端按 markdown 语义把单 \n 折叠了。本组测试锁死发送侧的展开行为。

func TestExpandLineBreaks_BasicSingleLine(t *testing.T) {
	if got := expandLineBreaksForMarkdown("单行文本"); got != "单行文本" {
		t.Errorf("单行文本不应被改动，got %q", got)
	}
	if got := expandLineBreaksForMarkdown(""); got != "" {
		t.Errorf("空串应原样返回，got %q", got)
	}
}

// TestExpandLineBreaks_HelpText 帮助文本形态：逐行 \n 必须变成 \n\n（钉钉/微信才换行）。
func TestExpandLineBreaks_HelpText(t *testing.T) {
	in := "【SecAutoMind 机器人命令】\n【通用 General】\n· 帮助 / help — 显示本帮助\n· 版本 / version"
	got := expandLineBreaksForMarkdown(in)

	if strings.Contains(got, "命令】\n【通用") {
		t.Fatalf("单换行未被展开，钉钉/微信会渲染成一整行：%q", got)
	}
	for _, line := range []string{"【SecAutoMind 机器人命令】", "【通用 General】", "· 帮助 / help — 显示本帮助"} {
		if !strings.Contains(got, line) {
			t.Errorf("展开后丢失内容行 %q：%q", line, got)
		}
	}
	if strings.HasSuffix(got, "\n") {
		t.Errorf("不应残留尾随换行，got %q", got)
	}
	// 行间恰好两个换行（一个空行），不是三个以上（空行翻倍说明实现错了）
	if strings.Contains(got, "\n\n\n") {
		t.Errorf("出现连续 3 个及以上换行（空行翻倍），got %q", got)
	}
}

func TestExpandLineBreaks_CRLFAndExistingBlankLines(t *testing.T) {
	// Windows 行尾
	if got, want := expandLineBreaksForMarkdown("a\r\nb"), "a\n\nb"; got != want {
		t.Errorf("CRLF: got %q, want %q", got, want)
	}
	// 原段落空行不得翻倍
	if got, want := expandLineBreaksForMarkdown("a\n\nb"), "a\n\nb"; got != want {
		t.Errorf("已有空行应保持单个空行间距，got %q, want %q", got, want)
	}
	// 多个连续空行同样收敛，不膨胀
	if got, want := expandLineBreaksForMarkdown("a\n\n\n\nb"), "a\n\nb"; got != want {
		t.Errorf("多空行应收敛为单个空行间距，got %q, want %q", got, want)
	}
}

// TestExpandLineBreaks_Idempotent 幂等：重复展开结果不变（回复可能经多条路径处理）。
func TestExpandLineBreaks_Idempotent(t *testing.T) {
	in := "标题\n第一行\n\n第二段\n```\ncode1\ncode2\n```\n收尾"
	once := expandLineBreaksForMarkdown(in)
	twice := expandLineBreaksForMarkdown(once)
	if once != twice {
		t.Fatalf("不幂等：\nonce=%q\ntwice=%q", once, twice)
	}
}

// TestExpandLineBreaks_CodeFencePreserved 代码块内部必须保持单换行，
// 否则每行代码之间都会被插入空行，报告里的代码段彻底不可读。
func TestExpandLineBreaks_CodeFencePreserved(t *testing.T) {
	in := "说明\n```bash\nls -la\necho hi\n```\n结束"
	got := expandLineBreaksForMarkdown(in)
	if !strings.Contains(got, "```bash\nls -la\necho hi\n```") {
		t.Fatalf("代码块内部被插入了空行：%q", got)
	}
	if !strings.Contains(got, "说明\n\n```bash") {
		t.Errorf("代码块前的正文未展开换行：%q", got)
	}
}

// TestExpandLineBreaks_MutationGuard 变异守护：把 "\n\n" 退回 "\n" 时本测试必须 FAIL。
//（变异命令：sed 's/b.WriteString("\\n\\n")/b.WriteString("\\n")/' internal/robot/newline.go）
func TestExpandLineBreaks_MutationGuard(t *testing.T) {
	got := expandLineBreaksForMarkdown("第一行\n第二行")
	if got != "第一行\n\n第二行" {
		t.Fatalf("换行未展开为段落换行：got %q, want %q（若此测试红说明展开被破坏）", got, "第一行\n\n第二行")
	}
}
