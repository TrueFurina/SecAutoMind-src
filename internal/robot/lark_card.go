package robot

import (
	"encoding/json"
	"regexp"
	"strings"

	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
)

// larkCardMaxContentRunes 卡片 markdown 内容的 rune 上限。
// 飞书 interactive 卡片整体 JSON 有大小限制（约 30KB），中文按 UTF-8 3 字节算，
// 8000 rune ≈ 24KB，留足余量；超长回复回退纯文本（text 上限远大于卡片）。
const larkCardMaxContentRunes = 8000

var (
	larkHeadingRe = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*$`)
	larkHRuleRe   = regexp.MustCompile(`^\s*(-{3,}|\*{3,}|_{3,})\s*$`)
)

type larkCardConfig struct {
	WideScreenMode bool `json:"wide_screen_mode"`
}

type larkCardMarkdownElement struct {
	Tag     string `json:"tag"`
	Content string `json:"content"`
}

type larkCard struct {
	Config   larkCardConfig            `json:"config"`
	Elements []larkCardMarkdownElement `json:"elements"`
}

// larkCardMarkdown 把服务端 markdown 回复转换成飞书卡片 markdown 组件可渲染的形态。
//
// 🔴 背景：lark.go 原先回包写死 MsgTypeText，飞书把整段回复当字符串显示，
// `#`/`|`/``` 全部裸奔（2026-10-18 生产实测）。卡片 markdown 组件支持加粗/斜体/
// 行内代码/代码块/列表/引用，但**不支持 # 标题与表格**，转换规则：
//   - `#`～`######` 标题 → 加粗行（组件不认 # 标题，会按字面输出井号）；
//   - 连续的 `|` 表格块 → 围栏代码块（组件不渲染表格；等宽字体下管道对齐仍可读，
//     而直接透传必然裸奔）；已处于围栏内的表格行不动，避免双重包裹；
//   - `---` 水平线 → 丢弃（组件不支持，按字面输出会变成一串减号）；
//   - 围栏代码块内部一律不动；其余语法原样透传。
//
// 仅作用于飞书发送路径；QQ/钉钉/微信等渠道的发送层不受影响。
func larkCardMarkdown(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	var b strings.Builder
	b.Grow(len(s) + 64)
	inFence := false
	tableOpen := false
	flushTable := func() {
		if tableOpen {
			b.WriteString("```\n")
			tableOpen = false
		}
	}
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			flushTable()
			inFence = !inFence
			b.WriteString(line)
			b.WriteString("\n")
			continue
		}
		if inFence {
			b.WriteString(line)
			b.WriteString("\n")
			continue
		}
		if strings.HasPrefix(trimmed, "|") {
			if !tableOpen {
				b.WriteString("```\n")
				tableOpen = true
			}
			b.WriteString(strings.TrimRight(line, " \t"))
			b.WriteString("\n")
			continue
		}
		flushTable()
		if larkHRuleRe.MatchString(line) {
			continue
		}
		if m := larkHeadingRe.FindStringSubmatch(line); m != nil {
			b.WriteString("**" + strings.TrimSpace(m[1]) + "**")
			b.WriteString("\n\n")
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	flushTable()
	return strings.TrimRight(b.String(), "\n")
}

// larkReplyPayload 决定飞书回复的消息类型与 content：
// 默认走 interactive 卡片（markdown 组件渲染标题/代码块/列表，配合
// expandLineBreaksForMarkdown 保证段落换行），转换后超长或序列化失败时回退纯文本。
// 返回的 content 已是可直接放进 Reply Body 的 JSON 字符串。
func larkReplyPayload(reply string) (string, string) {
	if strings.TrimSpace(reply) == "" {
		reply = "(空回复)"
	}
	if md := expandLineBreaksForMarkdown(larkCardMarkdown(reply)); md != "" && len([]rune(md)) <= larkCardMaxContentRunes {
		card := larkCard{
			Config:   larkCardConfig{WideScreenMode: true},
			Elements: []larkCardMarkdownElement{{Tag: "markdown", Content: md}},
		}
		if b, err := json.Marshal(card); err == nil {
			return larkim.MsgTypeInteractive, string(b)
		}
	}
	b, _ := json.Marshal(larkTextContent{Text: reply})
	return larkim.MsgTypeText, string(b)
}
