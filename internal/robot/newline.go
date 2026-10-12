package robot

import "strings"

// expandLineBreaksForMarkdown 把纯文本的单换行升级为 markdown 段落换行（\n\n）。
//
// 🔴 根因：钉钉/微信等客户端对机器人消息按 markdown 渲染，**单个 \n 不构成换行**
//（会被折叠成空格），必须 \n\n 才分段。服务端一侧写的是 "\n"（帮助文本、
// AI 报告都是逐行拼接），因此用户收到的是一坨没有换行的长文本——把同一段文本
// 复制出来粘贴到别处能看到换行，正是"文本里有 \n、但 IM 渲染不认"的实证。
//
// 规则：
//   - 行尾统一补成 \n\n（内容行之间产生一个空行，视觉上即正常换行）；
//   - 原文中的空行直接丢弃——内容行自带的 \n\n 已提供段落间距，保留会翻倍成两大段空行；
//   - ``` / ~~~ 围栏（代码块）内部保持单换行不动，否则代码每一行之间都会插空行；
//   - 幂等：对已展开的文本重复调用结果不变（"a\n\nb" 再处理仍是 "a\n\nb"）。
func expandLineBreaksForMarkdown(s string) string {
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	var b strings.Builder
	b.Grow(len(s) + len(lines))
	inFence := false
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			b.WriteString(line)
			b.WriteString("\n")
			inFence = !inFence
			continue
		}
		if inFence {
			b.WriteString(line)
			b.WriteString("\n")
			continue
		}
		if strings.TrimSpace(line) == "" {
			// 原段落空行：间距由上一内容行的 \n\n 提供，此处跳过避免空行翻倍。
			continue
		}
		b.WriteString(line)
		b.WriteString("\n\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
