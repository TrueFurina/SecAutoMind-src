package robot

import "strings"

// splitTextChunks splits text into chunks no longer than maxRunes (rune count).
func splitTextChunks(text string, maxRunes int) []string {
	text = strings.TrimSpace(text)
	if text == "" || maxRunes <= 0 {
		return nil
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return []string{text}
	}
	var out []string
	for len(runes) > 0 {
		end := maxRunes
		if end > len(runes) {
			end = len(runes)
		}
		out = append(out, string(runes[:end]))
		runes = runes[end:]
	}
	return out
}

func trimReply(s string) string {
	return strings.TrimSpace(s)
}

// truncateForLog 按 rune 截断日志预览文本（绝不能按字节切，否则中文会被切成乱码，
// 让排障的人误判成"写入把内容弄坏了"——本机实锤过的虚惊）。
func truncateForLog(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "…"
}
