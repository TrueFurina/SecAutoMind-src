// presolve_attachment.go —— 聊天上传附件的真实内容加载器。
//
// 背景（Tier 2 激活）：生产 handler 调 TryPresolve(ctx, message, nil)，
// attachments 恒为 nil，导致所有依赖真实文件的执行层求解器（exec_strings /
// exec_git_history / exec_pcap_http / exec_endian_swap …）在真实 CTF 附件
// 场景永远拿不到内容、只能休眠。
//
// 但聊天上传链路（internal/handler/multi_agent_prepare.go）会把已保存的附件
// 绝对路径以如下形式追加进用户消息文本：
//
//	[用户上传的文件]
//	- shell.php: E:\xxx\chat_uploads\2026-09-07\<convID>\shell.php
//
// 本文件在 presolve 入口处识别并读取这些文件，把真实内容灌进 attachments，
// 从而在不改动任何函数签名、不动 handler 的前提下激活执行层求解器。
//
// 安全：路径必须落在当前工作目录的 chat_uploads/ 之下（白名单 + 穿越防护），
// 单文件 4 MiB 上限、总数 10 个上限，避免把任意文件读进求解上下文。
package ctfplatform

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

const (
	attachmentMarker = "[用户上传的文件]"
	// maxAttachmentFileBytes 单文件读入上限（4 MiB），超出则跳过（避免大文件拖垮求解）。
	maxAttachmentFileBytes = 4 << 20
	// maxAttachmentFiles 单次 presolve 最多读入的附件数。
	maxAttachmentFiles = 10
)

// attachLineRe 匹配 "- 文件名: 绝对路径" 行。
var attachLineRe = regexp.MustCompile(`(?m)^-\s*([^:\r\n]+):\s*(.+?)\s*$`)

// loadChatAttachmentFiles 从用户消息文本中识别聊天上传附件的绝对路径，
// 校验其位于 chat_uploads 白名单内后读入内容，返回 文件名→文件内容。
// 任何异常（路径越界/不存在/过大/读取失败）都静默跳过，绝不影响主流程。
func loadChatAttachmentFiles(text string, logger *zap.Logger) map[string]string {
	idx := strings.Index(text, attachmentMarker)
	if idx < 0 {
		return nil
	}
	block := text[idx+len(attachmentMarker):]

	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		return nil
	}
	rootAbs, err := filepath.Abs(filepath.Join(cwd, "chat_uploads"))
	if err != nil {
		return nil
	}

	loaded := make(map[string]string)
	for _, m := range attachLineRe.FindAllStringSubmatch(block, -1) {
		if len(loaded) >= maxAttachmentFiles {
			break
		}
		name := strings.TrimSpace(m[1])
		raw := strings.TrimSpace(m[2])
		if name == "" || raw == "" {
			continue
		}
		abs := resolveUnderRoot(raw, rootAbs)
		if abs == "" {
			continue
		}
		st, err := os.Stat(abs)
		if err != nil {
			continue
		}
		mode := st.Mode()
		if !mode.IsRegular() {
			continue
		}
		if st.Size() > maxAttachmentFileBytes {
			if logger != nil {
				logger.Debug("presolve 跳过超大附件", zap.String("file", name), zap.Int64("size", st.Size()))
			}
			continue
		}
		content, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		loaded[name] = string(content)
	}
	if len(loaded) == 0 {
		return nil
	}
	if logger != nil {
		logger.Info("presolve 载入聊天上传附件", zap.Int("count", len(loaded)))
	}
	return loaded
}

// resolveUnderRoot 把 raw 解析为绝对路径并强制其位于 root 之下（防路径穿越）。
// 返回 "" 表示不合法。
func resolveUnderRoot(raw, rootAbs string) string {
	var abs string
	if filepath.IsAbs(raw) {
		abs = filepath.Clean(raw)
	} else {
		a, err := filepath.Abs(raw)
		if err != nil {
			return ""
		}
		abs = a
	}
	abs, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// 文件可能刚写入尚未可解析；退回 Clean 结果并继续做前缀校验
		abs = filepath.Clean(abs)
	}
	rootClean := filepath.Clean(rootAbs)
	if abs != rootClean && !strings.HasPrefix(abs, rootClean+string(os.PathSeparator)) && !strings.HasPrefix(abs, rootClean+"/") {
		return ""
	}
	// 额外确认不是目录（EvalSymlinks 失败时 Stat 已在调用方做）
	if info, err := fs.Stat(os.DirFS(filepath.Dir(abs)), filepath.Base(abs)); err == nil && info.IsDir() {
		return ""
	}
	return abs
}
