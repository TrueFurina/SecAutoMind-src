// presolve_python.go — 西湖论剑 Python skills 兜底求解通道（2026-10-23 吞并接入）
//
// 定位：Go 求解器（157 注册 + 硬编码扇出）全 miss 后，把题干文本交给迁移的
// 西湖论剑 79 个确定性 Python skill（data/ctf_benchmark/xhlj_legacy/）尝试求解。
// 这是吞并路线的「能力接入」层：资产 2026-10-23 已物理迁入，本文件使其进入生产链路。
//
// 安全设计（fail-closed，不破坏主链路）：
//   - 开关 SECAUTOMIND_PYTHON_FALLBACK（默认开；显式 "0" 关闭）
//   - python 不可用 / legacy 目录缺失 / 进程超时 / 输出非法 → 一律返回 nil
//   - 进程级超时 SECAUTOMIND_PYTHON_FALLBACK_TIMEOUT_MS（默认 45000ms）
//   - 候选只收 flag 形态（DASCTF{..}/flag{..}/CTF{..}/vnctf{..} 等），去重
//   - runner 内部另有 40s 预算与单 skill 异常捕获（见 runner.py）
package ctfplatform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	xhljFlagShapeRe = regexp.MustCompile(`(?i)(?:DASCTF|N1CTF|VNCTF|CTF|flag|Flag|FLAG)\{[^}\s]{1,200}\}`)
)

const (
	envPythonFallback       = "SECAUTOMIND_PYTHON_FALLBACK"
	envPythonBin            = "SECAUTOMIND_PYTHON"
	envXHLJLegacyDir        = "SECAUTOMIND_XHLJ_LEGACY"
	envPythonFallbackTimout = "SECAUTOMIND_PYTHON_FALLBACK_TIMEOUT_MS"

	defaultXHLJRelPath = `data\ctf_benchmark\xhlj_legacy`
)

// pythonFallbackEnabled 读开关：默认开；显式 "0"/"false" 关闭。
func pythonFallbackEnabled() bool {
	v := strings.TrimSpace(os.Getenv(envPythonFallback))
	if v == "" {
		return true
	}
	return v != "0" && !strings.EqualFold(v, "false")
}

// findPythonPath 定位 python 可执行文件：env 优先，否则 PATH。
func findPythonPath() (string, bool) {
	if p := strings.TrimSpace(os.Getenv(envPythonBin)); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	if p, err := exec.LookPath("python"); err == nil {
		return p, true
	}
	return "", false
}

// xhljLegacyDir 定位迁移资产目录：env 优先，否则从仓库根相对路径探测。
func xhljLegacyDir() string {
	if d := strings.TrimSpace(os.Getenv(envXHLJLegacyDir)); d != "" {
		if _, err := os.Stat(filepath.Join(d, "runner.py")); err == nil {
			return d
		}
	}
	// 仓库根相对：CWD 或向上两级（包目录是 internal/ctfplatform）
	for _, base := range []string{".", filepath.Join("..", "..")} {
		cand := filepath.Join(base, defaultXHLJRelPath)
		if _, err := os.Stat(filepath.Join(cand, "runner.py")); err == nil {
			if abs, err := filepath.Abs(cand); err == nil {
				return abs
			}
			return cand
		}
	}
	return ""
}

func pythonFallbackTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv(envPythonFallbackTimout)); v != "" {
		if ms, err := time.ParseDuration(v + "ms"); err == nil && ms > 0 {
			return ms
		}
	}
	return 45 * time.Second
}

// tryPythonLegacyFallback 调 xhlj_legacy/runner.py 遍历 Python skills，返回 flag 形态候选。
// fail-closed：任何失败返回 nil。
func tryPythonLegacyFallback(text string, attachments map[string]string) []string {
	if !pythonFallbackEnabled() {
		return nil
	}
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	if strings.TrimSpace(fullText) == "" {
		return nil
	}
	py, ok := findPythonPath()
	if !ok {
		return nil
	}
	legacyDir := xhljLegacyDir()
	if legacyDir == "" {
		return nil
	}
	runner := filepath.Join(legacyDir, "runner.py")
	if _, err := os.Stat(runner); err != nil {
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "xhlj_py_*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmpDir)
	inputFile := filepath.Join(tmpDir, "input.txt")
	if err := os.WriteFile(inputFile, []byte(fullText), 0o600); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pythonFallbackTimeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, py, runner,
		"--text-file", inputFile, "--legacy-dir", legacyDir)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil // 超时 fail-closed
	}
	if err != nil {
		return nil
	}

	var resp struct {
		Solves []struct {
			Skill string `json:"skill"`
			Flag  string `json:"flag"`
		} `json:"solves"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var flags []string
	for _, s := range resp.Solves {
		f := strings.TrimSpace(s.Flag)
		if f == "" || seen[f] || !xhljFlagShapeRe.MatchString(f) {
			continue
		}
		seen[f] = true
		flags = append(flags, f)
	}
	return flags
}

// pythonFallbackResult 构造命中结果（供两处接入点复用）。
func pythonFallbackResult(flags []string) *PresolveResult {
	if len(flags) == 0 {
		return nil
	}
	return &PresolveResult{
		Solved: true,
		Flags:  flags,
		Engine: "xhlj_python",
		Detail: fmt.Sprintf("[presolve:xhlj_python] 西湖论剑技能兜底命中 %d 个候选", len(flags)),
	}
}
