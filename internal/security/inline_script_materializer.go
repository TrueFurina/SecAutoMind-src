package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// inlineScriptThresholdBytes 内联脚本参数超过该字节数时，判定为“巨型内联”，
// 需要落盘为临时脚本文件后以文件方式执行，避免触碰平台命令行长度上限。
// Windows CreateProcess 命令行上限约 32767 字符（含引号/空格），此处留足余量。
const inlineScriptThresholdBytes = 20000

// estimatedCommandLineLen 粗略估算把 args 拼进命令行后的字符数（含引号与空格）。
// Go 在 Windows 上经 exec.Cmd 启动子进程时同样要生成一行命令行字符串，
// 超长会直接得到 “The command line is too long” / ERROR_FILENAME_EXCED_RANGE。
// 这里不追求逐字符精确，只用于提前判断是否需要走落盘路径。
func estimatedCommandLineLen(args []string) int {
	n := 0
	for i, a := range args {
		if i > 0 {
			n++ // 空格分隔符
		}
		// 含空格或引号时 Go 会加引号并转义，这里按“原长 + 2 个引号”粗估
		if strings.ContainsAny(a, " \t\"") {
			n += 2
		}
		n += len(a)
	}
	return n
}

// materializeInlineScript 检查 command + args 是否构成 “python* -c <巨型源码>”：
//   - command 的 basename 是 python/python3/py（Windows 下忽略 .exe）；
//   - 参数中存在独立的 "-c"，且紧随其后的源码长度超过 inlineScriptThresholdBytes；
//   - 估算命令行总长超过 30000 字符（命中平台上限风险区）。
//
// 满足条件时，把源码以 UTF-8 落盘到临时目录（内容 sha256 命名，幂等复用），
// 并把 [“-c”, 源码] 两项改写为 [脚本文件绝对路径]，其余参数原样保留。
// 返回改写后的 (command, args)。不满足条件或落盘失败时原样返回，并给出 error 供日志记录。
//
// 注意：Windows 下 python 脚本文件路径参数不参与 shell 拼接，因此不受 32767 限制。
func materializeInlineScript(command string, args []string) (string, []string, error) {
	if runtime.GOOS != "windows" {
		return command, args, nil
	}
	if estimatedCommandLineLen(args) <= 30000 {
		return command, args, nil
	}

	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	isPython := base == "python" || base == "python3" || base == "py"
	if !isPython {
		return command, args, fmt.Errorf("命令行过长但命令不是 python（%s），无法自动落盘", command)
	}

	// 找到固定参数中的 “-c 源码” 对
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-c" {
			continue
		}
		code := args[i+1]
		if len(code) <= inlineScriptThresholdBytes {
			continue
		}
		path, err := writeInlineScriptCache(code)
		if err != nil {
			return command, args, fmt.Errorf("内联脚本落盘失败: %w", err)
		}
		// 改写：去掉 "-c" 与其源码，插入脚本路径
		newArgs := make([]string, 0, len(args)-1)
		newArgs = append(newArgs, args[:i]...)
		newArgs = append(newArgs, path)
		newArgs = append(newArgs, args[i+2:]...)
		return command, newArgs, nil
	}
	return command, args, fmt.Errorf("命令行过长但未找到可落盘的巨型 -c 源码（共 %d 个参数）", len(args))
}

// inlineScriptCacheDir 返回临时脚本缓存目录（默认 %TEMP%/secautomind-inline）。
func inlineScriptCacheDir() (string, error) {
	base := os.TempDir()
	if base == "" {
		base = "."
	}
	dir := filepath.Join(base, "secautomind-inline")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// writeInlineScriptCache 把源码按内容 sha256 写为 <cache>/<hash>.py。
// 同内容复用已有文件，避免反复写盘；写入时用临时文件 + rename 保证并发安全。
func writeInlineScriptCache(code string) (string, error) {
	sum := sha256.Sum256([]byte(code))
	hash := hex.EncodeToString(sum[:])[:24]
	dir, err := inlineScriptCacheDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, hash+".py")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	tmp, err := os.CreateTemp(dir, "*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(code); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		// 并发写入时 rename 可能因目标已存在而失败：目标已可用则忽略
		if _, statErr := os.Stat(path); statErr == nil {
			_ = os.Remove(tmpName)
			return path, nil
		}
		_ = os.Remove(tmpName)
		return "", err
	}
	return path, nil
}

// CleanupInlineScriptCache 清理内联脚本缓存目录中的过期文件。
// 删除策略：超过 maxAge 的文件删除；文件数超过 maxFiles 时按修改时间删除最旧的。
// 建议在应用启动时调用一次。
func CleanupInlineScriptCache(maxAge time.Duration, maxFiles int) {
	dir, err := inlineScriptCacheDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	// 收集所有 .py 文件
	type cacheFile struct {
		name    string
		modTime time.Time
	}
	var files []cacheFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".py") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, cacheFile{name: e.Name(), modTime: info.ModTime()})
	}
	now := time.Now()
	deleted := 0
	// 1. 删除超龄文件
	for _, f := range files {
		if now.Sub(f.modTime) > maxAge {
			_ = os.Remove(filepath.Join(dir, f.name))
			deleted++
		}
	}
	// 2. 如果文件数仍超限，按修改时间排序删除最旧的
	if len(files)-deleted > maxFiles {
		// 重新收集存活文件
		var alive []cacheFile
		for _, f := range files {
			if now.Sub(f.modTime) <= maxAge {
				alive = append(alive, f)
			}
		}
		// 按修改时间升序（最旧在前）
		sort.Slice(alive, func(i, j int) bool {
			return alive[i].modTime.Before(alive[j].modTime)
		})
		for i := 0; i < len(alive)-maxFiles; i++ {
			_ = os.Remove(filepath.Join(dir, alive[i].name))
			deleted++
		}
	}
	if deleted > 0 {
		// 静默清理，不影响主流程
	}
}
