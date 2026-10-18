// Package paths 统一解析 SecAutoMind 的应用数据根（data root）。
//
// 背景：进程原先按 CWD 解析 "data/"、"tmp/" 等相对路径。安装包把程序装到
// C:\Program Files\SecAutoMind，快捷方式的工作目录又是安装目录，普通用户双击后
// 写 data/ 会被 UAC 拒绝（64 位进程无虚拟化重定向）。
//
// 解析顺序（Init 时一次性确定，进程内不变）：
//  1. 环境变量 SECAUTOMIND_HOME（显式指定，最高优先级）
//  2. 配置文件所在目录——若其中已存在 data/（既有安装，保持原位，不做迁移）
//  3. 配置文件所在目录——若可写（绿色版/解压即用）
//  4. 用户数据目录（Program Files 等只读安装场景）：
//     Windows: %LOCALAPPDATA%\SecAutoMind；其他: $XDG_DATA_HOME/secautomind 或 ~/.local/share/secautomind
//
// 兼容性约定：Init 之前调用 Resolve 一律原样返回相对路径，因此既有单元测试与
// 未初始化的库调用方行为完全不变。
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// EnvHome 是覆盖数据根的环境变量名。
const EnvHome = "SECAUTOMIND_HOME"

const (
	appDirName  = "SecAutoMind"
	unixDirName = "secautomind"
	dataDirName = "data"
)

var (
	mu       sync.RWMutex
	root     string        // 已解析的数据根（绝对路径）；空 = 尚未 Init
	probeDir = writableDir // 可在测试中替换
)

// Init 依据配置文件路径解析数据根并记忆。重复调用会重新解析（幂等）。
// configPath 为空时按当前工作目录处理。
func Init(configPath string) string {
	mu.Lock()
	defer mu.Unlock()
	root = resolveRoot(configPath)
	return root
}

// SetHome 显式指定数据根（测试或嵌入方使用）。
func SetHome(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		Reset()
		return
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	mu.Lock()
	root = filepath.Clean(dir)
	mu.Unlock()
}

// Reset 清除已解析的数据根，恢复"未初始化"状态（仅供测试）。
func Reset() {
	mu.Lock()
	root = ""
	mu.Unlock()
}

// Home 返回已解析的数据根；未 Init 时返回空串。
func Home() string {
	mu.RLock()
	defer mu.RUnlock()
	return root
}

// Resolve 把相对路径归到数据根下。
//   - 空串 → 空串（保留"未配置"语义，由调用方决定默认值）
//   - 绝对路径 → 原样 Clean
//   - 未 Init → 原样返回（兼容既有行为）
func Resolve(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	h := Home()
	if h == "" {
		return p
	}
	return filepath.Join(h, p)
}

// Abs 返回绝对路径：已 Init 时相对数据根，未 Init 时相对当前工作目录。
func Abs(p string) (string, error) {
	return filepath.Abs(Resolve(p))
}

// ResolveAll 就地解析切片中的每个路径（空元素跳过）。
func ResolveAll(items []string) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		if strings.TrimSpace(item) == "" {
			out[i] = item
			continue
		}
		out[i] = Resolve(item)
	}
	return out
}

func resolveRoot(configPath string) string {
	if v := strings.TrimSpace(os.Getenv(EnvHome)); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			return filepath.Clean(abs)
		}
		return filepath.Clean(v)
	}

	base := configDir(configPath)

	// 既有安装：data/ 已存在则沿用原位，绝不自动迁移用户数据。
	if fi, err := os.Stat(filepath.Join(base, dataDirName)); err == nil && fi.IsDir() {
		return base
	}
	// 绿色版：安装/解压目录可写，数据留在程序旁边。
	if probeDir(base) {
		return base
	}
	// 系统安装目录（Program Files 等）不可写：退到用户数据目录。
	if d := userDataDir(); d != "" {
		return d
	}
	return base
}

func configDir(configPath string) string {
	p := strings.TrimSpace(configPath)
	if p == "" {
		if wd, err := os.Getwd(); err == nil {
			return wd
		}
		return "."
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	return filepath.Dir(abs)
}

// writableDir 通过实际创建临时文件判断目录可写——比检查权限位可靠，
// 也是唯一能正确反映 Windows ACL / UAC 行为的方式。
func writableDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".secautomind-write-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// userDataDir 返回当前用户的数据目录；取不到时返回空串。
func userDataDir() string {
	if runtime.GOOS == "windows" {
		// 注意：本仓库已知某些 shell 缺失 %AppData%，这里同时兜底 %LOCALAPPDATA%
		// 与 USERPROFILE 推导，避免因环境变量缺失静默退化成相对路径。
		for _, key := range []string{"LOCALAPPDATA", "APPDATA"} {
			if v := strings.TrimSpace(os.Getenv(key)); v != "" {
				return filepath.Join(v, appDirName)
			}
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "AppData", "Local", appDirName)
		}
		return ""
	}
	if v := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); v != "" {
		return filepath.Join(v, unixDirName)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", unixDirName)
	}
	return ""
}

// EnsureHome 创建数据根目录并返回其路径（未 Init 时返回空串，不创建任何东西）。
func EnsureHome() (string, error) {
	h := Home()
	if h == "" {
		return "", nil
	}
	if err := os.MkdirAll(h, 0o755); err != nil {
		return "", fmt.Errorf("创建数据根目录失败: %w", err)
	}
	return h, nil
}

// UserDataDir 返回当前用户的数据目录（仅计算路径，不创建）。
func UserDataDir() string { return userDataDir() }

// DirWritable 通过实际写入探测目录是否可写（Windows 上 ACL/UAC 只能这样判断）。
func DirWritable(dir string) bool { return probeDir(dir) }

// ConfigPath 返回可写的配置文件路径，解决"装到 Program Files、首次启动没有 config.yaml"
// 时连配置都创建不出来的问题：
//   - 文件已存在 → 原路径（绝不迁移既有配置）
//   - 所在目录可写 → 原路径
//   - 否则 → 用户数据目录下的同名文件（安装包自带 exe 时走这条）
func ConfigPath(p string) string {
	if strings.TrimSpace(p) == "" {
		p = "config.yaml"
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	if _, err := os.Stat(abs); err == nil {
		return abs
	}
	if probeDir(filepath.Dir(abs)) {
		return abs
	}
	if d := userDataDir(); d != "" {
		return filepath.Join(d, filepath.Base(abs))
	}
	return abs
}
