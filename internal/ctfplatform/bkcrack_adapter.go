package ctfplatform

// bkcrack_adapter.go —— ZIP 已知明文攻击（Biham–Kocher）外部工具适配器。
//
// 背景（吞并路线图 P0-1）：冻结仓的 `crypto_zip_bkcrack` skill 依赖预编译 bkcrack
// 二进制（PKZIP 兼容加密的已知明文攻击）。Go 侧需要一个**外调适配器**：
// 探测二进制 → 恢复内部密钥 (X,Y,Z) → 用密钥解密条目。本文件只做「封装 + 解析 +
// fail-closed」，不含 ZIP 解析逻辑（zip 条目由调用方给定）。
//
// 安全/诚实口径：
//   - 二进制缺失时返回 ErrBkcrackUnavailable（**不得**静默降级成"解不出"）；
//   - 命令非零退出 → 带 stderr 尾部的错误；输出里找不到 Keys 行 → 解析错误；
//   - 本适配器不做任何"猜 flag"行为，只搬运真实攻击结果。
//
// 二进制查找顺序：环境变量 SECAUTOMIND_BKCRACK > PATH 中的 bkcrack。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ErrBkcrackUnavailable 表示外部 bkcrack 二进制不可用（未安装 / 路径无效）。
// 调用方应把它与"攻击失败"区分开：前者是环境缺口，后者是密码学结果。
var ErrBkcrackUnavailable = errors.New("bkcrack 二进制不可用（设置 SECAUTOMIND_BKCRACK 或安装 bkcrack）")

// bkcrackDefaultTimeout 单次 bkcrack 调用的默认超时。
// 32 位密钥空间攻击在普通机器上通常数十秒内完成；超过 5 分钟视为失败（fail-closed）。
const bkcrackDefaultTimeout = 5 * time.Minute

// bkcrackKeysRe 匹配 bkcrack 的密钥输出行，例如：
//
//	Keys: 7d1e8f2a 3b4c5d6e 9f0a1b2c
var bkcrackKeysRe = regexp.MustCompile(`(?i)Keys:\s*([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})`)

// bkcrackRunner 执行一条命令并返回合并后的 stdout/stderr 与错误。
// 抽成变量是为了让测试注入确定性输出（无需真实二进制 / 不依赖平台）。
var bkcrackRunner = func(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// bkcrackPath 返回可用的 bkcrack 可执行文件路径。
func bkcrackPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("SECAUTOMIND_BKCRACK")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("%w: SECAUTOMIND_BKCRACK=%q 不存在或不是文件", ErrBkcrackUnavailable, p)
	}
	if p, err := exec.LookPath("bkcrack"); err == nil {
		return p, nil
	}
	return "", ErrBkcrackUnavailable
}

// BkcrackAvailable 报告外部 bkcrack 当前是否可用（供能力探测 / 健康检查用）。
func BkcrackAvailable() bool {
	_, err := bkcrackPath()
	return err == nil
}

// BkcrackRecoverKeys 对 ZIP 的指定条目执行已知明文攻击，返回内部密钥 "k1 k2 k3"（8 位十六进制 ×3）。
//
// 参数：
//   - zipPath：加密 ZIP 路径；
//   - entry：ZIP 内的条目名（bkcrack -c 参数）；
//   - plaintext：已知明文（bkcrack -p 参数，写入临时文件）；
//   - offset：已知明文在明文流中的偏移（bkcrack -o 参数，0 表示从头）。
func BkcrackRecoverKeys(ctx context.Context, zipPath, entry string, plaintext []byte, offset int) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("bkcrack: 已知明文为空（拒绝执行无意义攻击）")
	}
	if offset < 0 {
		return "", fmt.Errorf("bkcrack: 偏移必须 ≥ 0，得到 %d", offset)
	}
	bin, err := bkcrackPath()
	if err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, bkcrackDefaultTimeout)
	defer cancel()

	ptFile, err := os.CreateTemp("", "bkcrack-plain-*.bin")
	if err != nil {
		return "", fmt.Errorf("bkcrack: 创建临时明文文件失败: %w", err)
	}
	defer os.Remove(ptFile.Name())
	if _, err := ptFile.Write(plaintext); err != nil {
		ptFile.Close()
		return "", fmt.Errorf("bkcrack: 写临时明文失败: %w", err)
	}
	ptFile.Close()

	args := []string{
		"-C", zipPath,
		"-c", entry,
		"-p", ptFile.Name(),
	}
	if offset > 0 {
		args = append(args, "-o", fmt.Sprintf("%d", offset))
	}
	out, runErr := bkcrackRunner(ctx, bin, args...)
	if runErr != nil {
		// 超时与"命令失败"分开报，便于定位是环境慢还是参数错。
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("bkcrack: 攻击超时（%s）", bkcrackDefaultTimeout)
		}
		return "", fmt.Errorf("bkcrack: 攻击失败: %v（输出尾部: %s）", runErr, tailOf(out, 400))
	}
	m := bkcrackKeysRe.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("bkcrack: 输出中未找到 Keys 行（输出尾部: %s）", tailOf(out, 400))
	}
	return fmt.Sprintf("%s %s %s", strings.ToLower(m[1]), strings.ToLower(m[2]), strings.ToLower(m[3])), nil
}

// BkcrackDecryptEntry 用已恢复的内部密钥把 ZIP 中的指定条目解密到 outPath。
// keys 必须形如 "k1 k2 k3"（BkcrackRecoverKeys 的返回值）。
func BkcrackDecryptEntry(ctx context.Context, zipPath, entry, keys, outPath string) error {
	if !regexp.MustCompile(`(?i)^[0-9a-f]{8}\s+[0-9a-f]{8}\s+[0-9a-f]{8}$`).MatchString(strings.TrimSpace(keys)) {
		return fmt.Errorf("bkcrack: 密钥格式非法（期望 8 位十六进制 ×3，得到 %q）", keys)
	}
	if strings.TrimSpace(outPath) == "" {
		return errors.New("bkcrack: 输出路径为空")
	}
	bin, err := bkcrackPath()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, bkcrackDefaultTimeout)
	defer cancel()

	k := strings.Fields(strings.TrimSpace(keys))
	args := []string{
		"-C", zipPath,
		"-k", k[0], k[1], k[2],
		"-c", entry,
		"-D", outPath,
	}
	out, runErr := bkcrackRunner(ctx, bin, args...)
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("bkcrack: 解密超时（%s）", bkcrackDefaultTimeout)
		}
		return fmt.Errorf("bkcrack: 解密失败: %v（输出尾部: %s）", runErr, tailOf(out, 400))
	}
	return nil
}

// tailOf 取输出尾部 n 字节（bkcrack 的报错常在最后几行）。
func tailOf(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
