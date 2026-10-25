package ctfplatform

// upx_adapter.go —— UPX 脱壳外部工具适配器（吞并路线图 P2 能力项第一刀）。
//
// 与 bkcrack_adapter.go 同构：探测二进制 → `upx -d` 解压 → 返回解压后字节。
// 安全/诚实口径：
//   - 二进制缺失返回 ErrUpxUnavailable（环境缺口，与"脱壳失败"区分，不静默吞）；
//   - 非零退出 → 带 stderr 尾部的错误（CTF 改魔数/字段篡改的样本会在此失败——
//     helloupx11 实测：l_info 魔数清零 + 尾部 PackHeader version/method/level 篡改 +
//     adler/len 字段层破坏，需重实现 UPX 校验逻辑方可脱，登记为 P2 深水区）；
//   - 本适配器只搬运真实脱壳结果，不做任何"猜 flag"行为。
//
// 二进制查找顺序：环境变量 SECAUTOMIND_UPX > PATH 中的 upx。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrUpxUnavailable 表示外部 upx 二进制不可用（未安装 / 路径无效）。
var ErrUpxUnavailable = errors.New("upx 二进制不可用（设置 SECAUTOMIND_UPX 或安装 upx）")

// upxDefaultTimeout 单次 upx -d 的默认超时（解压本身秒级；留余量给大文件 IO）。
const upxDefaultTimeout = 2 * time.Minute

// upxRunner 可注入的命令执行器（测试确定性）。
var upxRunner = func(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// upxPath 返回可用的 upx 可执行文件路径。
func upxPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("SECAUTOMIND_UPX")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("%w: SECAUTOMIND_UPX=%q 不存在或不是文件", ErrUpxUnavailable, p)
	}
	if p, err := exec.LookPath("upx"); err == nil {
		return p, nil
	}
	return "", ErrUpxUnavailable
}

// upxUnpack 对 UPX 加壳字节执行 `upx -d`，返回解压后的完整文件字节。
// 输入不要求以 ELF 头开头（UPX 加壳后的形态即可）；解压失败/超时/工具缺失
// 一律返回 error（fail-closed），调用方据此区分"环境缺口"与"脱壳失败"。
func upxUnpack(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("upxUnpack: 空输入")
	}
	tool, err := upxPath()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, upxDefaultTimeout)
	defer cancel()
	src, err := os.CreateTemp("", "secautomind-upx-in-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(src.Name())
	if _, err := src.Write(data); err != nil {
		src.Close()
		return nil, err
	}
	src.Close()
	dst, err := os.CreateTemp("", "secautomind-upx-out-*")
	if err != nil {
		return nil, err
	}
	dstName := dst.Name()
	dst.Close()
	os.Remove(dstName)              // upx -d 拒绝覆盖已存在的输出：只占名不占文件
	defer func() { os.Remove(dstName) }()

	out, err := upxRunner(ctx, tool, "-d", "-o", dst.Name(), src.Name())
	if err != nil {
		tail := out
		if len(tail) > 200 {
			tail = tail[len(tail)-200:]
		}
		return nil, fmt.Errorf("upx -d 失败: %w（输出尾部: %s）", err, strings.TrimSpace(tail))
	}
	unpacked, err := os.ReadFile(dst.Name())
	if err != nil {
		return nil, err
	}
	if len(unpacked) == 0 {
		return nil, fmt.Errorf("upx -d 产出为空（样本可能经反脱壳篡改）")
	}
	return unpacked, nil
}

// looksUpxPacked 启发式判定：ELF 且无 section header（UPX ELF 典型形态），
// 或字节流中含 "UPX!" 魔数。
func looksUpxPacked(d []byte) bool {
	if len(d) < 64 {
		return false
	}
	if d[0] == 0x7f && d[1] == 'E' && d[2] == 'L' && d[3] == 'F' {
		// e_shoff == 0 且 e_shnum == 0 → 无 section header（UPX ELF 典型）
		shoff := int64(0)
		for i := 0; i < 8; i++ {
			shoff |= int64(d[40+i]) << (8 * uint(i))
		}
		shnum := int(d[58]) | int(d[59])<<8
		if shoff == 0 && shnum == 0 {
			return true
		}
	}
	return bytes.Contains(d, []byte("UPX!"))
}
