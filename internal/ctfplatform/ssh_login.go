package ctfplatform

// ssh_login.go —— SSH 登录与远程命令执行，作为"拿到 shell / 提权成功"的非 flag 证据。
//
// 靶场链条：.htpasswd 破解 → SSH 登录 → 提权枚举 → root。
// 与 flag 判分无关；不产生 WebFinding。
//
// 安全说明：靶机是自签主机密钥的旧系统，所有函数默认**拒绝** insecure 模式，
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

// buildSSHConfig 构造客户端配置。2009 年的 OpenSSH 只支持老算法，需显式放开。
func buildSSHConfig(user string, auth []ssh.AuthMethod, allowInsecure bool,
	timeout time.Duration) (*ssh.ClientConfig, error) {

	if !allowInsecure {
		return nil, fmt.Errorf("拒绝执行：靶机为自签主机密钥，必须显式允许 insecure 模式")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 实验靶场，显式声明
		Timeout:         timeout,
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256", "ecdh-sha2-nistp256",
				"diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
				"diffie-hellman-group1-sha1",
			},
			Ciphers: []string{"aes128-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc"},
		},
		HostKeyAlgorithms: []string{"ssh-rsa", "rsa-sha2-256", "ssh-ed25519"},
	}, nil
}

// dialSSH 建立连接并完成握手认证。
func dialSSH(ctx context.Context, addr string, cfg *ssh.ClientConfig,
	timeout time.Duration) (*ssh.Client, error) {

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
	return ssh.NewClient(c, chans, reqs), nil
}

// runOnClient 在已认证的客户端上执行命令并返回合并输出。
func runOnClient(client *ssh.Client, command string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建会话失败: %w", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(command)
	if err != nil {
		// 命令非 0 退出很常见（如 sudo -l 需要口令），输出仍要返回
		return string(out), fmt.Errorf("命令退出异常: %w", err)
	}
	return string(out), nil
}

// TrySSHLogin 尝试口令登录并执行 `id; hostname`。
func TrySSHLogin(ctx context.Context, addr, user, password string,
	allowInsecureHostKey bool, timeout time.Duration) (*SSHAccess, error) {

	cfg, err := buildSSHConfig(user, []ssh.AuthMethod{ssh.Password(password)}, allowInsecureHostKey, timeout)
	if err != nil {
		return nil, err
	}
	client, err := dialSSH(ctx, addr, cfg, timeout)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	out, err := runOnClient(client, "id; hostname")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	res := &SSHAccess{User: user, Addr: addr}
	if len(lines) > 0 {
		res.WhoAmI = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		res.Hostname = strings.TrimSpace(lines[1])
	}
	return res, nil
}

// RunSSHCommand 用给定口令登录并执行一条命令，返回合并输出。
// 用途：拿到初始 shell 后的**提权枚举**（sudo -l / SUID / cron / 内核版本…）。
func RunSSHCommand(ctx context.Context, addr, user, password, command string,
	allowInsecureHostKey bool, timeout time.Duration) (string, error) {

	if command == "" {
		return "", fmt.Errorf("命令为空")
	}
	cfg, err := buildSSHConfig(user, []ssh.AuthMethod{ssh.Password(password)}, allowInsecureHostKey, timeout)
	if err != nil {
		return "", err
	}
	client, err := dialSSH(ctx, addr, cfg, timeout)
	if err != nil {
		return "", err
	}
	defer client.Close()
	return runOnClient(client, command)
}

// TrySSHLoginWithKey 用**私钥**登录（对应"偷到 achen 私钥"这一跳）。
// pemKey 需为 PKCS#1/PKCS#8 PEM（PPK 先经 PPKToPEM 转换）。
func TrySSHLoginWithKey(ctx context.Context, addr, user string, pemKey []byte,
	allowInsecureHostKey bool, timeout time.Duration) (*SSHAccess, error) {

	signer, err := ssh.ParsePrivateKey(pemKey)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	cfg, err := buildSSHConfig(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, allowInsecureHostKey, timeout)
	if err != nil {
		return nil, err
	}
	client, err := dialSSH(ctx, addr, cfg, timeout)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	out, err := runOnClient(client, "id; hostname")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	res := &SSHAccess{User: user, Addr: addr}
	if len(lines) > 0 {
		res.WhoAmI = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		res.Hostname = strings.TrimSpace(lines[1])
	}
	return res, nil
}

// RunSSHCommandWithKey 用私钥登录后执行命令（提权链用）。
func RunSSHCommandWithKey(ctx context.Context, addr, user string, pemKey []byte,
	command string, allowInsecureHostKey bool, timeout time.Duration) (string, error) {

	if command == "" {
		return "", fmt.Errorf("命令为空")
	}
	signer, err := ssh.ParsePrivateKey(pemKey)
	if err != nil {
		return "", fmt.Errorf("解析私钥失败: %w", err)
	}
	cfg, err := buildSSHConfig(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, allowInsecureHostKey, timeout)
	if err != nil {
		return "", err
	}
	client, err := dialSSH(ctx, addr, cfg, timeout)
	if err != nil {
		return "", err
	}
	defer client.Close()
	return runOnClient(client, command)
}
