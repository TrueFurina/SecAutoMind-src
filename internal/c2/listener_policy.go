package c2

import (
	"net"
	"strings"
)

// ----------------------------------------------------------------------------
// 监听器安全策略（服务端强制）
// ----------------------------------------------------------------------------
//
// 背景（2026-10-03 线上实例自审计实锤）：
// tcp_reverse 监听器的 allow_legacy_shell=true 会开放"未加密经典反弹 Shell"
// （bash / nc / python -c 直连即执行任意命令，无 Beacon 鉴权）。若同时把
// bind_host 设为 0.0.0.0 / :: / 公网 IP，等价于在公网网卡上开一个未授权 RCE 入口。
// 该组合曾被 Agent 自行创建并绑定到 0.0.0.0:5555，仅因云安全组未放行该端口而未
// 被实际利用——那是运气，不是设计。故在服务端（而非仅前端/文档）强制约束：
//
//	allow_legacy_shell=true 仅允许 bind_host 为回环地址（127.0.0.0/8、::1、localhost、空）。
//
// 覆盖路径：Manager.CreateListener / Manager.StartListener（含进程重启时的
// RestoreRunningListeners）/ MCP 工具 c2_listener update / HTTP handler update。
// 如此即便数据库中已存在违规历史记录，重启也不会再拉起该风险面。

// ErrLegacyShellPublicBind legacy shell 绑定在非回环地址时被拒绝。
var ErrLegacyShellPublicBind = &CommonError{
	Code: "legacy_shell_public_bind",
	Message: "安全策略拒绝：tcp_reverse 的 allow_legacy_shell（未加密经典反弹 Shell，无 Beacon 鉴权）" +
		"仅允许绑定回环地址（127.0.0.1 / ::1 / localhost / 留空）。" +
		"请改用 CSB1 加密 Beacon（build 生成 implant），或将 bind_host 改为 127.0.0.1。",
	HTTP: 400,
}

// IsLoopbackBindHost 判定绑定地址是否为回环地址。
// 空串按 CreateListener 的默认行为（127.0.0.1）视为回环。
func IsLoopbackBindHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return true // 默认回环
	}
	// 去掉 IPv6 方括号（如 [::1]）
	h = strings.Trim(h, "[]")
	switch h {
	case "localhost", "::1", "0:0:0:0:0:0:0:1", "127.0.0.1":
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		// 非 IP（域名/主机名）：无法证明是回环，按最严处理——不视为回环
		return false
	}
	return ip.IsLoopback()
}

// ValidateListenerPolicy 校验监听器配置是否符合安全策略。
// 目前仅约束 tcp_reverse + allow_legacy_shell 的绑定地址；其余组合放行。
// cfg 为 nil 时视为未开启 legacy shell（放行）。
func ValidateListenerPolicy(ltype, bindHost string, cfg *ListenerConfig) error {
	if cfg == nil || !cfg.AllowLegacyShell {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(ltype), string(ListenerTypeTCPReverse)) {
		return nil // legacy shell 开关只对 tcp_reverse 有意义
	}
	if IsLoopbackBindHost(bindHost) {
		return nil
	}
	return ErrLegacyShellPublicBind
}
