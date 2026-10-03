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
// 被实际利用——那是运气，不是设计。
//
// 补洞（2026-10-04 第二次实锤）：首版策略只约束了
// tcp_reverse + allow_legacy_shell，属"只补被报告的那一格"。线上随后被查出
// 两个**明文传输的 http_beacon**（0.0.0.0:8080、0.0.0.0:18087）仍在全网卡监听——
// 同一类风险的另一个格子。故升级为按「传输是否加密」穷举的完整矩阵：
//
//	非回环绑定（0.0.0.0 / :: / 公网或内网 IP / 域名）仅允许加密载荷：
//	  · https_beacon                → TLS，放行
//	  · tcp_reverse（非 legacy）     → CSB1 魔数 + AES-GCM Beacon，放行
//	  · tcp_reverse + allow_legacy_shell → 明文反弹 Shell，拒绝
//	  · http_beacon                 → 明文 HTTP，拒绝
//	  · websocket                   → 实现层无 TLS（ws://），拒绝
//	  · 未知类型                     → fail-closed（按明文处理），拒绝
//	回环绑定（127.0.0.0/8、::1、localhost、留空）一律放行。
//
// 注意：TLS 只保证传输加密，不等于鉴权；公网暴露 Beacon 仍应叠加网络层收敛。
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

// ErrPlaintextPublicBind 明文传输的监听器绑定在非回环地址时被拒绝。
var ErrPlaintextPublicBind = &CommonError{
	Code: "plaintext_public_bind",
	Message: "安全策略拒绝：该监听器使用未加密传输，仅允许绑定回环地址（127.0.0.1 / ::1 / localhost / 留空）。" +
		"http_beacon 与 websocket 均为明文通道；如需对外提供服务，请改用 https_beacon（TLS）" +
		"或关闭 allow_legacy_shell 使用 CSB1 加密 Beacon，并把 bind_host 指向回环、经反向代理/加密隧道转发。",
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

// IsEncryptedListener 判定监听器在此配置下是否为加密传输。
// 未知类型按明文处理（fail-closed），避免新增类型时静默拿到放行资格。
func IsEncryptedListener(ltype string, cfg *ListenerConfig) bool {
	switch ListenerType(strings.ToLower(strings.TrimSpace(ltype))) {
	case ListenerTypeHTTPSBeacon:
		// 构造器强制 useTLS=true，buildTLSConfig 失败即启动失败，不会静默回落明文
		return true
	case ListenerTypeTCPReverse:
		// CSB1 魔数 + AES-GCM（EncryptionKey）；仅 legacy shell 为明文
		return cfg == nil || !cfg.AllowLegacyShell
	default:
		// http_beacon（明文 HTTP）/ websocket（实现层无 TLS）/ 未知类型
		return false
	}
}

// ValidateListenerPolicy 校验监听器配置是否符合安全策略。
// 规则：非回环绑定仅允许加密载荷；拒绝时返回可区分的哨兵错误。
func ValidateListenerPolicy(ltype, bindHost string, cfg *ListenerConfig) error {
	if IsLoopbackBindHost(bindHost) {
		return nil
	}
	// 非回环绑定：仅加密载荷放行
	if IsEncryptedListener(ltype, cfg) {
		return nil
	}
	// tcp_reverse + legacy shell 保留专用错误码（语义更精确，历史用例兼容）
	if ListenerType(strings.ToLower(strings.TrimSpace(ltype))) == ListenerTypeTCPReverse &&
		cfg != nil && cfg.AllowLegacyShell {
		return ErrLegacyShellPublicBind
	}
	return ErrPlaintextPublicBind
}
