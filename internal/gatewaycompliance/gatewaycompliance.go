// Package gatewaycompliance 是「AI 安全网关合规」判据的单一真值源。
//
// 存在理由（2026-11-09 用户拍板）：server 侧（对话通道）与 runner 侧（解题 L3）
// 要执行**同一套**网关合规判定，口径必须只有一份——本包只依赖 stdlib，
// 位于低层，config 与 runnerl3 均可安全引入。
//
// 判据：
//  1. OriginOf：URL 归一到 scheme://host（含端口），用于"是否指向同一接入点"；
//  2. IsLoopbackOrigin：本地网关（127.0.0.1/localhost/::1）豁免——用户口径：
//     ofm/ollama 这类本机转发器**算**"经网关接入"（终审主办方现场确认过的形态）；
//     公网直连一律不豁免。
//  3. ChannelViolation：给定网关 origin，判定一个通道 base_url 是否违规。
package gatewaycompliance

import (
	"fmt"
	"net/url"
	"strings"
)

// OriginOf 提取 URL 的 scheme://host（host 含端口）。非绝对 URL 返回错误。
func OriginOf(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("非绝对 URL: %q", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// IsLoopbackOrigin 判定 origin（OriginOf 的产物）是否指向本机回环地址。
// 用户 2026-11-09 拍板：本地网关转发器（ofm/ollama 等）算"经网关接入"，予以豁免；
// 该豁免只认回环地址，不认任何公网 host。
func IsLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "127.0.0.1" || h == "localhost" || h == "::1" ||
		strings.HasPrefix(h, "127.")
}

// Violation 返回非空描述 = 该 base_url 未满足网关合规（回环豁免与同源放行）。
// gwOrigin 必须是 OriginOf(网关地址) 的产物；channelID 仅用于报错定位。
func Violation(gwOrigin, channelID, baseURL string) string {
	o, err := OriginOf(baseURL)
	if err != nil {
		return fmt.Sprintf("%s(%s：URL 不可解析)", channelID, truncate(baseURL, 60))
	}
	if o == gwOrigin || IsLoopbackOrigin(o) {
		return ""
	}
	return fmt.Sprintf("%s(%s)", channelID, o)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
