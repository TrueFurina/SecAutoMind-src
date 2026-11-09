package runnerl3

import (
	"fmt"
	"os"
	"strings"

	"secautomind-ai/internal/gatewaycompliance"
	"secautomind-ai/internal/llmchannel"
)

// CheckGatewayCompliance 终审网关硬约束的 fail-closed 校验。
//
// 背景与证据（2026-10-28）：XH-202609 第一环节硬约束「终审所有 Agent 的模型调用必须经
// 主办方指定 AI 安全网关接入」，但 `ai.gateway` 配置段在 Go 运行时**零消费**（宣称的
// 「运行时统一改写」不存在），且 runner L3 的 failover 默认开启、免费通道为硬编码
// 公网直连——主通道一抖动即自动切直连，机器主动违规。详见
// docs/evidence/网关合规接线缺口_LLM链_20261028.md。
//
// 规则（CTF_GATEWAY_REQUIRED 未设/非 true → 一律放行，日常直连零影响）：
//  1. RUNNER_LLM_FALLBACK 未启用：本进程无模型调用 → 合规；
//  2. AI_GATEWAY_BASE_URL 未设：无从校验 → 违规（fail-closed，宁可不跑不可违规）；
//  3. 主通道（RUNNER_LLM_BASE_URL，默认 deepseek 直连）的 scheme://host 必须与网关一致；
//  4. failover 开启（默认开）时，用与 buildFailoverModel **同一口径**（llmchannel.Resolve）
//     枚举会被真实拨打的通道集合（含匿名通道——无 key 也会拨打），任何非网关 host
//     都算违规。内置免费通道全是公网直连，实际等价于「终审须 RUNNER_LLM_FAILOVER=false
//     （或 RUNNER_LLM_FAILOVER_CHANNELS 限定为网关 host 通道）」。
//
// 网关地址复用 verify_gateway.sh 既有 env（AI_GATEWAY_BASE_URL），不另造第二套口径。
func CheckGatewayCompliance() error {
	if !envBool("CTF_GATEWAY_REQUIRED", false) {
		return nil
	}
	if !envBool("RUNNER_LLM_FALLBACK", false) {
		return nil // L3 未启用：本进程不会发起任何模型调用
	}
	gw := strings.TrimSpace(os.Getenv("AI_GATEWAY_BASE_URL"))
	if gw == "" {
		return fmt.Errorf("网关合规：CTF_GATEWAY_REQUIRED=true 但 AI_GATEWAY_BASE_URL 未设，无从校验（fail-closed）")
	}
	gwOrigin, err := gatewaycompliance.OriginOf(gw)
	if err != nil {
		return fmt.Errorf("网关合规：AI_GATEWAY_BASE_URL 无法解析：%w", err)
	}

	primary := llmchannel.Channel{
		ID:      "primary",
		BaseURL: envOrDefault("RUNNER_LLM_BASE_URL", "https://api.deepseek.com/v1"),
	}
	// 判据与 server 侧同源（internal/gatewaycompliance）：非网关 origin 且非回环豁免 = 违规。
	if v := gatewaycompliance.Violation(gwOrigin, "主通道 "+primary.BaseURL, primary.BaseURL); v != "" {
		return fmt.Errorf("网关合规：%s 直连未走网关 %s —— 把 RUNNER_LLM_BASE_URL 指向网关，或仅在非终审环境关掉 CTF_GATEWAY_REQUIRED",
			v, gwOrigin)
	}

	// failover 通道集合：Resolve 的结果 = Solve 时会被真实拨打的通道（含匿名通道）
	if envBool("RUNNER_LLM_FAILOVER", true) {
		channels := llmchannel.Resolve(&primary, llmchannel.Options{
			Only: llmchannel.ParseChannelIDs(os.Getenv("RUNNER_LLM_FAILOVER_CHANNELS")),
		})
		var bad []string
		for _, c := range channels {
			if v := gatewaycompliance.Violation(gwOrigin, c.ID, c.BaseURL); v != "" {
				bad = append(bad, v)
			}
		}
		if len(bad) > 0 {
			return fmt.Errorf("网关合规：failover 含非网关直连通道 %d 个：%s —— 终审请 RUNNER_LLM_FAILOVER=false（内置免费通道均为公网直连；本地回环网关按 2026-11-09 拍板口径豁免）",
				len(bad), strings.Join(bad, "、"))
		}
	}
	return nil
}
