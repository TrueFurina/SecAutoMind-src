package runnerl3

import (
	"strings"
	"testing"
)

// CheckGatewayCompliance 回归（2026-10-28 终审网关硬约束 fail-closed 校验）。
// 评估与证据：docs/evidence/网关合规接线缺口_LLM链_20261028.md。
//
// 用例设计（因果链：开关→放行/拦截，覆盖全部四条规则）：
//  T1 默认关 → 一律放行（日常直连零影响）
//  T2 开 + L3 未启用 → 放行（本进程无模型调用）
//  T3 开 + L3 启用 + 网关地址未设 → 拦（无从校验 = fail-closed）
//  T4 开 + 主通道默认 deepseek 直连 → 拦（点名主通道）
//  T5 开 + 主通道指网关 + failover 默认开 → 拦（匿名通道 kilo 无 key 也在拨打集合里）
//  T6 开 + 主通道指网关 + failover 关 → 放行（终审合规形态）
//  T7 开 + 网关地址非绝对 URL → 拦（解析失败）

const gwTestURL = "https://gw.example.com/v1"

func TestGatewayComplianceOffByDefault(t *testing.T) {
	t.Setenv("CTF_GATEWAY_REQUIRED", "")
	t.Setenv("RUNNER_LLM_FALLBACK", "true")
	t.Setenv("RUNNER_LLM_BASE_URL", "https://api.deepseek.com/v1") // 直连也放行
	t.Setenv("AI_GATEWAY_BASE_URL", "")
	if err := CheckGatewayCompliance(); err != nil {
		t.Fatalf("默认关时必须放行，实际拦截：%v", err)
	}
}

func TestGatewayCompliancePassWhenL3Disabled(t *testing.T) {
	t.Setenv("CTF_GATEWAY_REQUIRED", "true")
	t.Setenv("RUNNER_LLM_FALLBACK", "false")
	t.Setenv("AI_GATEWAY_BASE_URL", "")
	if err := CheckGatewayCompliance(); err != nil {
		t.Fatalf("L3 未启用（本进程无模型调用）应放行，实际拦截：%v", err)
	}
}

func TestGatewayComplianceBlocksMissingGatewayURL(t *testing.T) {
	t.Setenv("CTF_GATEWAY_REQUIRED", "true")
	t.Setenv("RUNNER_LLM_FALLBACK", "true")
	t.Setenv("AI_GATEWAY_BASE_URL", "")
	t.Setenv("RUNNER_LLM_BASE_URL", gwTestURL)
	err := CheckGatewayCompliance()
	if err == nil || !strings.Contains(err.Error(), "无从校验") {
		t.Fatalf("网关地址缺失必须 fail-closed 拦截，实际：%v", err)
	}
}

func TestGatewayComplianceBlocksDirectPrimary(t *testing.T) {
	t.Setenv("CTF_GATEWAY_REQUIRED", "true")
	t.Setenv("RUNNER_LLM_FALLBACK", "true")
	t.Setenv("AI_GATEWAY_BASE_URL", gwTestURL)
	t.Setenv("RUNNER_LLM_BASE_URL", "") // 默认值 = deepseek 直连
	t.Setenv("RUNNER_LLM_FAILOVER", "false")
	err := CheckGatewayCompliance()
	if err == nil || !strings.Contains(err.Error(), "api.deepseek.com") {
		t.Fatalf("主通道直连必须拦截并点名，实际：%v", err)
	}
}

func TestGatewayComplianceBlocksFailoverDirectChannels(t *testing.T) {
	t.Setenv("CTF_GATEWAY_REQUIRED", "true")
	t.Setenv("RUNNER_LLM_FALLBACK", "true")
	t.Setenv("AI_GATEWAY_BASE_URL", gwTestURL)
	t.Setenv("RUNNER_LLM_BASE_URL", gwTestURL) // 主通道已合规
	t.Setenv("RUNNER_LLM_FAILOVER", "")        // 默认开
	t.Setenv("RUNNER_LLM_FAILOVER_CHANNELS", "")
	err := CheckGatewayCompliance()
	if err == nil {
		t.Fatal("failover 默认开且含公网直连通道时必须拦截")
	}
	// kilo 是匿名通道（无 key 也在拨打集合里），是确定性违规锚点
	if !strings.Contains(err.Error(), "kilo") {
		t.Fatalf("违规清单应点名匿名直连通道 kilo，实际：%v", err)
	}
}

func TestGatewayCompliancePassWhenFailoverOff(t *testing.T) {
	t.Setenv("CTF_GATEWAY_REQUIRED", "true")
	t.Setenv("RUNNER_LLM_FALLBACK", "true")
	t.Setenv("AI_GATEWAY_BASE_URL", gwTestURL)
	t.Setenv("RUNNER_LLM_BASE_URL", gwTestURL)
	t.Setenv("RUNNER_LLM_FAILOVER", "false")
	if err := CheckGatewayCompliance(); err != nil {
		t.Fatalf("主通道指网关 + failover 关 = 终审合规形态，应放行，实际拦截：%v", err)
	}
}

func TestGatewayComplianceBlocksUnparseableGatewayURL(t *testing.T) {
	t.Setenv("CTF_GATEWAY_REQUIRED", "true")
	t.Setenv("RUNNER_LLM_FALLBACK", "true")
	t.Setenv("AI_GATEWAY_BASE_URL", "gw.example.com/v1") // 相对 URL：无 scheme
	t.Setenv("RUNNER_LLM_BASE_URL", gwTestURL)
	err := CheckGatewayCompliance()
	if err == nil || !strings.Contains(err.Error(), "无法解析") {
		t.Fatalf("网关地址不可解析必须拦截，实际：%v", err)
	}
}

// TestGatewayComplianceCurrentEnv 供 scripts/finals_preflight.py 以
// `go test -run TestGatewayComplianceCurrentEnv ./internal/runnerl3/` 调用：
// 按**当前真实环境**（不做任何 setenv，继承进程 env）执行网关合规校验。
// 校验逻辑单一真值源 = CheckGatewayCompliance（Go 侧），preflight 不复刻第二份口径。
// CTF_GATEWAY_REQUIRED 未启用 → Skip（测试进程 rc 仍为 0，preflight 视为绿）。
func TestGatewayComplianceCurrentEnv(t *testing.T) {
	if !envBool("CTF_GATEWAY_REQUIRED", false) {
		t.Skip("CTF_GATEWAY_REQUIRED 未启用，跳过当前环境网关合规校验")
	}
	if err := CheckGatewayCompliance(); err != nil {
		t.Fatalf("当前环境网关合规校验失败（终审硬约束，模型调用链存在直连旁路）：%v", err)
	}
}
