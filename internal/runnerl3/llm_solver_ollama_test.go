// llm_solver_ollama_test.go —— Layer 3 真机 e2e（听风 2026-10-25 统一收口）。
//
// 仅供服务器本地 Ollama 真机验证 runnerl3 与真实 eino ChatModel 的集成链路
// （eino → Ollama OpenAI 兼容 /v1 真模型调用、工具绑定循环、候选提取）。
// 门控 RUN_L3_OLLAMA_E2E=1：CI/本机默认跳过，避免依赖本地 Ollama。
//
// 这是「统一 L3 两套分叉」后防止回归的黄金探针——任一处集成断裂
// （eino ChatModel 构造失败 / base_url 错配 / 工具循环崩）都会让本测试 FAIL。
package runnerl3

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

// fakeSkillRunnerNoop 满足 SkillRunner 接口但不真正跑 skill，
// 仅用于真机 e2e 隔离模型回路（execute_python 工具不被真实触发）。
type fakeSkillRunnerNoop struct{}

func (fakeSkillRunnerNoop) RunSkill(_ context.Context, _ string, _ *ctfplatform.Challenge) ([]string, bool) {
	return nil, false
}

func TestL3E2E_Ollama(t *testing.T) {
	if os.Getenv("RUN_L3_OLLAMA_E2E") != "1" {
		t.Skip("RUN_L3_OLLAMA_E2E != 1，跳过真机 e2e")
	}

	// 指向服务器本地 Ollama（OpenAI 兼容 /v1）
	os.Setenv("RUNNER_LLM_FALLBACK", "true")
	// Ollama 不校验 key，但 NewChatModel 要求 APIKey 非空，否则跳过。
	os.Setenv("RUNNER_LLM_API_KEY", "ollama")
	if os.Getenv("RUNNER_LLM_BASE_URL") == "" {
		os.Setenv("RUNNER_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
	}
	if os.Getenv("RUNNER_LLM_MODEL") == "" {
		os.Setenv("RUNNER_LLM_MODEL", "qwen3.5:9b")
	}
	// 收敛预算：真机空转也别太久
	os.Setenv("RUNNER_LLM_MAX_ROUNDS", "3")
	os.Setenv("RUNNER_LLM_MAX_TOOL_CALLS", "5")
	os.Setenv("RUNNER_LLM_TIMEOUT_SEC", "60")

	// NewLLMFallback 读 env 构造真实 eino ChatModel —— 这是集成链路的第一道关。
	ff := NewLLMFallback(context.Background(), zap.NewNop(), fakeSkillRunnerNoop{})
	if ff == nil || !ff.Enabled || ff.model == nil {
		t.Fatalf("Ollama 真实 eino ChatModel 未成功构造（集成链路断）：ff=%v", ff)
	}

	ch := &ctfplatform.Challenge{
		Title:       "e2e 连通性验证题",
		Category:    "misc",
		Description: "你是测试模型。请直接输出最终答案：flag{l3_e2e_pong_2026}。",
	}

	// Solve 触发 eino → Ollama 真模型调用 + 候选提取。
	flags, err := ff.Solve(context.Background(), ch)
	if err != nil {
		t.Fatalf("Solve 报错（eino→Ollama 集成异常）: %v", err)
	}
	t.Logf("Ollama(%s) 返回候选: %v", os.Getenv("RUNNER_LLM_MODEL"), flags)
	if len(flags) == 0 {
		t.Fatalf("Ollama 未产出任何候选，集成链路可能未贯通（模型未应答或候选提取失败）")
	}
}
