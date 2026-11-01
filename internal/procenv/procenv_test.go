package procenv

import (
	"os"
	"strings"
	"testing"
)

// TestChildEnvDropsSecrets 锁死 2026-11-01 09:04 真机事故：
// 模型 `print(os.environ)` 把 RUNNER_LLM_API_KEY 明文当工具输出收走。
//
// 断言方式刻意用「构造真实环境 → 调 ChildEnv → 查结果」而不是查正则：
// 测的是行为，不是实现（否则改白名单写法就假红）。
func TestChildEnvDropsSecrets(t *testing.T) {
	secrets := map[string]string{
		"RUNNER_LLM_API_KEY":  "sk-test-should-never-reach-child",
		"CTF2_AGENT_TOKEN":    "tok-should-never-reach-child",
		"SSH_AUTH_SOCK":       "/tmp/ssh-XXXX/agent.1234",
		"JIYUAN_LVDONG_API_KEY": "sk_tr_should_never_reach_child",
		"GITHUB_TOKEN":        "ghp_should_never_reach_child",
		"AWS_SECRET_ACCESS_KEY": "aws-should-never-reach-child",
	}
	for k, v := range secrets {
		t.Setenv(k, v)
	}
	// 解释器真正需要的必须留着，否则等于把 Python 弄坏。
	keepers := map[string]string{
		"PATH":            "/usr/local/bin:/usr/bin:/bin",
		"HOME":            "/home/user",
		"LANG":            "zh_CN.UTF-8",
		"PYTHONIOENCODING": "utf-8",
	}
	for k, v := range keepers {
		t.Setenv(k, v)
	}

	got := ChildEnv()
	joined := strings.Join(got, "\n")

	for k, v := range secrets {
		if strings.Contains(joined, v) {
			t.Fatalf("%s 的明文下发给模型可写子进程了（事故原形）：%s", k, v)
		}
		if strings.HasPrefix(joined, k+"=") || strings.Contains(joined, "\n"+k+"=") {
			t.Fatalf("%s 这个键本身也不该出现", k)
		}
	}
	for k, v := range keepers {
		if !strings.Contains(joined, k+"="+v) {
			t.Fatalf("%s 必须保留（否则解释器/编码会坏），当前 env=%v", k, got)
		}
	}
}

// TestChildEnvIsSubsetOfParent 保证不凭空造变量，也不触发 panic。
func TestChildEnvIsSubsetOfParent(t *testing.T) {
	parent := map[string]bool{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			parent[kv[:i]] = true
		}
	}
	for _, kv := range ChildEnv() {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if !parent[k] {
			t.Fatalf("ChildEnv 造出了父进程没有的变量 %q", k)
		}
	}
}
