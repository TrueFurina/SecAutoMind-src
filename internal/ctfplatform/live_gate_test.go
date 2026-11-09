package ctfplatform

// live 测试显式开启闸门（2026-11-10 健康度体检发现）。
//
// 事故形态（本机真实发生，非假想）：开发/编排 shell 里常带 CTF2/DASCTF 真凭证，
// 于是随手一条 `go test ./...` 就会——
//   ① 真打比赛平台（dasctf/CTF² 有频控与 WAF，白耗配额）；
//   ② TestCTF2LiveTargetChain **真建靶机环境**（账号级 5 格，占着不放别人起不来）；
//   ③ 把整包拖到 120s 超时，全量套件变红，真问题被淹在假红里。
// 决赛前这是隐患不是便利：体检/回归必须默认离线可跑。
//
// 规则：live 测试除凭证外，还必须显式 `RUN_LIVE_TESTS=1` 才运行；否则 Skip，
// 且 Skip 消息说明开启方式（真机冒烟按 runbook 带该变量跑）。
// CI 无凭证 → 本闸门不改变其行为（依旧 Skip）；本机默认 → 套件干净快。

import (
	"os"
	"strings"
	"testing"
)

// liveOptInEnabled 判据单一来源（可测）：仅 RUN_LIVE_TESTS=1 才为真。
func liveOptInEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("RUN_LIVE_TESTS")), "1")
}

// requireLiveOptIn 未显式开启即 Skip。放在每个 live 测试的**最前面**（先于凭证判断），
// 这样"带着凭证跑 ./..."也绝不会真打平台。
func requireLiveOptIn(t *testing.T, what string) {
	t.Helper()
	if !liveOptInEnabled() {
		t.Skipf("跳过 %s：live 测试需显式 RUN_LIVE_TESTS=1（本机 shell 常带真凭证，" +
			"默认不真打平台/不占靶机额度；真机冒烟请按 runbook 带该变量运行）", what)
	}
}

// 闸门判据回归：默认关必须为 false——写反的代价是"以为默认不跑、实际每次 ./...
// 都在打平台并占靶机额度"，属最难发现的一类静默行为。
func TestRequireLiveOptInSkipsByDefault(t *testing.T) {
	t.Setenv("RUN_LIVE_TESTS", "")
	if liveOptInEnabled() {
		t.Fatal("RUN_LIVE_TESTS 置空时判据必须为 false（默认不跑 live）")
	}
	t.Setenv("RUN_LIVE_TESTS", "0")
	if liveOptInEnabled() {
		t.Fatal("RUN_LIVE_TESTS=0 时判据必须为 false")
	}
	t.Setenv("RUN_LIVE_TESTS", "1")
	if !liveOptInEnabled() {
		t.Fatal("RUN_LIVE_TESTS=1 时判据必须为 true（显式可开启）")
	}
}
